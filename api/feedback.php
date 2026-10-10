<?php
/**
 * Pulsschlag Deggendorf - Gottesdienst Feedback API v2
 * Pure PHP + SQLite Endpoint
 * Handles submission, moderation, retrieval, statistics, and soft-delete / anonymisation after 30 days.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ── Database setup ────────────────────────────────────────────────────────────
$dbDir = __DIR__ . '/data';
if (!file_exists($dbDir)) {
    @mkdir($dbDir, 0755, true);
    @file_put_contents($dbDir . '/.htaccess', "Order deny,allow\nDeny from all\n");
}

$dbPath = $dbDir . '/feedback.sqlite';

try {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Main feedback table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS feedback (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            service_date    TEXT NOT NULL,
            event_type      TEXT NOT NULL DEFAULT 'Gottesdienst',
            category        TEXT NOT NULL DEFAULT 'Sonstiges',
            rating          INTEGER DEFAULT 0,
            positive_text   TEXT,
            improvement_text TEXT,
            tags            TEXT,
            author_name     TEXT,
            author_contact  TEXT,
            status          TEXT NOT NULL DEFAULT 'pending',
            reviewed        INTEGER NOT NULL DEFAULT 0,
            action_taken    INTEGER NOT NULL DEFAULT 0,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ");

    // Dynamic column check & migration for existing SQLite databases
    $existingCols = [];
    $colStmt = $pdo->query("PRAGMA table_info(feedback)");
    while ($col = $colStmt->fetch()) {
        $existingCols[] = strtolower($col['name']);
    }

    $colDefinitions = [
        'event_type'       => "ALTER TABLE feedback ADD COLUMN event_type TEXT NOT NULL DEFAULT 'Gottesdienst'",
        'category'         => "ALTER TABLE feedback ADD COLUMN category TEXT NOT NULL DEFAULT 'Sonstiges'",
        'rating'           => "ALTER TABLE feedback ADD COLUMN rating INTEGER DEFAULT 0",
        'positive_text'    => "ALTER TABLE feedback ADD COLUMN positive_text TEXT",
        'improvement_text' => "ALTER TABLE feedback ADD COLUMN improvement_text TEXT",
        'tags'             => "ALTER TABLE feedback ADD COLUMN tags TEXT",
        'author_name'      => "ALTER TABLE feedback ADD COLUMN author_name TEXT",
        'author_contact'   => "ALTER TABLE feedback ADD COLUMN author_contact TEXT",
        'status'           => "ALTER TABLE feedback ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'",
        'reviewed'         => "ALTER TABLE feedback ADD COLUMN reviewed INTEGER NOT NULL DEFAULT 0",
        'action_taken'     => "ALTER TABLE feedback ADD COLUMN action_taken INTEGER NOT NULL DEFAULT 0",
        'created_at'       => "ALTER TABLE feedback ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
    ];

    foreach ($colDefinitions as $colName => $alterSql) {
        if (!in_array(strtolower($colName), $existingCols)) {
            try { $pdo->exec($alterSql); } catch (Exception $ignored) {}
        }
    }

    // Safe index creation
    try {
        $pdo->exec("
            CREATE INDEX IF NOT EXISTS idx_created_at   ON feedback(created_at);
            CREATE INDEX IF NOT EXISTS idx_service_date  ON feedback(service_date);
            CREATE INDEX IF NOT EXISTS idx_status        ON feedback(status);
        ");
    } catch (Exception $ignored) {}

    // Long-term aggregate stats table (survives 30-day raw purge)
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS feedback_stats (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            week_start TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'Gottesdienst',
            category   TEXT NOT NULL DEFAULT 'Sonstiges',
            count      INTEGER NOT NULL DEFAULT 0,
            sum_rating REAL NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_stats_week ON feedback_stats(week_start);
    ");

    // Event types table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS event_types (
            id          TEXT PRIMARY KEY,
            name_de     TEXT NOT NULL,
            name_en     TEXT NOT NULL,
            sort_order  INTEGER NOT NULL DEFAULT 0,
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_event_types_sort   ON event_types(sort_order);
        CREATE INDEX IF NOT EXISTS idx_event_types_active ON event_types(is_active);
    ");

    // Seed default event types and ensure clean encoding
    $defaultEventTypes = [
        ['id' => 'gottesdienst',        'name_de' => 'Gottesdienst',                               'name_en' => 'Sunday Service',                  'sort_order' => 1, 'is_active' => 1],
        ['id' => 'lobpreisabend',       'name_de' => 'Lobpreisabend',                              'name_en' => 'Worship Evening',                 'sort_order' => 2, 'is_active' => 1],
        ['id' => 'explore',             'name_de' => 'Explore',                                    'name_en' => 'Explore',                         'sort_order' => 3, 'is_active' => 1],
        ['id' => 'kleingruppen',        'name_de' => 'Kleingruppen- oder Hauskreisveranstaltung',  'name_en' => 'Small Group Event',              'sort_order' => 4, 'is_active' => 1],
        ['id' => 'love_after_marriage', 'name_de' => 'Love after Marriage – Kurs',                 'name_en' => 'Love After Marriage Course',      'sort_order' => 5, 'is_active' => 1],
        ['id' => 'gemeindefest',        'name_de' => 'Gemeindefest',                               'name_en' => 'Church Community Event',         'sort_order' => 6, 'is_active' => 1],
        ['id' => 'schulung',            'name_de' => 'Schulung oder Leitertreffen',                'name_en' => 'Training or Leaders\' Meeting',   'sort_order' => 7, 'is_active' => 1],
        ['id' => 'sonstiges',           'name_de' => 'Sonstige Veranstaltung',                     'name_en' => 'Other Event',                     'sort_order' => 8, 'is_active' => 1],
    ];

    $checkEtStmt = $pdo->prepare("SELECT id FROM event_types WHERE id = :id");
    $insEtStmt = $pdo->prepare("INSERT INTO event_types (id, name_de, name_en, sort_order, is_active) VALUES (:id, :name_de, :name_en, :sort_order, :is_active)");
    $cleanEtStmt = $pdo->prepare("UPDATE event_types SET name_de = :name_de, name_en = :name_en WHERE id = :id AND (name_de LIKE '%%' OR name_en LIKE '%%' OR name_de = 'Hauskreisveranstaltung')");

    foreach ($defaultEventTypes as $row) {
        $checkEtStmt->execute([':id' => $row['id']]);
        if (!$checkEtStmt->fetch()) {
            $insEtStmt->execute($row);
        } else {
            $cleanEtStmt->execute([':id' => $row['id'], ':name_de' => $row['name_de'], ':name_en' => $row['name_en']]);
        }
    }

    // Soft-delete: anonymise text in records older than 30 days but keep stats row
    // First: archive stats for rows about to be anonymised
    $aboutToExpire = $pdo->query("
        SELECT event_type, category, COUNT(*) as cnt, SUM(CASE WHEN rating > 0 THEN rating ELSE 0 END) as sum_r
        FROM feedback
        WHERE datetime(created_at) < datetime('now', '-30 days')
          AND (positive_text IS NOT NULL AND positive_text != '')
        GROUP BY event_type, category
    ")->fetchAll();

    foreach ($aboutToExpire as $row) {
        $week = date('Y-\WW'); // current ISO week as fallback; ideally derive from created_at
        $pdo->prepare("
            INSERT INTO feedback_stats (week_start, event_type, category, count, sum_rating)
            VALUES (:w, :et, :cat, :cnt, :sr)
        ")->execute([':w' => $week, ':et' => $row['event_type'], ':cat' => $row['category'], ':cnt' => $row['cnt'], ':sr' => $row['sum_r']]);
    }

    // Anonymise raw text (keep row for long-term stats)
    $pdo->exec("
        UPDATE feedback
        SET positive_text = NULL, improvement_text = NULL, author_name = NULL, author_contact = NULL
        WHERE datetime(created_at) < datetime('now', '-30 days')
          AND (positive_text IS NOT NULL OR improvement_text IS NOT NULL)
    ");

    // Actually purge fully-empty rows older than 90 days
    $pdo->exec("DELETE FROM feedback WHERE datetime(created_at) < datetime('now', '-90 days');");

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Database error: " . $e->getMessage()]);
    exit();
}

// ── Rate limiting (server-side, by IP) ───────────────────────────────────────
function isRateLimited(PDO $pdo, string $ip): bool {
    try {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS rate_limit (
                ip TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ");
        $pdo->exec("DELETE FROM rate_limit WHERE datetime(created_at) < datetime('now', '-15 minutes');");
        $stmt = $pdo->prepare("SELECT COUNT(*) as cnt FROM rate_limit WHERE ip = :ip");
        $stmt->execute([':ip' => $ip]);
        $row = $stmt->fetch();
        return (int)($row['cnt'] ?? 0) >= 3;
    } catch (Exception $e) {
        return false; // fail open
    }
}

function logRequest(PDO $pdo, string $ip): void {
    try {
        $pdo->prepare("INSERT INTO rate_limit (ip) VALUES (:ip)")->execute([':ip' => $ip]);
    } catch (Exception $e) {}
}

// ── Leader PIN verification ───────────────────────────────────────────────────
define('LEADER_PIN', '2018');

function verifyPin(?string $pin): bool {
    return trim((string)$pin) === LEADER_PIN;
}

$method = $_SERVER['REQUEST_METHOD'];
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// ── Helper: detect automated test records ──────────────────────────────────────
function getExcludeTestCondition(string $prefix = ''): string {
    $p = $prefix ? $prefix . '.' : '';
    return " NOT (
        LOWER({$p}tags) LIKE '%test%'
        OR LOWER({$p}author_name) = 'automated test'
        OR LOWER({$p}author_name) LIKE '%testbot%'
        OR LOWER({$p}positive_text) LIKE '%automatisierter test%'
        OR LOWER({$p}positive_text) LIKE '%automated live verification%'
    )";
}

// ══════════════════════════════════════════════════════════════════════════════
// GET Requests
// ══════════════════════════════════════════════════════════════════════════════
if ($method === 'GET') {

    // ── Aggregate stats (long-term) ──────────────────────────────────────────
    if (isset($_GET['stats']) && $_GET['stats'] === 'aggregate') {
        $rows = $pdo->query("SELECT week_start, event_type, category, SUM(count) as total, SUM(sum_rating) as sum_r FROM feedback_stats GROUP BY week_start, event_type, category ORDER BY week_start DESC")->fetchAll();
        echo json_encode(["success" => true, "aggregate" => $rows]);
        exit();
    }

    // ── Live stats ────────────────────────────────────────────────────────────
    if (isset($_GET['stats']) && $_GET['stats'] === '1') {
        $dateFrom    = isset($_GET['date_from'])    ? trim($_GET['date_from']) : '';
        $dateTo      = isset($_GET['date_to'])      ? trim($_GET['date_to']) : '';
        $eventType   = isset($_GET['event_type'])   ? trim($_GET['event_type']) : '';
        $category    = isset($_GET['category'])     ? trim($_GET['category']) : '';
        $status      = isset($_GET['status'])       ? trim($_GET['status']) : '';
        $includeTest = isset($_GET['include_test']) && $_GET['include_test'] === '1';

        $where = ['1=1'];
        $params = [];

        if (!$includeTest) {
            $where[] = getExcludeTestCondition();
        }

        if ($dateFrom) { $where[] = "service_date >= :date_from"; $params[':date_from'] = $dateFrom; }
        if ($dateTo)   { $where[] = "service_date <= :date_to";   $params[':date_to']   = $dateTo; }

        if ($status && $status !== 'all') {
            if ($status === 'unreviewed') {
                $where[] = "(reviewed = 0 AND action_taken = 0 AND status != 'archived')";
            } elseif ($status === 'reviewed') {
                $where[] = "reviewed = 1";
            } elseif ($status === 'action_taken') {
                $where[] = "action_taken = 1";
            } elseif ($status === 'archived') {
                $where[] = "status = 'archived'";
            } else {
                $where[] = "status = :status";
                $params[':status'] = $status;
            }
        }

        if ($category && $category !== 'all') {
            $where[] = "(category = :category OR (',' || REPLACE(category, ' ', '') || ',') LIKE :category_like)";
            $params[':category'] = $category;
            $params[':category_like'] = '%,' . str_replace(' ', '', $category) . ',%';
        }

        if ($eventType && $eventType !== 'all') {
            $etMatch = null;
            try {
                $stmtEt = $pdo->prepare("SELECT id, name_de, name_en FROM event_types WHERE LOWER(id) = LOWER(:e) OR LOWER(name_de) = LOWER(:e) OR LOWER(name_en) = LOWER(:e)");
                $stmtEt->execute([':e' => $eventType]);
                $etMatch = $stmtEt->fetch();
            } catch (Exception $e) {}

            if ($etMatch) {
                $aliasClauses = [
                    "LOWER(event_type) = LOWER(:et_id)",
                    "LOWER(event_type) = LOWER(:et_nde)",
                    "LOWER(event_type) = LOWER(:et_nen)"
                ];
                $params[':et_id']  = $etMatch['id'];
                $params[':et_nde'] = $etMatch['name_de'];
                $params[':et_nen'] = $etMatch['name_en'];

                if ($etMatch['id'] === 'lobpreisabend') {
                    $aliasClauses[] = "LOWER(event_type) = 'worship-abend'";
                } elseif ($etMatch['id'] === 'explore') {
                    $aliasClauses[] = "LOWER(event_type) = 'explore-abend'";
                } elseif ($etMatch['id'] === 'kleingruppen') {
                    $aliasClauses[] = "LOWER(event_type) = 'hauskreisleiter-nachmittag'";
                    $aliasClauses[] = "LOWER(event_type) LIKE '%hauskreis%'";
                }
                $where[] = "(" . implode(" OR ", $aliasClauses) . ")";
            } else {
                $where[] = "LOWER(event_type) = LOWER(:event_type)";
                $params[':event_type'] = $eventType;
            }
        }

        $whereSql = implode(" AND ", $where);

        $stmtRows = $pdo->prepare("SELECT id, event_type, category, rating, created_at FROM feedback WHERE $whereSql");
        $stmtRows->execute($params);
        $allFeedback = $stmtRows->fetchAll();

        $deptMap = [];
        $eventMap = [];
        $totalRating = 0;
        $ratingCount = 0;

        foreach ($allFeedback as $fb) {
            $r = (int)($fb['rating'] ?? 0);
            if ($r > 0) {
                $totalRating += $r;
                $ratingCount++;
            }

            // Event type
            $et = $fb['event_type'] ?: 'Gottesdienst';
            if (!isset($eventMap[$et])) {
                $eventMap[$et] = ['event_type' => $et, 'total_count' => 0, 'sum_rating' => 0, 'rating_count' => 0];
            }
            $eventMap[$et]['total_count']++;
            if ($r > 0) {
                $eventMap[$et]['sum_rating'] += $r;
                $eventMap[$et]['rating_count']++;
            }

            // Departments (split comma-separated)
            $cats = array_filter(array_map('trim', explode(',', $fb['category'] ?? 'Sonstiges')));
            if (empty($cats)) $cats = ['Sonstiges'];
            foreach ($cats as $c) {
                if (!isset($deptMap[$c])) {
                    $deptMap[$c] = ['category' => $c, 'total_count' => 0, 'sum_rating' => 0, 'rating_count' => 0];
                }
                $deptMap[$c]['total_count']++;
                if ($r > 0) {
                    $deptMap[$c]['sum_rating'] += $r;
                    $deptMap[$c]['rating_count']++;
                }
            }
        }

        $deptStats = [];
        foreach ($deptMap as $c => $d) {
            $deptStats[] = [
                'category'    => $c,
                'total_count' => $d['total_count'],
                'avg_rating'  => $d['rating_count'] > 0 ? round($d['sum_rating'] / $d['rating_count'], 1) : null,
            ];
        }
        usort($deptStats, fn($a, $b) => $b['total_count'] <=> $a['total_count']);

        $eventStats = [];
        foreach ($eventMap as $e => $d) {
            $eventStats[] = [
                'event_type'  => $e,
                'total_count' => $d['total_count'],
                'avg_rating'  => $d['rating_count'] > 0 ? round($d['sum_rating'] / $d['rating_count'], 1) : null,
            ];
        }
        usort($eventStats, fn($a, $b) => $b['total_count'] <=> $a['total_count']);

        // Overall: count of all filtered feedback rows (counted once)
        $overall = [
            'total_all' => count($allFeedback),
            'avg_all'   => $ratingCount > 0 ? round($totalRating / $ratingCount, 1) : null,
        ];

        // Trends: compare last 4 weeks vs previous 4 weeks per category
        $trendWhere = (!$includeTest) ? " AND " . getExcludeTestCondition() : "";
        $stmtTrend = $pdo->query("
            SELECT category,
                   AVG(CASE WHEN created_at >= datetime('now','-28 days') AND rating > 0 THEN rating END) as recent_avg,
                   AVG(CASE WHEN created_at < datetime('now','-28 days') AND created_at >= datetime('now','-56 days') AND rating > 0 THEN rating END) as prev_avg
            FROM feedback
            WHERE 1=1 $trendWhere
            GROUP BY category
        ");
        $trends = [];
        foreach ($stmtTrend->fetchAll() as $row) {
            $diff = (float)($row['recent_avg'] ?? 0) - (float)($row['prev_avg'] ?? 0);
            $trends[$row['category']] = $diff > 0.2 ? 'up' : ($diff < -0.2 ? 'down' : 'neutral');
        }

        echo json_encode([
            "success"       => true,
            "overall"       => $overall,
            "departments"   => $deptStats,
            "by_event_type" => $eventStats,
            "trends"        => $trends,
        ]);
        exit();
    }

    // ── Event types list ───────────────────────────────────────────────────────
    if (isset($_GET['event_types'])) {
        $stmt = $pdo->query("
            SELECT et.id, et.name_de, et.name_en, et.sort_order, et.is_active, et.created_at,
                   (
                       SELECT COUNT(*) FROM feedback f
                       WHERE LOWER(f.event_type) = LOWER(et.id)
                          OR LOWER(f.event_type) = LOWER(et.name_de)
                          OR LOWER(f.event_type) = LOWER(et.name_en)
                          OR (et.id = 'lobpreisabend' AND LOWER(f.event_type) = 'worship-abend')
                          OR (et.id = 'explore' AND LOWER(f.event_type) = 'explore-abend')
                          OR (et.id = 'kleingruppen' AND (LOWER(f.event_type) = 'hauskreisleiter-nachmittag' OR LOWER(f.event_type) LIKE '%hauskreis%'))
                   ) as feedback_count
            FROM event_types et
            ORDER BY et.sort_order ASC, et.created_at ASC
        ");
        $eventTypes = $stmt->fetchAll();
        echo json_encode(["success" => true, "event_types" => $eventTypes]);
        exit();
    }

    // ── List feedback entries ─────────────────────────────────────────────────
    $serviceDate = isset($_GET['service_date']) ? trim($_GET['service_date']) : '';
    $category    = isset($_GET['category'])     ? trim($_GET['category'])     : '';
    $eventType   = isset($_GET['event_type'])   ? trim($_GET['event_type'])   : '';
    $status      = isset($_GET['status'])       ? trim($_GET['status'])       : '';
    $dateFrom    = isset($_GET['date_from'])    ? trim($_GET['date_from'])    : '';
    $dateTo      = isset($_GET['date_to'])      ? trim($_GET['date_to'])      : '';
    $searchQuery = isset($_GET['q'])            ? trim($_GET['q'])            : '';
    $includeTest = isset($_GET['include_test']) && $_GET['include_test'] === '1';

    $whereClauses = ['1=1'];
    $params = [];

    if (!$includeTest) {
        $whereClauses[] = getExcludeTestCondition();
    }

    if (!empty($serviceDate) && $serviceDate !== 'all') {
        $whereClauses[] = "service_date = :service_date";
        $params[':service_date'] = $serviceDate;
    }
    if (!empty($category) && $category !== 'all') {
        $whereClauses[] = "(category = :category OR (',' || REPLACE(category, ' ', '') || ',') LIKE :category_like)";
        $params[':category'] = $category;
        $params[':category_like'] = '%,' . str_replace(' ', '', $category) . ',%';
    }
    if (!empty($eventType) && $eventType !== 'all') {
        $etMatch = null;
        try {
            $stmtEt = $pdo->prepare("SELECT id, name_de, name_en FROM event_types WHERE LOWER(id) = LOWER(:e) OR LOWER(name_de) = LOWER(:e) OR LOWER(name_en) = LOWER(:e)");
            $stmtEt->execute([':e' => $eventType]);
            $etMatch = $stmtEt->fetch();
        } catch (Exception $e) {}

        if ($etMatch) {
            $aliasClauses = [
                "LOWER(event_type) = LOWER(:et_id)",
                "LOWER(event_type) = LOWER(:et_nde)",
                "LOWER(event_type) = LOWER(:et_nen)"
            ];
            $params[':et_id']  = $etMatch['id'];
            $params[':et_nde'] = $etMatch['name_de'];
            $params[':et_nen'] = $etMatch['name_en'];

            if ($etMatch['id'] === 'lobpreisabend') {
                $aliasClauses[] = "LOWER(event_type) = 'worship-abend'";
            } elseif ($etMatch['id'] === 'explore') {
                $aliasClauses[] = "LOWER(event_type) = 'explore-abend'";
            } elseif ($etMatch['id'] === 'kleingruppen') {
                $aliasClauses[] = "LOWER(event_type) = 'hauskreisleiter-nachmittag'";
                $aliasClauses[] = "LOWER(event_type) LIKE '%hauskreis%'";
            }

            $whereClauses[] = "(" . implode(" OR ", $aliasClauses) . ")";
        } else {
            $whereClauses[] = "LOWER(event_type) = LOWER(:event_type)";
            $params[':event_type'] = $eventType;
        }
    }
    if (!empty($status) && $status !== 'all') {
        if ($status === 'unreviewed') {
            $whereClauses[] = "(reviewed = 0 AND action_taken = 0 AND status != 'archived')";
        } elseif ($status === 'reviewed') {
            $whereClauses[] = "reviewed = 1";
        } elseif ($status === 'action_taken') {
            $whereClauses[] = "action_taken = 1";
        } elseif ($status === 'archived') {
            $whereClauses[] = "status = 'archived'";
        } else {
            $whereClauses[] = "status = :status";
            $params[':status'] = $status;
        }
    }
    if (!empty($dateFrom)) {
        $whereClauses[] = "service_date >= :date_from";
        $params[':date_from'] = $dateFrom;
    }
    if (!empty($dateTo)) {
        $whereClauses[] = "service_date <= :date_to";
        $params[':date_to'] = $dateTo;
    }
    if (!empty($searchQuery)) {
        $whereClauses[] = "(
            positive_text LIKE :sq
            OR improvement_text LIKE :sq
            OR author_name LIKE :sq
            OR author_contact LIKE :sq
            OR category LIKE :sq
        )";
        $params[':sq'] = '%' . $searchQuery . '%';
    }

    $whereSql = "WHERE " . implode(" AND ", $whereClauses);

    $stmt = $pdo->prepare("
        SELECT id, service_date, event_type, category, rating,
               positive_text, improvement_text, tags,
               author_name, author_contact,
               status, reviewed, action_taken, created_at
        FROM feedback $whereSql
        ORDER BY created_at DESC LIMIT 500
    ");
    $stmt->execute($params);
    $items = $stmt->fetchAll();

    echo json_encode([
        "success"  => true,
        "count"    => count($items),
        "feedback" => $items,
    ]);
    exit();
}

// ══════════════════════════════════════════════════════════════════════════════
// POST Requests
// ══════════════════════════════════════════════════════════════════════════════
if ($method === 'POST') {
    $rawInput = file_get_contents("php://input");
    $data = json_decode($rawInput, true);

    if (!$data) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid JSON payload."]);
        exit();
    }

    // ── Moderation & Event Management actions (PIN-protected) ────────────────
    if (isset($data['_action'])) {
        if (!verifyPin($data['_pin'] ?? '')) {
            http_response_code(403);
            echo json_encode(["error" => "Ungültiger PIN."]);
            exit();
        }

        $action = $data['_action'];
        $id     = isset($data['_id']) ? (int)$data['_id'] : 0;

        switch ($action) {
            case 'approve':
                $pdo->prepare("UPDATE feedback SET status='approved' WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'hide':
                $pdo->prepare("UPDATE feedback SET status='hidden' WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'archive':
                $pdo->prepare("UPDATE feedback SET status='archived' WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'restore':
                $pdo->prepare("UPDATE feedback SET status='pending' WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'delete':
                $pdo->prepare("DELETE FROM feedback WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'reviewed':
                $val = isset($data['value']) ? ((int)$data['value'] ? 1 : 0) : 1;
                $pdo->prepare("UPDATE feedback SET reviewed=:val WHERE id=:id")->execute([':val' => $val, ':id' => $id]);
                break;
            case 'toggle_reviewed':
                $pdo->prepare("UPDATE feedback SET reviewed = CASE WHEN reviewed=1 THEN 0 ELSE 1 END WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'action_taken':
                $val = isset($data['value']) ? ((int)$data['value'] ? 1 : 0) : 1;
                $pdo->prepare("UPDATE feedback SET action_taken=:val WHERE id=:id")->execute([':val' => $val, ':id' => $id]);
                break;
            case 'toggle_action_taken':
                $pdo->prepare("UPDATE feedback SET action_taken = CASE WHEN action_taken=1 THEN 0 ELSE 1 END WHERE id=:id")->execute([':id' => $id]);
                break;
            case 'edit_category':
                $newCat = isset($data['category']) ? trim($data['category']) : '';
                if ($newCat) {
                    $pdo->prepare("UPDATE feedback SET category=:cat WHERE id=:id")->execute([':cat' => $newCat, ':id' => $id]);
                }
                break;

            // ── Event Type Management ──
            case 'save_event_type':
                $evId   = trim($data['id'] ?? '');
                $nameDe = trim($data['name_de'] ?? '');
                $nameEn = trim($data['name_en'] ?? '');
                $isActive = isset($data['is_active']) ? (int)$data['is_active'] : 1;

                if (empty($nameDe) || empty($nameEn)) {
                    http_response_code(400);
                    echo json_encode(["error" => "Bitte Name auf Deutsch und Englisch angeben."]);
                    exit();
                }

                // Check previous values before updating
                $oldRow = null;
                if (!empty($evId)) {
                    $oldStmt = $pdo->prepare("SELECT * FROM event_types WHERE LOWER(id) = LOWER(:id)");
                    $oldStmt->execute([':id' => $evId]);
                    $oldRow = $oldStmt->fetch();
                }

                if (empty($evId)) {
                    // Generate a clean slug
                    $slug = strtolower(preg_replace('/[^a-z0-9]+/i', '_', trim($nameDe)));
                    $slug = trim($slug, '_');
                    if (empty($slug)) $slug = 'event_' . time();
                    // Ensure uniqueness
                    $chk = $pdo->prepare("SELECT id FROM event_types WHERE id = :id");
                    $chk->execute([':id' => $slug]);
                    if ($chk->fetch()) {
                        $slug .= '_' . time();
                    }
                    $evId = $slug;
                }

                if (!isset($data['sort_order'])) {
                    $maxOrder = (int)$pdo->query("SELECT MAX(sort_order) FROM event_types")->fetchColumn();
                    $sortOrder = $maxOrder + 1;
                } else {
                    $sortOrder = (int)$data['sort_order'];
                }

                $stmt = $pdo->prepare("
                    INSERT INTO event_types (id, name_de, name_en, sort_order, is_active)
                    VALUES (:id, :name_de, :name_en, :sort_order, :is_active)
                    ON CONFLICT(id) DO UPDATE SET
                        name_de = excluded.name_de,
                        name_en = excluded.name_en,
                        is_active = excluded.is_active
                ");
                $stmt->execute([
                    ':id' => $evId,
                    ':name_de' => $nameDe,
                    ':name_en' => $nameEn,
                    ':sort_order' => $sortOrder,
                    ':is_active' => $isActive,
                ]);

                // If name changed, preserve existing feedback associations
                if ($oldRow) {
                    if ($oldRow['name_de'] !== $nameDe) {
                        $pdo->prepare("UPDATE feedback SET event_type = :nid WHERE event_type = :oname")->execute([':nid' => $evId, ':oname' => $oldRow['name_de']]);
                    }
                    if ($oldRow['name_en'] !== $nameEn) {
                        $pdo->prepare("UPDATE feedback SET event_type = :nid WHERE event_type = :oname")->execute([':nid' => $evId, ':oname' => $oldRow['name_en']]);
                    }
                }

                echo json_encode(["success" => true, "id" => $evId]);
                exit();

            case 'toggle_event_type':
                $evId = trim($data['id'] ?? '');
                $isActive = isset($data['is_active']) ? (int)$data['is_active'] : 1;
                $pdo->prepare("UPDATE event_types SET is_active = :act WHERE LOWER(id) = LOWER(:id)")->execute([':act' => $isActive, ':id' => $evId]);
                echo json_encode(["success" => true]);
                exit();

            case 'reorder_event_types':
                $order = $data['order'] ?? [];
                if (is_array($order)) {
                    $stmt = $pdo->prepare("UPDATE event_types SET sort_order = :ord WHERE LOWER(id) = LOWER(:id)");
                    foreach ($order as $idx => $evId) {
                        $stmt->execute([':ord' => $idx + 1, ':id' => trim($evId)]);
                    }
                }
                echo json_encode(["success" => true]);
                exit();

            case 'delete_event_type':
                $evId = trim($data['id'] ?? ($data['_id'] ?? ''));
                $evRow = $pdo->prepare("SELECT * FROM event_types WHERE LOWER(id) = LOWER(:id)");
                $evRow->execute([':id' => $evId]);
                $ev = $evRow->fetch();
                if (!$ev) {
                    http_response_code(404);
                    echo json_encode(["error" => "Veranstaltungsart nicht gefunden."]);
                    exit();
                }

                // Check if connected to feedback (case-insensitive)
                $stmt = $pdo->prepare("
                    SELECT COUNT(*) as cnt FROM feedback
                    WHERE LOWER(event_type) = LOWER(:id)
                       OR LOWER(event_type) = LOWER(:name_de)
                       OR LOWER(event_type) = LOWER(:name_en)
                       OR (:id = 'lobpreisabend' AND LOWER(event_type) = 'worship-abend')
                       OR (:id = 'explore' AND LOWER(event_type) = 'explore-abend')
                       OR (:id = 'kleingruppen' AND (LOWER(event_type) = 'hauskreisleiter-nachmittag' OR LOWER(event_type) LIKE '%hauskreis%'))
                ");
                $stmt->execute([':id' => $ev['id'], ':name_de' => $ev['name_de'], ':name_en' => $ev['name_en']]);
                $inUseCount = (int)$stmt->fetch()['cnt'];

                if ($inUseCount > 0) {
                    if ((int)$ev['is_active'] === 0) {
                        // Already inactive/archived and has feedback: block permanent deletion
                        http_response_code(400);
                        echo json_encode([
                            "error" => "Veranstaltungsart kann nicht gelöscht werden, da sie mit $inUseCount Rückmeldung(en) verknüpft ist. Sie bleibt archiviert.",
                            "archived" => true,
                            "feedback_count" => $inUseCount
                        ]);
                        exit();
                    }
                    // Safe guard: Do not delete permanently if connected to feedback! Deactivate instead.
                    $pdo->prepare("UPDATE event_types SET is_active = 0 WHERE LOWER(id) = LOWER(:id)")->execute([':id' => $ev['id']]);
                    echo json_encode([
                        "success" => true,
                        "archived" => true,
                        "feedback_count" => $inUseCount,
                        "message" => "Veranstaltungsart ist mit $inUseCount Rückmeldung(en) verknüpft und wurde archiviert."
                    ]);
                    exit();
                } else {
                    $pdo->prepare("DELETE FROM event_types WHERE LOWER(id) = LOWER(:id)")->execute([':id' => $ev['id']]);
                    echo json_encode([
                        "success" => true,
                        "deleted" => true,
                        "message" => "Veranstaltungsart wurde gelöscht."
                    ]);
                    exit();
                }

            default:
                http_response_code(400);
                echo json_encode(["error" => "Unknown action."]);
                exit();
        }

        echo json_encode(["success" => true]);
        exit();
    }

    // ── New feedback submission ────────────────────────────────────────────────
    // Honeypot
    if (!empty($data['website_hp'])) {
        echo json_encode(["success" => true, "message" => "Feedback received."]);
        exit();
    }

    // Rate limit
    if (isRateLimited($pdo, $clientIp)) {
        http_response_code(429);
        echo json_encode(["error" => "Zu viele Anfragen. Bitte warte kurz.", "rate_limited" => true]);
        exit();
    }

    $serviceDate     = isset($data['service_date'])     ? trim($data['service_date'])     : date('Y-m-d');
    $rawEventType    = isset($data['event_type'])       ? trim($data['event_type'])       : '';

    if (empty($rawEventType)) {
        http_response_code(400);
        echo json_encode(["error" => "Bitte wähle eine gültige Veranstaltungsart aus."]);
        exit();
    }

    // Server-side verification: event type must exist in event_types table and must be active
    $evStmt = $pdo->prepare("
        SELECT id, name_de, name_en, is_active 
        FROM event_types 
        WHERE LOWER(id) = LOWER(:e) OR LOWER(name_de) = LOWER(:e) OR LOWER(name_en) = LOWER(:e)
        LIMIT 1
    ");
    $evStmt->execute([':e' => $rawEventType]);
    $evMatch = $evStmt->fetch();

    if (!$evMatch) {
        http_response_code(400);
        echo json_encode(["error" => "Die angegebene Veranstaltungsart existiert nicht oder wurde gelöscht."]);
        exit();
    }

    if ((int)$evMatch['is_active'] !== 1) {
        http_response_code(400);
        echo json_encode(["error" => "Diese Veranstaltung ist archiviert und nimmt keine neuen Rückmeldungen mehr an."]);
        exit();
    }

    // Canonicalize to active event's German name
    $eventType = $evMatch['name_de'];
    if (isset($data['categories']) && is_array($data['categories'])) {
        $category = implode(', ', array_filter(array_map('trim', $data['categories'])));
    } elseif (isset($data['category'])) {
        $category = is_array($data['category']) ? implode(', ', array_filter(array_map('trim', $data['category']))) : trim($data['category']);
    } else {
        $category = 'Sonstiges';
    }
    if (empty($category)) {
        $category = 'Sonstiges';
    }
    $rating          = isset($data['rating'])           ? (int)$data['rating']            : 0;
    $positiveText    = isset($data['positive_text'])    ? trim($data['positive_text'])    : '';
    $improvementText = isset($data['improvement_text']) ? trim($data['improvement_text']) : '';
    $tags            = isset($data['tags']) && is_array($data['tags']) ? implode(',', $data['tags']) : (isset($data['tags']) ? trim($data['tags']) : '');
    $authorName      = isset($data['author_name'])      ? trim($data['author_name'])      : '';
    $authorContact   = isset($data['author_contact'])   ? trim($data['author_contact'])   : '';

    // Clamp rating
    if ($rating < 0) $rating = 0;
    if ($rating > 5) $rating = 5;

    // Validate: need at least text or a rating
    if (empty($positiveText) && empty($improvementText) && $rating === 0) {
        http_response_code(400);
        echo json_encode(["error" => "Bitte trage Feedback oder eine Bewertung ein."]);
        exit();
    }

    // Basic profanity / spam check (extend word list as needed)
    $spamWords = ['spam', 'viagra', 'casino', 'http://', 'https://', 'buy now', 'click here'];
    $combined = strtolower($positiveText . ' ' . $improvementText);
    foreach ($spamWords as $sw) {
        if (strpos($combined, $sw) !== false) {
            // Silently accept but mark hidden
            $rating = 0;
            $positiveText = '';
            $improvementText = '';
            break;
        }
    }

    $stmt = $pdo->prepare("
        INSERT INTO feedback
            (service_date, event_type, category, rating, positive_text, improvement_text, tags, author_name, author_contact, status)
        VALUES
            (:service_date, :event_type, :category, :rating, :positive_text, :improvement_text, :tags, :author_name, :author_contact, 'pending')
    ");

    $stmt->execute([
        ':service_date'     => $serviceDate,
        ':event_type'       => $eventType,
        ':category'         => $category,
        ':rating'           => $rating,
        ':positive_text'    => $positiveText,
        ':improvement_text' => $improvementText,
        ':tags'             => $tags,
        ':author_name'      => $authorName,
        ':author_contact'   => $authorContact,
    ]);

    $newId = (int)$pdo->lastInsertId();

    logRequest($pdo, $clientIp);

    echo json_encode([
        "success" => true,
        "message" => "Feedback erfolgreich gespeichert!",
        "id"      => $newId,
    ]);
    exit();
}

http_response_code(405);
echo json_encode(["error" => "Method not allowed"]);
