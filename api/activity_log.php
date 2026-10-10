<?php
/**
 * Pulsschlag Deggendorf - Central Admin Activity & Visitor Audit Log API
 * SQLite backend recording page visits, submissions, team signups, and admin edits.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$dbDir = __DIR__ . '/data';
if (!file_exists($dbDir)) {
    @mkdir($dbDir, 0755, true);
    @file_put_contents($dbDir . '/.htaccess', "Order deny,allow\nDeny from all\n");
}

$dbPath = $dbDir . '/activity.sqlite';

try {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            device TEXT DEFAULT 'Desktop',
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_activity_tool ON activity_logs(tool);
    ");

    // Auto-purge logs older than 90 days
    $pdo->exec("DELETE FROM activity_logs WHERE datetime(created_at) < datetime('now', '-90 days');");

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Database error: " . $e->getMessage()]);
    exit();
}

// GET: Fetch recent logs for Admin Dashboard
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $toolFilter = isset($_GET['tool']) ? trim($_GET['tool']) : '';
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 150;
    if ($limit > 500) $limit = 500;

    if (!empty($toolFilter) && $toolFilter !== 'all') {
        $stmt = $pdo->prepare("SELECT * FROM activity_logs WHERE tool = :tool ORDER BY created_at DESC LIMIT :limit");
        $stmt->bindValue(':tool', $toolFilter, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $stmt = $pdo->prepare("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT :limit");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
    }

    $logs = $stmt->fetchAll();
    echo json_encode(["success" => true, "logs" => $logs, "count" => count($logs)]);
    exit();
}

// POST: Log a new visitor or action event
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input) {
        echo json_encode(["success" => false, "message" => "Ungültiges Payload."]);
        exit();
    }

    $tool = isset($input['tool']) ? trim($input['tool']) : 'portal';
    $action = isset($input['action']) ? trim($input['action']) : 'Besuch';
    $details = isset($input['details']) ? trim($input['details']) : '';
    $device = isset($input['device']) ? trim($input['device']) : 'Desktop';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 200) : '';

    $stmt = $pdo->prepare("INSERT INTO activity_logs (tool, action, details, device, user_agent) VALUES (:tool, :action, :details, :device, :ua)");
    $stmt->execute([
        ':tool' => $tool,
        ':action' => $action,
        ':details' => $details,
        ':device' => $device,
        ':ua' => $ua
    ]);

    echo json_encode(["success" => true, "message" => "Aktivität protokolliert."]);
    exit();
}
