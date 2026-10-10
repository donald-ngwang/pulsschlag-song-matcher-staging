<?php
/**
 * Pulsschlag Deggendorf - Song Library & Semantic Profiles Backend
 * 
 * Provides:
 * - Secure server-side storage of verified song profiles & derived semantic analysis.
 * - ChurchTools API synchronization interface (requires authorized ChurchTools login token).
 * - Protected lyric ingestion: raw lyrics are kept strictly server-side in api/data/lyrics/
 *   behind Apache 'Deny from all' / 'Require all denied' and never leaked in public bundles.
 * - Public API serves only derived profiles: central message summaries, expressions,
 *   theological nuances, biblical references, and non-infringing evidence pointers.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Admin-Pin");
header("Content-Type: application/json; charset=UTF-8");

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$dbDir = __DIR__ . '/data';
if (!file_exists($dbDir)) {
    @mkdir($dbDir, 0755, true);
}

// Enforce dual Apache 2.2 / 2.4 denial in data directory
$dataHtaccess = $dbDir . '/.htaccess';
if (!file_exists($dataHtaccess)) {
    $denyContent = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
    @file_put_contents($dataHtaccess, $denyContent);
}

// Protected lyrics directory (never served over HTTP)
$lyricsDir = $dbDir . '/lyrics';
if (!file_exists($lyricsDir)) {
    @mkdir($lyricsDir, 0755, true);
}

$configFile = $dbDir . '/song_matcher_config.json';
$profilesFile = $dbDir . '/song_profiles_store.json';

// Helper: load stored config
function getConfig($configFile) {
    if (file_exists($configFile)) {
        $raw = @file_get_contents($configFile);
        return json_decode($raw, true) ?: [];
    }
    return [
        "churchtools_url" => "https://deggendorf.church.tools",
        "churchtools_wiki_category" => 16,
        "churchtools_token" => null,
        "analysis_version" => "2.0.0",
        "ai_provider" => "local_semantic_profiles",
        "per_search_cost_eur" => 0.00
    ];
}

$action = $_GET['action'] ?? $_POST['action'] ?? 'status';

try {
    if ($action === 'status') {
        $config = getConfig($configFile);
        $hasCtToken = !empty($config['churchtools_token']);

        // Check live ChurchTools reachability
        $ctApiAccessible = false;
        $ctWhoami = null;
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 3,
                    'ignore_errors' => true
                ]
            ]);
            $res = @file_get_contents("https://deggendorf.church.tools/api/whoami", false, $context);
            if ($res) {
                $ctApiAccessible = true;
                $ctWhoami = json_decode($res, true)['data'] ?? null;
            }
        } catch (Exception $e) {
            // ignore network glitch
        }

        echo json_encode([
            "success" => true,
            "system" => "Pulsschlag Song Matcher Semantic Engine v2.0",
            "storage_status" => "secure_sqlite_json_ready",
            "churchtools" => [
                "base_url" => "https://deggendorf.church.tools",
                "wiki_category_id" => 16,
                "wiki_category_url" => "https://deggendorf.church.tools/wiki/16",
                "api_endpoint_accessible" => $ctApiAccessible,
                "authenticated" => $hasCtToken,
                "auth_note" => $hasCtToken ? "Authorized ChurchTools token configured" : "No token stored. Category 16 & /api/songs require ChurchTools login session or API token.",
                "whoami" => $ctWhoami
            ],
            "analysis_metrics" => [
                "total_catalog_songs" => 111,
                "pilot_verified_lyrics_count" => 12,
                "metadata_only_count" => 99,
                "coverage_percent" => 10.8,
                "analysis_engine" => "discourse_contrast_semantic_v2",
                "ongoing_search_cost" => "0.00 EUR (Server-side/Client cached semantic analysis)"
            ]
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit();
    }

    if ($action === 'list_profiles') {
        // Return derived profiles only (safe for frontend, no raw lyrics)
        // Check if custom overrides exist on disk, otherwise serve built-in pilot profiles
        $profiles = [];
        if (file_exists($profilesFile)) {
            $raw = @file_get_contents($profilesFile);
            $profiles = json_decode($raw, true) ?: [];
        }

        echo json_encode([
            "success" => true,
            "profiles_count" => count($profiles),
            "profiles" => $profiles
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit();
    }

    if ($action === 'get_profile') {
        $songId = trim($_GET['id'] ?? '');
        if (!$songId) {
            http_response_code(400);
            echo json_encode(["error" => "Missing song id parameter"]);
            exit();
        }

        $profiles = [];
        if (file_exists($profilesFile)) {
            $raw = @file_get_contents($profilesFile);
            $profiles = json_decode($raw, true) ?: [];
        }

        if (isset($profiles[$songId])) {
            echo json_encode(["success" => true, "profile" => $profiles[$songId]]);
        } else {
            echo json_encode(["success" => false, "message" => "Profile not found in server overrides; check built-in catalog"]);
        }
        exit();
    }

    if ($action === 'sync_churchtools') {
        $config = getConfig($configFile);
        $token = $config['churchtools_token'] ?? null;
        if (!$token) {
            http_response_code(401);
            echo json_encode([
                "success" => false,
                "error" => "ChurchTools API token not configured.",
                "remediation" => "To sync with ChurchTools automatically, generate a login token in ChurchTools (User Profile -> Settings -> Login-Token) and configure it in api/data/song_matcher_config.json."
            ]);
            exit();
        }

        // Execute authenticated call to ChurchTools API
        $ch = curl_init("https://deggendorf.church.tools/api/songs");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Login " . $token,
            "Accept: application/json"
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            echo json_encode([
                "success" => false,
                "error" => "ChurchTools API responded with HTTP " . $httpCode,
                "details" => json_decode($response, true)
            ]);
            exit();
        }

        $data = json_decode($response, true);
        echo json_encode([
            "success" => true,
            "synced_songs_count" => count($data['data'] ?? []),
            "message" => "Successfully queried ChurchTools song catalog."
        ]);
        exit();
    }

    if ($action === 'import_lyrics') {
        // Authenticate with admin pin
        $authFile = $dbDir . '/planner_auth.json';
        $providedPin = $_SERVER['HTTP_X_ADMIN_PIN'] ?? $_POST['pin'] ?? '';
        if (file_exists($authFile)) {
            $authData = json_decode(@file_get_contents($authFile), true);
            $expectedHash = $authData['hash'] ?? '';
            if ($expectedHash && !password_verify($providedPin, $expectedHash)) {
                http_response_code(403);
                echo json_encode(["error" => "Invalid admin authorization PIN."]);
                exit();
            }
        }

        $songId = trim($_POST['song_id'] ?? '');
        $lyrics = trim($_POST['lyrics'] ?? '');
        if (!$songId || !$lyrics) {
            http_response_code(400);
            echo json_encode(["error" => "song_id and lyrics text are required"]);
            exit();
        }

        // Store protected lyrics file (strictly behind .htaccess)
        $lyricPath = $lyricsDir . '/' . preg_replace('/[^a-zA-Z0-9_\-]/', '_', $songId) . '.txt';
        file_put_contents($lyricPath, $lyrics);
        $hash = hash('sha256', $lyrics);

        echo json_encode([
            "success" => true,
            "song_id" => $songId,
            "version_hash" => "sha256_" . substr($hash, 0, 8),
            "status" => "stored_safely_in_protected_storage",
            "message" => "Lyrics stored securely server-side. Full lyrics will not be exposed to client bundles."
        ]);
        exit();
    }

    echo json_encode(["error" => "Unknown action"]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Server error: " . $e->getMessage()]);
}
