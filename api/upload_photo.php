<?php
/**
 * Pulsschlag Deggendorf - Photo Upload API
 * Receives image uploads for event documentation, validates event association,
 * enforces strict 5MB size limit, verifies image magic bytes (JPG/PNG/WEBP only),
 * and stores sanitized images in cleanup_photos/ with script execution disabled.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-Participant-Id, X-Leader-Pin");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["success" => false, "message" => "POST method required."]);
    exit();
}

$dbDir = getenv('EVENT_STORAGE_DIR') ?: (__DIR__ . '/data');
$jsonFile = $dbDir . '/events_store.json';
$deletedFile = $dbDir . '/deleted_events.json';

// Ensure upload directory exists
$uploadDir = getenv('EVENT_UPLOAD_DIR') ?: (__DIR__ . '/../cleanup_photos');
if (!file_exists($uploadDir)) {
    @mkdir($uploadDir, 0755, true);
}
if (!file_exists($uploadDir)) {
    $uploadDir = dirname(__DIR__) . '/cleanup_photos';
    if (!file_exists($uploadDir)) {
        @mkdir($uploadDir, 0755, true);
    }
}

// Ensure .htaccess blocks script execution in cleanup_photos
$uploadHtaccess = $uploadDir . '/.htaccess';
if (!file_exists($uploadHtaccess)) {
    $denyScript = "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phps|cgi|pl|sh|exe|py)$\">\n    Order allow,deny\n    Deny from all\n</FilesMatch>\nRemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phps\nSetHandler default-handler\n";
    @file_put_contents($uploadHtaccess, $denyScript);
}

$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true);

$eventId = '';
if (is_array($inputData) && !empty($inputData['event_id'])) {
    $eventId = trim($inputData['event_id']);
} else if (!empty($_POST['event_id'])) {
    $eventId = trim($_POST['event_id']);
}

if (empty($eventId)) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Event-ID ist erforderlich für den Foto-Upload."]);
    exit();
}

// Verify that the event exists and has not been deleted
$deletedIds = [];
if (file_exists($deletedFile)) {
    $raw = file_get_contents($deletedFile);
    $deletedIds = json_decode($raw, true) ?: [];
}
if (in_array($eventId, $deletedIds)) {
    http_response_code(404);
    echo json_encode(["success" => false, "message" => "Dieses Event wurde gelöscht. Upload nicht möglich."]);
    exit();
}

$eventExists = false;
if (file_exists($jsonFile)) {
    $raw = file_get_contents($jsonFile);
    $events = json_decode($raw, true) ?: [];
    foreach ($events as $ev) {
        if (isset($ev['id']) && $ev['id'] === $eventId) {
            $eventExists = true;
            break;
        }
    }
}

if (!$eventExists) {
    http_response_code(404);
    echo json_encode(["success" => false, "message" => "Event mit der angegebenen ID existiert nicht auf dem Server."]);
    exit();
}

$imageData = null;

// Case 1: Base64 JSON Payload
if (is_array($inputData) && !empty($inputData['image'])) {
    $base64String = $inputData['image'];
    if (preg_match('/^data:image\/(\w+);base64,/', $base64String)) {
        $base64String = substr($base64String, strpos($base64String, ',') + 1);
    }
    $imageData = base64_decode($base64String, true);
}
// Case 2: Multipart Form-Data
else if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
    $imageData = file_get_contents($_FILES['photo']['tmp_name']);
}

if (!$imageData || strlen($imageData) === 0) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Keine Bilddaten übermittelt oder fehlerhafter Upload."]);
    exit();
}

// 1. Enforce max file size: 5 MB (5 * 1024 * 1024 bytes)
$maxSizeBytes = 5 * 1024 * 1024;
if (strlen($imageData) > $maxSizeBytes) {
    http_response_code(413);
    echo json_encode(["success" => false, "message" => "Die Bilddatei überschreitet das Limit von 5 MB."]);
    exit();
}

// 2. Validate MIME type & magic bytes using finfo
$mimeType = null;
if (function_exists('finfo_open')) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_buffer($finfo, $imageData);
    finfo_close($finfo);
}

// Fallback validation via getimagesizefromstring if finfo is unavailable
$allowedMimes = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp'
];

if (!$mimeType || !isset($allowedMimes[$mimeType])) {
    if (function_exists('getimagesizefromstring')) {
        $imgInfo = @getimagesizefromstring($imageData);
        if ($imgInfo && isset($imgInfo['mime']) && isset($allowedMimes[$imgInfo['mime']])) {
            $mimeType = $imgInfo['mime'];
        }
    }
}

if (!$mimeType || !isset($allowedMimes[$mimeType])) {
    http_response_code(400);
    echo json_encode([
        "success" => false, 
        "message" => "Ungültiges Bildformat. Nur echte JPG-, PNG- und WEBP-Bilder sind zulässig."
    ]);
    exit();
}

$ext = $allowedMimes[$mimeType];

// Generate unguessable sanitized filename
$cleanEventId = preg_replace('/[^a-zA-Z0-9_\-]/', '', $eventId);
try {
    $randomHex = bin2hex(random_bytes(8));
} catch (Exception $e) {
    $randomHex = substr(md5(uniqid((string)rand(), true)), 0, 16);
}

$fileName = 'photo_' . $cleanEventId . '_' . time() . '_' . $randomHex . '.' . $ext;
$targetPath = $uploadDir . '/' . $fileName;

if (file_put_contents($targetPath, $imageData, LOCK_EX)) {
    $publicUrl = '/cleanup_photos/' . $fileName;
    echo json_encode([
        "success" => true,
        "url" => $publicUrl,
        "filename" => $fileName,
        "message" => "Foto erfolgreich hochgeladen und verifiziert."
    ]);
} else {
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "message" => "Fehler beim Speichern der Bilddatei auf dem Server."
    ]);
}
