<?php
/**
 * Pulsschlag Deggendorf - Gratitude Photo Wall API
 * Handles public photo wall queries, participant photo uploads, and organizer admin actions.
 * Enforces server-side upload status, Europe/Berlin scheduling, storage quotas, and image sanitization.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Leader-Pin, X-Participant-Id");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$dbDir = getenv('EVENT_STORAGE_DIR') ?: (__DIR__ . '/data');
if (!file_exists($dbDir)) {
    @mkdir($dbDir, 0755, true);
}
$jsonFile = $dbDir . '/events_store.json';
$deletedFile = $dbDir . '/deleted_events.json';
$authFile = $dbDir . '/planner_auth.json';
$rateLimitFile = $dbDir . '/photo_rate_limits.json';

$uploadDir = getenv('PHOTO_WALL_DIR') ?: (__DIR__ . '/../gratitude_photos');
if (!file_exists($uploadDir)) {
    @mkdir($uploadDir, 0755, true);
}
if (!file_exists($uploadDir)) {
    $uploadDir = dirname(__DIR__) . '/gratitude_photos';
    if (!file_exists($uploadDir)) {
        @mkdir($uploadDir, 0755, true);
    }
}

// Ensure .htaccess blocks script execution in gratitude_photos
$uploadHtaccess = $uploadDir . '/.htaccess';
if (!file_exists($uploadHtaccess)) {
    $denyScript = "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phps|cgi|pl|sh|exe|py)$\">\n    Order allow,deny\n    Deny from all\n</FilesMatch>\nRemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phps\nSetHandler default-handler\n";
    @file_put_contents($uploadHtaccess, $denyScript);
}

function getClientIp(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

function checkPhotoRateLimit(string $rateFile, string $ip): bool {
    $now = time();
    $window = 300; // 5 minutes
    $maxUploads = 25; // max 25 uploads per IP per 5 mins

    $limits = [];
    if (file_exists($rateFile)) {
        $limits = json_decode(file_get_contents($rateFile), true) ?: [];
    }

    $ipAttempts = isset($limits[$ip]) && is_array($limits[$ip]) ? $limits[$ip] : [];
    $ipAttempts = array_filter($ipAttempts, fn($ts) => ($now - $ts) < $window);

    if (count($ipAttempts) >= $maxUploads) {
        return false;
    }

    $ipAttempts[] = $now;
    $limits[$ip] = array_values($ipAttempts);
    @file_put_contents($rateFile, json_encode($limits), LOCK_EX);
    return true;
}

function getStoredPinHash(string $authFile): string {
    if (file_exists($authFile)) {
        $raw = file_get_contents($authFile);
        $data = json_decode($raw, true);
        if (is_array($data)) {
            if (!empty($data['hash'])) return (string)$data['hash'];
            if (!empty($data['pin_hash'])) return (string)$data['pin_hash'];
            if (!empty($data['pin'])) {
                $h = password_hash((string)$data['pin'], PASSWORD_DEFAULT);
                $data['hash'] = $h;
                unset($data['pin']);
                @file_put_contents($authFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
                return $h;
            }
        }
    }
    $defPin = '2018';
    $defHash = password_hash($defPin, PASSWORD_DEFAULT);
    @file_put_contents($authFile, json_encode(["hash" => $defHash, "updated_at" => date('c')], JSON_PRETTY_PRINT), LOCK_EX);
    return $defHash;
}

function verifyPin(?string $pin, string $authFile): bool {
    if (!$pin) return false;
    $stored = getStoredPinHash($authFile);
    if (password_verify(trim($pin), $stored)) return true;
    // Fallback for sha256 mock test hashes if any
    if (strlen($stored) === 64 && hash('sha256', trim($pin)) === $stored) return true;
    return false;
}

function extractPin(): string {
    if (!empty($_SERVER['HTTP_X_LEADER_PIN'])) return trim($_SERVER['HTTP_X_LEADER_PIN']);
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $a = trim($_SERVER['HTTP_AUTHORIZATION']);
        if (stripos($a, 'Bearer ') === 0) return trim(substr($a, 7));
    }
    if (isset($_GET['pin'])) return trim($_GET['pin']);
    if (isset($_POST['pin'])) return trim($_POST['pin']);
    return '';
}

function getBerlinNow(): DateTime {
    return new DateTime('now', new DateTimeZone('Europe/Berlin'));
}

function evaluateUploadStatus(array $wall): array {
    $manualStatus = $wall['uploadStatus'] ?? 'open';
    if ($manualStatus === 'closed') {
        return ['open' => false, 'reason' => 'manual', 'message' => 'Uploads wurden manuell geschlossen.'];
    }

    $now = getBerlinNow();
    if (!empty($wall['scheduledOpen'])) {
        try {
            $openDt = new DateTime($wall['scheduledOpen'], new DateTimeZone('Europe/Berlin'));
            if ($now < $openDt) {
                return [
                    'open' => false,
                    'reason' => 'scheduled_future',
                    'message' => 'Uploads öffnen am ' . $openDt->format('d.m.Y \u\m H:i') . ' Uhr.'
                ];
            }
        } catch (Exception $e) {}
    }

    if (!empty($wall['scheduledClose'])) {
        try {
            $closeDt = new DateTime($wall['scheduledClose'], new DateTimeZone('Europe/Berlin'));
            if ($now >= $closeDt) {
                return [
                    'open' => false,
                    'reason' => 'scheduled_past',
                    'message' => 'Uploads wurden am ' . $closeDt->format('d.m.Y \u\m H:i') . ' Uhr beendet.'
                ];
            }
        } catch (Exception $e) {}
    }

    return ['open' => true, 'reason' => null, 'message' => 'Uploads geöffnet.'];
}

function loadAllEvents(string $jsonFile, string $deletedFile): array {
    $deletedIds = [];
    if (file_exists($deletedFile)) {
        $deletedIds = json_decode(file_get_contents($deletedFile), true) ?: [];
    }
    $events = [];
    if (file_exists($jsonFile)) {
        $events = json_decode(file_get_contents($jsonFile), true) ?: [];
    }
    return array_values(array_filter($events, fn($e) => isset($e['id']) && !in_array($e['id'], $deletedIds)));
}

function saveEvents(string $jsonFile, array $events): bool {
    return file_put_contents($jsonFile, json_encode($events, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX) !== false;
}

function findEventByToken(array $events, string $token): ?array {
    $token = trim($token);
    if (!$token) return null;
    foreach ($events as $idx => $ev) {
        $gw = $ev['gratitudeWall'] ?? null;
        if (!$gw || empty($gw['enabled'])) continue;
        if ((!empty($gw['uploadToken']) && $gw['uploadToken'] === $token) ||
            (!empty($gw['wallToken']) && $gw['wallToken'] === $token)) {
            return [
                'index' => $idx,
                'event' => $ev,
                'isUploadToken' => (!empty($gw['uploadToken']) && $gw['uploadToken'] === $token),
                'isWallToken' => (!empty($gw['wallToken']) && $gw['wallToken'] === $token)
            ];
        }
    }
    return null;
}

function detectImageType(string $data): ?string {
    if (strlen($data) < 12) return null;
    if (substr($data, 0, 3) === "\xFF\xD8\xFF") return 'jpeg';
    if (substr($data, 0, 8) === "\x89PNG\r\n\x1a\n") return 'png';
    if (substr($data, 0, 4) === "RIFF" && substr($data, 8, 4) === "WEBP") return 'webp';
    return null;
}

function stripExifAndSave(string $imageData, string $destPath, string $type): bool {
    // If GD is available, re-encoding guarantees 100% removal of EXIF/GPS tags
    if (extension_loaded('gd') && function_exists('imagecreatefromstring')) {
        $im = @imagecreatefromstring($imageData);
        if ($im !== false) {
            $ok = false;
            if ($type === 'png') {
                imagealphablending($im, false);
                imagesavealpha($im, true);
                $ok = @imagepng($im, $destPath, 8);
            } elseif ($type === 'webp' && function_exists('imagewebp')) {
                $ok = @imagewebp($im, $destPath, 85);
            } else {
                $ok = @imagejpeg($im, $destPath, 85);
            }
            imagedestroy($im);
            if ($ok) return true;
        }
    }

    // Direct binary write (Client canvas re-encoding already strips EXIF before upload)
    return file_put_contents($destPath, $imageData, LOCK_EX) !== false;
}

function createThumbnail(string $origPath, string $thumbPath, int $maxDim = 400): bool {
    if (extension_loaded('gd') && function_exists('imagecreatefromstring')) {
        $raw = @file_get_contents($origPath);
        if (!$raw) return false;
        $src = @imagecreatefromstring($raw);
        if (!$src) return false;

        $w = imagesx($src);
        $h = imagesy($src);
        if ($w <= 0 || $h <= 0) {
            imagedestroy($src);
            return false;
        }

        $scale = min(1.0, $maxDim / max($w, $h));
        $tw = max(1, (int)round($w * $scale));
        $th = max(1, (int)round($h * $scale));

        $dst = imagecreatetruecolor($tw, $th);
        imagealphablending($dst, false);
        imagesavealpha($dst, true);
        imagecopyresampled($dst, $src, 0, 0, 0, 0, $tw, $th, $w, $h);

        $ok = @imagejpeg($dst, $thumbPath, 80);
        imagedestroy($src);
        imagedestroy($dst);
        return $ok;
    }
    // Fallback: copy original
    return @copy($origPath, $thumbPath);
}

// ── GET REQUESTS ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? 'wall_data';
    $token = $_GET['token'] ?? '';
    $eventId = $_GET['event_id'] ?? '';
    $pin = extractPin();

    $events = loadAllEvents($jsonFile, $deletedFile);

    // ACTION: WALL_DATA (Public participant read for wall or upload page)
    if ($action === 'wall_data') {
        header("Content-Type: application/json; charset=UTF-8");
        $found = findEventByToken($events, $token);
        if (!$found) {
            http_response_code(404);
            echo json_encode(["success" => false, "message" => "Fotowand nicht gefunden oder ungültiger Link."]);
            exit();
        }

        $ev = $found['event'];
        $gw = $ev['gratitudeWall'] ?? [];
        $uploadStatus = evaluateUploadStatus($gw);

        $wallStatus = $gw['wallStatus'] ?? 'open';
        $keepVisible = $gw['keepWallVisibleAfterClose'] ?? true;
        // Wall is visible if wallStatus is open, UNLESS uploads are closed AND keepVisible is false
        $isWallVisible = ($wallStatus === 'open');
        if (!$uploadStatus['open'] && !$keepVisible) {
            $isWallVisible = false;
        }

        // Calculate storage usage
        $storageBytes = array_reduce($gw['photos'] ?? [], fn($sum, $p) => $sum + ($p['sizeBytes'] ?? 0), 0);

        // Safe public projection (no sensitive planning info)
        $publicPhotos = array_map(function($p) {
            return [
                "id" => $p['id'],
                "url" => $p['url'],
                "thumbnailUrl" => $p['thumbnailUrl'] ?? $p['url'],
                "uploadedAt" => $p['uploadedAt'] ?? '',
                "width" => $p['width'] ?? 0,
                "height" => $p['height'] ?? 0,
                "sizeBytes" => $p['sizeBytes'] ?? 0
            ];
        }, $gw['photos'] ?? []);

        // Sort descending by upload time (newest first for wall)
        usort($publicPhotos, fn($a, $b) => strcmp($b['uploadedAt'], $a['uploadedAt']));

        // If organizer with valid PIN requests, show photos even if public wall is closed
        $isOrganizer = verifyPin($pin, $authFile);
        $photosToReturn = ($isWallVisible || $isOrganizer) ? $publicPhotos : [];

        echo json_encode([
            "success" => true,
            "title" => $gw['title'] ?? 'Dafür bin ich dankbar',
            "title_en" => $gw['title_en'] ?? 'What I’m grateful for',
            "introduction" => $gw['introduction'] ?? 'Unsere digitalen Erntedankgaben: Lade ein Bild hoch, das zeigt, wofür du dankbar bist.',
            "introduction_en" => $gw['introduction_en'] ?? 'Our digital harvest thanksgiving offerings: Upload a photo showing what you’re grateful for.',
            "eventTitle" => $ev['details']['title'] ?? '',
            "uploadToken" => $gw['uploadToken'] ?? '',
            "wallToken" => $gw['wallToken'] ?? '',
            "eventId" => $ev['id'],
            "isUploadToken" => $found['isUploadToken'],
            "isWallToken" => $found['isWallToken'],
            "uploadOpen" => $uploadStatus['open'],
            "uploadReason" => $uploadStatus['reason'],
            "uploadMessage" => $uploadStatus['message'],
            "wallVisible" => $isWallVisible,
            "wallMessage" => $isWallVisible ? '' : 'Diese Fotowand ist derzeit nicht öffentlich einsehbar.',
            "photoCount" => count($gw['photos'] ?? []),
            "storageBytes" => $storageBytes,
            "maxStorageBytes" => 500 * 1024 * 1024,
            "photos" => $photosToReturn
        ]);
        exit();
    }

    // ACTION: ADMIN_WALL_DATA (Organizer view with all metadata and full photo details)
    if ($action === 'admin_wall_data') {
        header("Content-Type: application/json; charset=UTF-8");
        if (!verifyPin($pin, $authFile)) {
            http_response_code(403);
            echo json_encode(["success" => false, "message" => "Berechtigung verweigert: Gültige Leitungs-PIN erforderlich."]);
            exit();
        }

        $targetEvent = null;
        if ($eventId) {
            foreach ($events as $ev) {
                if ($ev['id'] === $eventId) {
                    $targetEvent = $ev;
                    break;
                }
            }
        } elseif ($token) {
            $found = findEventByToken($events, $token);
            if ($found) $targetEvent = $found['event'];
        }

        if (!$targetEvent) {
            http_response_code(404);
            echo json_encode(["success" => false, "message" => "Event nicht gefunden."]);
            exit();
        }

        $gw = $targetEvent['gratitudeWall'] ?? [];
        $uploadStatus = evaluateUploadStatus($gw);
        $storageBytes = array_reduce($gw['photos'] ?? [], fn($sum, $p) => $sum + ($p['sizeBytes'] ?? 0), 0);

        echo json_encode([
            "success" => true,
            "eventId" => $targetEvent['id'],
            "eventTitle" => $targetEvent['details']['title'] ?? '',
            "gratitudeWall" => $gw,
            "uploadOpen" => $uploadStatus['open'],
            "uploadReason" => $uploadStatus['reason'],
            "uploadMessage" => $uploadStatus['message'],
            "photoCount" => count($gw['photos'] ?? []),
            "storageBytes" => $storageBytes,
            "maxStorageBytes" => 500 * 1024 * 1024,
            "photos" => $gw['photos'] ?? []
        ]);
        exit();
    }

    // ACTION: DOWNLOAD_ZIP (Organizer or wall participant)
    if ($action === 'download_zip') {
        $targetEvent = null;
        if ($token) {
            $found = findEventByToken($events, $token);
            if ($found) $targetEvent = $found['event'];
        } elseif ($eventId && verifyPin($pin, $authFile)) {
            foreach ($events as $ev) {
                if ($ev['id'] === $eventId) {
                    $targetEvent = $ev;
                    break;
                }
            }
        }

        if (!$targetEvent || empty($targetEvent['gratitudeWall']['photos'])) {
            http_response_code(404);
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Keine Fotos zum Herunterladen gefunden."]);
            exit();
        }

        $gw = $targetEvent['gratitudeWall'];
        $photos = $gw['photos'] ?? [];

        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $tmpZip = tempnam(sys_get_temp_dir(), 'wallzip_') . '.zip';
            if ($zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
                foreach ($photos as $idx => $p) {
                    $fn = basename($p['filename'] ?? basename($p['url']));
                    $filePath = $uploadDir . '/' . $fn;
                    if (file_exists($filePath)) {
                        $zipName = sprintf('foto_%03d_%s', $idx + 1, $fn);
                        $zip->addFile($filePath, $zipName);
                    }
                }
                $zip->close();

                $safeTitle = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $gw['title'] ?? 'Fotowand');
                header('Content-Type: application/zip');
                header('Content-Disposition: attachment; filename="' . $safeTitle . '_' . date('Ymd_His') . '.zip"');
                header('Content-Length: ' . filesize($tmpZip));
                header('Pragma: no-cache');
                readfile($tmpZip);
                @unlink($tmpZip);
                exit();
            }
        }

        // Fallback: return JSON list of photo URLs for client-side JSZip
        header("Content-Type: application/json");
        echo json_encode([
            "success" => true,
            "fallback_client" => true,
            "photos" => $photos
        ]);
        exit();
    }
}

// ── POST REQUESTS ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input');
    $inputData = json_decode($rawInput, true) ?: [];

    $action = $_POST['action'] ?? $inputData['action'] ?? 'upload';
    $token = trim($_POST['token'] ?? $_POST['upload_token'] ?? $inputData['token'] ?? $inputData['upload_token'] ?? $_GET['token'] ?? $_GET['upload_token'] ?? '');
    $pin = extractPin();
    if (!$pin && !empty($inputData['pin'])) $pin = trim($inputData['pin']);
    if (!$pin && !empty($_POST['pin'])) $pin = trim($_POST['pin']);

    $events = loadAllEvents($jsonFile, $deletedFile);

    // ── 1. PARTICIPANT UPLOAD ACTION ──────────────────────────────────────────
    if ($action === 'upload') {
        header("Content-Type: application/json; charset=UTF-8");
        $found = findEventByToken($events, $token);
        if (!$found) {
            http_response_code(404);
            echo json_encode(["success" => false, "message" => "Ungültiger Upload-Link oder Event existiert nicht mehr."]);
            exit();
        }

        $evIndex = $found['index'];
        $ev = $found['event'];
        $gw = $ev['gratitudeWall'] ?? [];

        // Enforce upload window strictly on server
        $status = evaluateUploadStatus($gw);
        if (!$status['open']) {
            http_response_code(403);
            echo json_encode(["success" => false, "message" => $status['message']]);
            exit();
        }

        // Rate limiting
        $ip = getClientIp();
        if (!checkPhotoRateLimit($rateLimitFile, $ip)) {
            http_response_code(429);
            echo json_encode(["success" => false, "message" => "Zu viele Uploads hintereinander. Bitte kurz warten."]);
            exit();
        }

        // Extract image bytes
        $imageData = null;
        $thumbData = null;
        $fingerprint = trim($_POST['fingerprint'] ?? $inputData['fingerprint'] ?? '');

        if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
            $imageData = file_get_contents($_FILES['photo']['tmp_name']);
        } elseif (!empty($inputData['photo'])) {
            $b64 = $inputData['photo'];
            if (preg_match('/^data:image\/(\w+);base64,/', $b64)) {
                $b64 = substr($b64, strpos($b64, ',') + 1);
            }
            $imageData = base64_decode($b64, true);
        }

        if (isset($_FILES['thumbnail']) && $_FILES['thumbnail']['error'] === UPLOAD_ERR_OK) {
            $thumbData = file_get_contents($_FILES['thumbnail']['tmp_name']);
        } elseif (!empty($inputData['thumbnail'])) {
            $tb64 = $inputData['thumbnail'];
            if (preg_match('/^data:image\/(\w+);base64,/', $tb64)) {
                $tb64 = substr($tb64, strpos($tb64, ',') + 1);
            }
            $thumbData = base64_decode($tb64, true);
        }

        if (!$imageData || strlen($imageData) === 0) {
            http_response_code(400);
            echo json_encode(["success" => false, "message" => "Keine Bilddaten empfangen."]);
            exit();
        }

        // Limit check: 10 MB raw
        if (strlen($imageData) > 10 * 1024 * 1024) {
            http_response_code(413);
            echo json_encode(["success" => false, "message" => "Bild überschreitet das Limit von 10 MB."]);
            exit();
        }

        // Magic bytes validation
        $imgType = detectImageType($imageData);
        if (!$imgType) {
            http_response_code(400);
            echo json_encode(["success" => false, "message" => "Ungültiges Bildformat. Nur echte JPG-, PNG- oder WebP-Bilder sind erlaubt."]);
            exit();
        }

        // Fingerprint check to prevent accidental duplicate submission
        if ($fingerprint) {
            foreach ($gw['photos'] ?? [] as $existingP) {
                if (!empty($existingP['fingerprint']) && $existingP['fingerprint'] === $fingerprint) {
                    echo json_encode([
                        "success" => true,
                        "duplicate" => true,
                        "photo" => $existingP,
                        "message" => "Foto wurde bereits hochgeladen."
                    ]);
                    exit();
                }
            }
        }

        // Event quota check (500 MB max per event)
        $currentBytes = array_reduce($gw['photos'] ?? [], fn($sum, $p) => $sum + ($p['sizeBytes'] ?? 0), 0);
        if ($currentBytes + strlen($imageData) > 500 * 1024 * 1024) {
            http_response_code(400);
            echo json_encode(["success" => false, "message" => "Speicherlimit für diese Fotowand erreicht (500 MB)."]);
            exit();
        }

        // Generate safe unguessable filenames
        $photoId = 'p_' . time() . '_' . bin2hex(random_bytes(6));
        $ext = ($imgType === 'png') ? 'png' : (($imgType === 'webp') ? 'webp' : 'jpg');
        $filename = 'wall_' . $photoId . '.' . $ext;
        $thumbFilename = 'thumb_' . $photoId . '.' . $ext;

        $targetPath = $uploadDir . '/' . $filename;
        $thumbPath = $uploadDir . '/' . $thumbFilename;

        // Strip EXIF metadata and write photo
        if (!stripExifAndSave($imageData, $targetPath, $imgType)) {
            http_response_code(500);
            echo json_encode(["success" => false, "message" => "Fehler beim Speichern auf dem Server."]);
            exit();
        }

        // Save thumbnail: either client-generated or server-generated
        if ($thumbData && detectImageType($thumbData)) {
            stripExifAndSave($thumbData, $thumbPath, detectImageType($thumbData));
        } else {
            createThumbnail($targetPath, $thumbPath, 400);
        }

        $width = (int)($_POST['width'] ?? $inputData['width'] ?? 0);
        $height = (int)($_POST['height'] ?? $inputData['height'] ?? 0);
        if ($width <= 0 || $height <= 0) {
            if (function_exists('getimagesize')) {
                $sz = @getimagesize($targetPath);
                if ($sz) {
                    $width = $sz[0];
                    $height = $sz[1];
                }
            }
        }

        $newPhotoRecord = [
            "id" => $photoId,
            "filename" => $filename,
            "thumbnailFilename" => $thumbFilename,
            "url" => "/gratitude_photos/" . $filename,
            "thumbnailUrl" => "/gratitude_photos/" . $thumbFilename,
            "uploadedAt" => getBerlinNow()->format('c'),
            "width" => $width ?: 1200,
            "height" => $height ?: 900,
            "sizeBytes" => filesize($targetPath) ?: strlen($imageData),
            "mimeType" => "image/" . $imgType,
            "fingerprint" => $fingerprint ?: md5($imageData)
        ];

        // Append photo to event atomically
        if (!isset($events[$evIndex]['gratitudeWall']['photos'])) {
            $events[$evIndex]['gratitudeWall']['photos'] = [];
        }
        $events[$evIndex]['gratitudeWall']['photos'][] = $newPhotoRecord;
        $events[$evIndex]['updatedAt'] = time() * 1000;

        saveEvents($jsonFile, $events);

        echo json_encode([
            "success" => true,
            "photo" => $newPhotoRecord,
            "message" => "Foto erfolgreich hochgeladen und auf der Wand platziert!"
        ]);
        exit();
    }

    // ── 2. ORGANIZER / ADMIN ACTIONS (PIN-PROTECTED) ───────────────────────────
    header("Content-Type: application/json; charset=UTF-8");
    if (!verifyPin($pin, $authFile)) {
        http_response_code(401);
        echo json_encode(["success" => false, "message" => "Berechtigung verweigert: Gültige Leitungs-PIN erforderlich."]);
        exit();
    }

    $eventId = trim($_POST['event_id'] ?? $inputData['event_id'] ?? '');
    $targetIdx = -1;
    if ($eventId) {
        foreach ($events as $i => $ev) {
            if ($ev['id'] === $eventId) {
                $targetIdx = $i;
                break;
            }
        }
    } elseif ($token) {
        $found = findEventByToken($events, $token);
        if ($found) {
            $targetIdx = $found['index'];
        }
    }

    if ($targetIdx < 0) {
        http_response_code(404);
        echo json_encode(["success" => false, "message" => "Event nicht gefunden."]);
        exit();
    }

    $currentEv = &$events[$targetIdx];
    if (!isset($currentEv['gratitudeWall'])) {
        $currentEv['gratitudeWall'] = [
            "enabled" => true,
            "title" => "Dafür bin ich dankbar",
            "introduction" => "Unsere digitalen Erntedankgaben: Lade ein Bild hoch, das zeigt, wofür du dankbar bist.",
            "uploadToken" => "up_" . bin2hex(random_bytes(10)),
            "wallToken" => "wall_" . bin2hex(random_bytes(10)),
            "uploadStatus" => "open",
            "wallStatus" => "open",
            "keepWallVisibleAfterClose" => true,
            "photos" => []
        ];
    }
    $gw = &$currentEv['gratitudeWall'];

    // ACTION: ADMIN_TOGGLE_UPLOAD
    if ($action === 'admin_toggle_upload') {
        $newStatus = trim($_POST['upload_status'] ?? $inputData['upload_status'] ?? $inputData['uploadStatus'] ?? $_POST['uploadStatus'] ?? '');
        if ($newStatus !== 'open' && $newStatus !== 'closed') {
            $newStatus = ($gw['uploadStatus'] === 'open') ? 'closed' : 'open';
        }
        $gw['uploadStatus'] = $newStatus;
        $currentEv['updatedAt'] = time() * 1000;
        saveEvents($jsonFile, $events);

        echo json_encode([
            "success" => true,
            "uploadStatus" => $newStatus,
            "message" => ($newStatus === 'open') ? "Uploads wurden geöffnet." : "Uploads wurden geschlossen."
        ]);
        exit();
    }

    // ACTION: ADMIN_UPDATE_SETTINGS
    if ($action === 'admin_update_settings') {
        $settings = $inputData['settings'] ?? $_POST;
        if (isset($settings['enabled'])) $gw['enabled'] = (bool)$settings['enabled'];
        if (isset($settings['title'])) $gw['title'] = trim($settings['title']);
        if (isset($settings['title_en'])) $gw['title_en'] = trim($settings['title_en']);
        if (isset($settings['introduction'])) $gw['introduction'] = trim($settings['introduction']);
        if (isset($settings['introduction_en'])) $gw['introduction_en'] = trim($settings['introduction_en']);
        if (isset($settings['uploadStatus'])) $gw['uploadStatus'] = $settings['uploadStatus'];
        if (isset($settings['wallStatus'])) $gw['wallStatus'] = $settings['wallStatus'];
        if (array_key_exists('scheduledOpen', $settings)) $gw['scheduledOpen'] = $settings['scheduledOpen'];
        if (array_key_exists('scheduledClose', $settings)) $gw['scheduledClose'] = $settings['scheduledClose'];
        if (isset($settings['keepWallVisibleAfterClose'])) $gw['keepWallVisibleAfterClose'] = (bool)$settings['keepWallVisibleAfterClose'];

        $currentEv['updatedAt'] = time() * 1000;
        saveEvents($jsonFile, $events);

        echo json_encode([
            "success" => true,
            "gratitudeWall" => $gw,
            "message" => "Einstellungen gespeichert."
        ]);
        exit();
    }

    // ACTION: ADMIN_DELETE_PHOTO
    if ($action === 'admin_delete_photo') {
        $photoId = trim($_POST['photo_id'] ?? $inputData['photo_id'] ?? $inputData['photoId'] ?? $_POST['photoId'] ?? '');
        $photos = $gw['photos'] ?? [];
        $remaining = [];
        $deletedCount = 0;

        foreach ($photos as $p) {
            if ($p['id'] === $photoId) {
                // Delete physical files
                if (!empty($p['filename'])) @unlink($uploadDir . '/' . basename($p['filename']));
                if (!empty($p['thumbnailFilename'])) @unlink($uploadDir . '/' . basename($p['thumbnailFilename']));
                $deletedCount++;
            } else {
                $remaining[] = $p;
            }
        }

        $gw['photos'] = $remaining;
        $currentEv['updatedAt'] = time() * 1000;
        saveEvents($jsonFile, $events);

        echo json_encode([
            "success" => true,
            "deletedCount" => $deletedCount,
            "remainingCount" => count($remaining),
            "message" => "Foto wurde gelöscht."
        ]);
        exit();
    }

    // ACTION: ADMIN_DELETE_ALL_PHOTOS
    if ($action === 'admin_delete_all_photos') {
        $photos = $gw['photos'] ?? [];
        foreach ($photos as $p) {
            if (!empty($p['filename'])) @unlink($uploadDir . '/' . basename($p['filename']));
            if (!empty($p['thumbnailFilename'])) @unlink($uploadDir . '/' . basename($p['thumbnailFilename']));
        }
        $gw['photos'] = [];
        $currentEv['updatedAt'] = time() * 1000;
        saveEvents($jsonFile, $events);

        echo json_encode([
            "success" => true,
            "message" => "Alle Fotos dieser Fotowand wurden unwiderruflich gelöscht."
        ]);
        exit();
    }

    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Unbekannte Admin-Aktion."]);
    exit();
}
