<?php
/**
 * Pulsschlag Deggendorf - Event Phase Email Reminder Service
 * Sends branded HTML email reminders to event leaders for specific event phases.
 * Requires organizer PIN for sending phase reminders.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Leader-Pin");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true);

if (!$input) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Ungültiges JSON Format."]);
    exit();
}

$dbDir = __DIR__ . '/data';
$authFile = $dbDir . '/planner_auth.json';
$rateLimitFile = $dbDir . '/rate_limits.json';

function getClientIp(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

function checkRateLimit(string $rateLimitFile, string $ip): array {
    $now = time();
    $window = 900;
    $maxAttempts = 5;

    $limits = [];
    if (file_exists($rateLimitFile)) {
        $raw = file_get_contents($rateLimitFile);
        $limits = json_decode($raw, true) ?: [];
    }

    $ipAttempts = isset($limits[$ip]) && is_array($limits[$ip]) ? $limits[$ip] : [];
    $ipAttempts = array_filter($ipAttempts, function($ts) use ($now, $window) {
        return ($now - $ts) < $window;
    });

    if (count($ipAttempts) >= $maxAttempts) {
        $oldest = min($ipAttempts);
        $retryAfter = $window - ($now - $oldest);
        return ["blocked" => true, "retryAfter" => max(1, $retryAfter)];
    }

    return ["blocked" => false, "attempts" => count($ipAttempts)];
}

function recordFailedAttempt(string $rateLimitFile, string $ip): void {
    $now = time();
    $window = 900;

    $limits = [];
    if (file_exists($rateLimitFile)) {
        $raw = file_get_contents($rateLimitFile);
        $limits = json_decode($raw, true) ?: [];
    }

    $ipAttempts = isset($limits[$ip]) && is_array($limits[$ip]) ? $limits[$ip] : [];
    $ipAttempts = array_filter($ipAttempts, function($ts) use ($now, $window) {
        return ($now - $ts) < $window;
    });

    $ipAttempts[] = $now;
    $limits[$ip] = array_values($ipAttempts);

    @file_put_contents($rateLimitFile, json_encode($limits, JSON_PRETTY_PRINT), LOCK_EX);
    usleep(250000);
}

function resetFailedAttempts(string $rateLimitFile, string $ip): void {
    if (file_exists($rateLimitFile)) {
        $raw = file_get_contents($rateLimitFile);
        $limits = json_decode($raw, true) ?: [];
        if (isset($limits[$ip])) {
            unset($limits[$ip]);
            @file_put_contents($rateLimitFile, json_encode($limits, JSON_PRETTY_PRINT), LOCK_EX);
        }
    }
}

function getStoredPinHash(string $authFile): string {
    if (file_exists($authFile)) {
        $raw = file_get_contents($authFile);
        $data = json_decode($raw, true);
        if (is_array($data)) {
            if (!empty($data['hash'])) {
                return (string)$data['hash'];
            }
            if (!empty($data['pin'])) {
                $hash = password_hash((string)$data['pin'], PASSWORD_DEFAULT);
                $data['hash'] = $hash;
                unset($data['pin']);
                $data['updated_at'] = date('c');
                @file_put_contents($authFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
                return $hash;
            }
        }
    }

    $defaultPin = '2018';
    $defaultHash = password_hash($defaultPin, PASSWORD_DEFAULT);
    @file_put_contents($authFile, json_encode([
        "hash" => $defaultHash,
        "updated_at" => date('c')
    ], JSON_PRETTY_PRINT), LOCK_EX);
    return $defaultHash;
}

function verifyLeaderPin(?string $pin, string $authFile, string $rateLimitFile): array {
    $ip = getClientIp();
    $rate = checkRateLimit($rateLimitFile, $ip);
    if ($rate['blocked']) {
        return [
            "success" => false,
            "status" => 429,
            "message" => "Zu viele Fehlversuche. Bitte in {$rate['retryAfter']} Sekunden erneut versuchen."
        ];
    }

    if ($pin === null || $pin === '') {
        return [
            "success" => false,
            "status" => 401,
            "message" => "Leitungs-PIN erforderlich."
        ];
    }

    $hash = getStoredPinHash($authFile);
    if (password_verify(trim($pin), $hash)) {
        resetFailedAttempts($rateLimitFile, $ip);
        return [
            "success" => true,
            "status" => 200,
            "message" => "PIN verifiziert."
        ];
    }

    recordFailedAttempt($rateLimitFile, $ip);
    return [
        "success" => false,
        "status" => 401,
        "message" => "Ungültige Leitungs-PIN."
    ];
}

function extractRequestPin(): string {
    if (!empty($_SERVER['HTTP_X_LEADER_PIN'])) {
        return trim($_SERVER['HTTP_X_LEADER_PIN']);
    }
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $auth = trim($_SERVER['HTTP_AUTHORIZATION']);
        if (stripos($auth, 'Bearer ') === 0) {
            return trim(substr($auth, 7));
        }
    }
    if (isset($_GET['pin'])) {
        return trim($_GET['pin']);
    }
    return '';
}

$rawOrganizerEmail = isset($input['organizerEmail']) ? trim($input['organizerEmail']) : '';
$organizerName = isset($input['organizerName']) ? trim($input['organizerName']) : 'Event-Leitung';
$eventTitle = isset($input['eventTitle']) ? trim($input['eventTitle']) : 'Gemeinde-Event';
$eventId = isset($input['eventId']) ? trim($input['eventId']) : '';
$action = isset($input['action']) ? trim($input['action']) : 'reminder';

// Helper to parse multiple email addresses separated by comma or semicolon
$emailParts = preg_split('/[,;]+/', $rawOrganizerEmail);
$validEmails = [];
foreach ($emailParts as $part) {
    $clean = trim($part);
    if (filter_var($clean, FILTER_VALIDATE_EMAIL)) {
        $validEmails[] = $clean;
    }
}
if (empty($validEmails)) {
    $validEmails = ['info@pulsschlag.church'];
}
$recipientString = implode(', ', $validEmails);

$eventUrl = $eventId 
    ? "https://tools.pulsschlag.church/?view=event-planner&event=" . urlencode($eventId) 
    : "https://tools.pulsschlag.church/?view=event-planner";

if ($action === 'question') {
    $questionAuthor = isset($input['questionAuthor']) ? trim($input['questionAuthor']) : 'Teilnehmer';
    $questionText = isset($input['questionText']) ? trim($input['questionText']) : '';

    $subject = "Neue Frage zum Event: " . $eventTitle . " von " . $questionAuthor;
    $htmlBody = '
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: Arial, sans-serif; background-color: #181817; color: #ffffff; padding: 20px; margin: 0;">
      <div style="max-width: 600px; margin: 0 auto; background: #23232a; border-radius: 14px; padding: 24px; border: 1px solid #fbb900;">
        <h2 style="color: #fbb900; margin-top: 0;">Neue Frage an die Event-Leitung</h2>
        <p style="font-size: 14px; color: #a1a1aa;">Event: <strong style="color: #ffffff;">' . htmlspecialchars($eventTitle) . '</strong></p>
        <p style="font-size: 14px; color: #a1a1aa;">Absender: <strong style="color: #ffffff;">' . htmlspecialchars($questionAuthor) . '</strong></p>
        <div style="background: rgba(251, 185, 0, 0.1); border-left: 4px solid #fbb900; padding: 14px 18px; border-radius: 8px; margin: 20px 0; font-size: 15px; color: #ffffff; line-height: 1.5;">
          ' . nl2br(htmlspecialchars($questionText)) . '
        </div>
        <p style="font-size: 12px; color: #71717a; text-align: center; border-top: 1px solid #3f3f46; padding-top: 12px;">
          Gesendet über den Pulsschlag Event-Planer • <a href="' . htmlspecialchars($eventUrl) . '" style="color: #fbb900;">tools.pulsschlag.church</a>
        </p>
      </div>
    </body>
    </html>';

    $fromAddress = "eventplaner@pulsschlag.church";
    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: Pulsschlag Event-Planer <" . $fromAddress . ">\r\n";
    $headers .= "Reply-To: " . $fromAddress . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    $isTestMode = (!empty($_SERVER['HTTP_X_TEST_MODE']) && $_SERVER['HTTP_X_TEST_MODE'] === '1') || !empty($input['test_mode']);
    $mailSuccess = $isTestMode ? true : @mail($recipientString, $subject, $htmlBody, $headers, "-f " . $fromAddress);

    echo json_encode([
        "success" => true,
        "message" => "Deine Frage wurde erfolgreich verarbeitet für (" . $recipientString . ")!",
        "recipient" => $recipientString,
        "test_mode" => $isTestMode
    ]);
    exit();
}

// Action: Phase reminder email (requires organizer authorization)
$pin = isset($input['pin']) ? trim($input['pin']) : extractRequestPin();
$authResult = verifyLeaderPin($pin, $authFile, $rateLimitFile);
if (!$authResult['success']) {
    http_response_code($authResult['status']);
    echo json_encode([
        "success" => false,
        "message" => "Berechtigung verweigert: Nur die Event-Leitung mit gültiger PIN kann Phasen-Erinnerungen versenden."
    ]);
    exit();
}

$phaseName = isset($input['phaseName']) ? trim($input['phaseName']) : 'Aktuelle Phase';
$eventDate = isset($input['eventDate']) ? trim($input['eventDate']) : '';
$eventLocation = isset($input['eventLocation']) ? trim($input['eventLocation']) : 'Pulsschlag Deggendorf';
$tasks = isset($input['tasks']) && is_array($input['tasks']) ? $input['tasks'] : [];
$roles = isset($input['roles']) && is_array($input['roles']) ? $input['roles'] : [];
$gear = isset($input['gear']) && is_array($input['gear']) ? $input['gear'] : [];

$subject = "Erinnerung: " . $eventTitle . " (" . $phaseName . ") - Pulsschlag Deggendorf";

$htmlBody = '
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; background-color: #181817; color: #e4e4e7; padding: 20px; margin: 0; }
    .container { max-width: 620px; margin: 0 auto; background: #23232a; border-radius: 14px; padding: 28px; border: 1px solid rgba(251, 185, 0, 0.3); }
    .header { border-bottom: 2px solid #fbb900; padding-bottom: 16px; margin-bottom: 24px; text-align: center; }
    .header h1 { margin: 0; color: #ffffff; font-size: 22px; }
    .header p { margin: 6px 0 0; color: #fbb900; font-size: 14px; font-weight: bold; }
    .info-box { background: rgba(251, 185, 0, 0.1); border: 1px solid rgba(251, 185, 0, 0.3); border-radius: 10px; padding: 16px; margin-bottom: 24px; }
    .info-row { font-size: 14px; margin-bottom: 6px; color: #f4f4f5; }
    .info-row strong { color: #fbb900; }
    .phase-badge { background: #fbb900; color: #000000; padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 12px; display: inline-block; margin-bottom: 12px; }
    .section-title { font-size: 16px; font-weight: bold; color: #ffffff; margin-top: 20px; margin-bottom: 12px; border-left: 3px solid #fbb900; padding-left: 10px; }
    .task-item { background: #1e1e24; border: 1px solid #3f3f46; border-radius: 8px; padding: 12px 14px; margin-bottom: 8px; font-size: 14px; display: flex; align-items: center; justify-content: space-between; }
    .task-done { text-decoration: line-through; color: #71717a; border-color: #27272a; }
    .role-badge { background: #3f3f46; color: #e4e4e7; font-size: 11px; padding: 2px 8px; border-radius: 6px; }
    .btn { display: inline-block; background: #fbb900; color: #000000; text-decoration: none; font-weight: bold; padding: 12px 24px; border-radius: 8px; margin-top: 24px; text-align: center; }
    .footer { font-size: 12px; color: #71717a; text-align: center; margin-top: 28px; border-top: 1px solid #27272a; padding-top: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Pulsschlag Deggendorf Portal</h1>
      <p>Event-Planer Phase Erinnerung</p>
    </div>

    <div class="phase-badge">' . htmlspecialchars($phaseName) . '</div>

    <p style="font-size: 15px; color: #ffffff;">Hallo ' . htmlspecialchars($organizerName) . ',</p>
    <p style="font-size: 14px; color: #a1a1aa; line-height: 1.5;">hier ist deine Phasen-Erinnerung für <strong>' . htmlspecialchars($eventTitle) . '</strong> mit allen Aufgaben und Verantwortlichkeiten:</p>

    <div class="info-box">
      <div class="info-row"><strong>Event:</strong> ' . htmlspecialchars($eventTitle) . '</div>
      <div class="info-row"><strong>Termin:</strong> ' . htmlspecialchars($eventDate) . '</div>
      <div class="info-row"><strong>Ort:</strong> ' . htmlspecialchars($eventLocation) . '</div>
      <div class="info-row"><strong>Ansprechpartner:</strong> ' . htmlspecialchars($organizerName) . ' (' . htmlspecialchars($recipientString) . ')</div>
    </div>

    <div class="section-title">Checkliste: ' . htmlspecialchars($phaseName) . '</div>
';

if (count($tasks) > 0) {
    foreach ($tasks as $task) {
        $isDone = !empty($task['done']);
        $cssClass = $isDone ? 'task-item task-done' : 'task-item';
        $icon = $isDone ? '✅' : '☐';
        
        $htmlBody .= '<div class="' . $cssClass . '">';
        $htmlBody .= '<span>' . $icon . ' ' . htmlspecialchars($task['task']) . '</span>';
        if (!empty($task['role'])) {
            $htmlBody .= ' <span class="role-badge">' . htmlspecialchars($task['role']) . '</span>';
        }
        $htmlBody .= '</div>';
    }
} else {
    $htmlBody .= '<p style="font-size: 13px; color: #71717a;">Keine spezifischen Aufgaben in dieser Phase hinterlegt.</p>';
}

if (count($roles) > 0) {
    $htmlBody .= '<div class="section-title">Bereichsleiter & Verantwortliche</div><ul style="padding-left: 20px; font-size: 13px; color: #cbd5e1;">';
    foreach ($roles as $role) {
        $roleName = isset($role['name']) ? $role['name'] : '';
        $person = isset($role['default']) && !empty($role['default']) ? $role['default'] : 'Noch offen';
        $htmlBody .= '<li><strong>' . htmlspecialchars($roleName) . ':</strong> ' . htmlspecialchars($person) . '</li>';
    }
    $htmlBody .= '</ul>';
}

if (count($gear) > 0) {
    $htmlBody .= '<div class="section-title">Benötigtes Material & Equipment</div><ul style="padding-left: 20px; font-size: 13px; color: #38bdf8;">';
    foreach ($gear as $item) {
        $htmlBody .= '<li>' . htmlspecialchars($item) . '</li>';
    }
    $htmlBody .= '</ul>';
}

$htmlBody .= '
    <div style="text-align: center;">
      <a href="' . htmlspecialchars($eventUrl) . '" class="btn">Master-Plan im Portal öffnen</a>
    </div>

    <div class="footer">
      <p>Pulsschlag Deggendorf • <a href="https://tools.pulsschlag.church" style="color: #fbb900;">tools.pulsschlag.church</a></p>
    </div>
  </div>
</body>
</html>
';

$fromAddress = "eventplaner@pulsschlag.church";
$headers  = "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/html; charset=UTF-8\r\n";
$headers .= "From: Pulsschlag Event-Planer <" . $fromAddress . ">\r\n";
$headers .= "Reply-To: " . $fromAddress . "\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

$isTestMode = (!empty($_SERVER['HTTP_X_TEST_MODE']) && $_SERVER['HTTP_X_TEST_MODE'] === '1') || !empty($input['test_mode']);
$mailSuccess = $isTestMode ? true : @mail($recipientString, $subject, $htmlBody, $headers, "-f " . $fromAddress);

echo json_encode([
    "success" => true,
    "message" => "Erinnerungs-E-Mail verarbeitet für " . $recipientString,
    "recipient" => $recipientString,
    "phase" => $phaseName,
    "test_mode" => $isTestMode
]);
exit();
