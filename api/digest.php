<?php
/**
 * Pulsschlag Deggendorf - Weekly Feedback Email Digest Script
 * Compiles Sunday service feedback and sends a formatted HTML report from feedback@pulsschlag.church.
 * Manages email recipient settings in SQLite so recipients sync across all devices.
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

$dbPath = $dbDir . '/feedback.sqlite';

try {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Create settings table for cross-device sync
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ");

    $action = isset($_GET['action']) ? $_GET['action'] : '';

    // Action 1: Get saved email recipient setting
    if ($action === 'get_settings' || $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['get_email'])) {
        $stmt = $pdo->prepare("SELECT value FROM settings WHERE key = 'recipient_emails'");
        $stmt->execute();
        $row = $stmt->fetch();
        $email = $row ? $row['value'] : "leitung@pulsschlag.church, pastoral@pulsschlag.church";
        echo json_encode(["success" => true, "email" => $email]);
        exit();
    }

    // Action 2: Save email recipient setting
    if ($action === 'save_settings') {
        $input = json_decode(file_get_contents('php://input'), true);
        $email = isset($input['email']) ? trim($input['email']) : (isset($_GET['email']) ? trim($_GET['email']) : '');
        if (!empty($email)) {
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('recipient_emails', :val)");
            $stmt->execute([':val' => $email]);
            echo json_encode(["success" => true, "message" => "Empfänger-E-Mail in der Datenbank gespeichert.", "email" => $email]);
        } else {
            echo json_encode(["success" => false, "message" => "Keine E-Mail angegeben."]);
        }
        exit();
    }

    // Action 3: Send Digest Report & Save Recipient Email
    $input = json_decode(file_get_contents('php://input'), true);
    $toParam = isset($_GET['email']) && !empty($_GET['email']) ? trim($_GET['email']) : (isset($input['email']) ? trim($input['email']) : '');

    if (!empty($toParam)) {
        $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('recipient_emails', :val)");
        $stmt->execute([':val' => $toParam]);
        $to = $toParam;
    } else {
        $stmt = $pdo->prepare("SELECT value FROM settings WHERE key = 'recipient_emails'");
        $stmt->execute();
        $row = $stmt->fetch();
        $to = $row ? $row['value'] : "leitung@pulsschlag.church, pastoral@pulsschlag.church";
    }

    // Fetch all feedback from past 30 days
    $stmt = $pdo->query("
        SELECT * FROM feedback 
        ORDER BY created_at DESC
        LIMIT 100
    ");
    $items = $stmt->fetchAll();

    if (count($items) === 0) {
        echo json_encode(["success" => true, "message" => "Kein Feedback in der Datenbank vorhanden.", "count" => 0, "recipient" => $to]);
        exit();
    }

    // Build Subject & HTML Body
    $subject = "Gottesdienst Feedback Bericht - Pulsschlag Deggendorf";

    $htmlBody = '
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f5; color: #18181b; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 24px; border: 1px solid #e4e4e7; }
        .header { border-bottom: 3px solid #fbb900; padding-bottom: 12px; margin-bottom: 20px; }
        .header h2 { margin: 0; color: #18181b; font-size: 20px; }
        .header p { margin: 4px 0 0; color: #71717a; font-size: 13px; }
        .card { background: #fafafa; border: 1px solid #e4e4e7; border-left: 4px solid #fbb900; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
        .card-title { font-weight: bold; color: #18181b; font-size: 14px; margin-bottom: 6px; }
        .badge { background: #fef3c7; color: #92400e; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; }
        .positive { background: #f0fdf4; border-left: 3px solid #22c55e; padding: 8px 12px; border-radius: 6px; margin-top: 6px; font-size: 13px; color: #15803d; }
        .improvement { background: #fffbeb; border-left: 3px solid #fbb900; padding: 8px 12px; border-radius: 6px; margin-top: 6px; font-size: 13px; color: #b45309; }
        .footer { font-size: 12px; color: #a1a1aa; text-align: center; margin-top: 24px; border-top: 1px solid #e4e4e7; padding-top: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h2>Pulsschlag Deggendorf Portal</h2>
          <p>Zusammengefasster Gottesdienst Feedback-Bericht</p>
        </div>
        <p style="font-size: 14px;">Hallo Team,</p>
        <p style="font-size: 14px;">hier sind die aktuellen Rückmeldungen aus der Gottesdienst-Feedback Datenbank:</p>
    ';

    foreach ($items as $item) {
        $stars = str_repeat("★", (int)$item['rating']) . str_repeat("☆", 5 - (int)$item['rating']);
        $htmlBody .= '<div class="card">';
        $htmlBody .= '<div class="card-title">';
        $htmlBody .= htmlspecialchars($item['category']) . ' <span class="badge">' . htmlspecialchars($item['service_date']) . '</span>';
        if (!empty($item['author_name'])) {
            $htmlBody .= ' <span style="font-weight:normal; color:#4b5563;">(' . htmlspecialchars($item['author_name']) . ')</span>';
        }
        $htmlBody .= '<span style="float: right; color: #fbb900;">' . $stars . '</span>';
        $htmlBody .= '</div>';

        if (!empty($item['positive_text'])) {
            $htmlBody .= '<div class="positive"><strong>Positiv:</strong> ' . htmlspecialchars($item['positive_text']) . '</div>';
        }
        if (!empty($item['improvement_text'])) {
            $htmlBody .= '<div class="improvement"><strong>Verbesserung:</strong> ' . htmlspecialchars($item['improvement_text']) . '</div>';
        }
        $htmlBody .= '</div>';
    }

    $htmlBody .= '
        <div class="footer">
          <p>Pulsschlag Deggendorf • <a href="https://tools.pulsschlag.church" style="color: #fbb900;">tools.pulsschlag.church</a></p>
        </div>
      </div>
    </body>
    </html>
    ';

    // Set clean domain sender headers
    $fromAddress = "feedback@pulsschlag.church";
    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: Pulsschlag Portal <" . $fromAddress . ">\r\n";
    $headers .= "Reply-To: " . $fromAddress . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    // Send email with envelope sender (-f)
    $mailSuccess = mail($to, $subject, $htmlBody, $headers, "-f " . $fromAddress);

    echo json_encode([
        "success" => $mailSuccess,
        "message" => $mailSuccess ? "Bericht erfolgreich gesendet an " . $to : "Mail-Server Fehler beim Senden.",
        "recipient" => $to,
        "count" => count($items)
    ]);
    exit();

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => $e->getMessage()]);
    exit();
}
