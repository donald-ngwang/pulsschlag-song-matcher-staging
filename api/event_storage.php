<?php
/**
 * Pulsschlag Deggendorf - Centralized Event Storage & Realtime Sync API
 * Robust authorization, bcrypt-hashed credentials, rate-limiting, and participant protection.
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Leader-Pin, X-Participant-Id");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$dbDir = getenv('EVENT_STORAGE_DIR') ?: (__DIR__ . '/data');
if (!file_exists($dbDir)) {
    @mkdir($dbDir, 0755, true);
}

// Dual Apache 2.2 / 2.4 denial in data directory
$dataHtaccess = $dbDir . '/.htaccess';
if (!file_exists($dataHtaccess)) {
    $denyContent = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
    @file_put_contents($dataHtaccess, $denyContent);
}

$jsonFile = $dbDir . '/events_store.json';
$deletedFile = $dbDir . '/deleted_events.json';
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
    $window = 900; // 15 minutes
    $maxAttempts = 5;

    $limits = [];
    if (file_exists($rateLimitFile)) {
        $raw = file_get_contents($rateLimitFile);
        $limits = json_decode($raw, true) ?: [];
    }

    $ipAttempts = isset($limits[$ip]) && is_array($limits[$ip]) ? $limits[$ip] : [];
    // Clean old attempts
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

    file_put_contents($rateLimitFile, json_encode($limits, JSON_PRETTY_PRINT), LOCK_EX);
    usleep(250000); // 250ms anti-bruteforce delay
}

function resetFailedAttempts(string $rateLimitFile, string $ip): void {
    if (file_exists($rateLimitFile)) {
        $raw = file_get_contents($rateLimitFile);
        $limits = json_decode($raw, true) ?: [];
        if (isset($limits[$ip])) {
            unset($limits[$ip]);
            file_put_contents($rateLimitFile, json_encode($limits, JSON_PRETTY_PRINT), LOCK_EX);
        }
    }
}

function getStoredPinHash(string $authFile): string {
    if (file_exists($authFile)) {
        $raw = file_get_contents($authFile);
        $data = json_decode($raw, true);
        if (is_array($data)) {
            // Already bcrypt hashed
            if (!empty($data['hash'])) {
                return (string)$data['hash'];
            }
            // Auto-upgrade legacy plaintext pin
            if (!empty($data['pin'])) {
                $hash = password_hash((string)$data['pin'], PASSWORD_DEFAULT);
                $data['hash'] = $hash;
                unset($data['pin']);
                $data['updated_at'] = date('c');
                file_put_contents($authFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
                return $hash;
            }
        }
    }

    // Default initialization with secure bcrypt hash
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

function getDeletedIds(string $deletedFile): array {
    if (file_exists($deletedFile)) {
        $raw = file_get_contents($deletedFile);
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            return $decoded;
        }
    }
    return [];
}

// ── GET: Fetch all server-synced events & deleted IDs ─────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = isset($_GET['action']) ? trim($_GET['action']) : '';

    // PIN verification endpoint with rate limiting
    if ($action === 'verify_pin') {
        $pin = extractRequestPin();
        $authResult = verifyLeaderPin($pin, $authFile, $rateLimitFile);
        http_response_code($authResult['status']);
        echo json_encode(["success" => $authResult['success'], "message" => $authResult['message']]);
        exit();
    }

function sanitizeEventsForPublic(array $events, string $callerId): array {
    foreach ($events as &$ev) {
        if (!is_array($ev)) continue;
        if (isset($ev['roles']) && is_array($ev['roles'])) {
            foreach ($ev['roles'] as &$r) {
                if (!is_array($r) || !isset($r['volunteers']) || !is_array($r['volunteers'])) continue;
                foreach ($r['volunteers'] as &$v) {
                    if (is_array($v)) {
                        $isMe = (!empty($callerId) && !empty($v['participantId']) && $v['participantId'] === $callerId);
                        $v['isOwner'] = $isMe;
                        if (!$isMe) {
                            unset($v['participantId']);
                        }
                    }
                }
            }
        }
        if (isset($ev['gearClaims']) && is_array($ev['gearClaims'])) {
            foreach ($ev['gearClaims'] as &$claimList) {
                if (!is_array($claimList)) continue;
                foreach ($claimList as &$c) {
                    if (is_array($c)) {
                        $isMe = (!empty($callerId) && !empty($c['participantId']) && $c['participantId'] === $callerId);
                        $c['isOwner'] = $isMe;
                        if (!$isMe) {
                            unset($c['participantId']);
                        }
                    }
                }
            }
        }
        if (isset($ev['carpools']) && is_array($ev['carpools'])) {
            if (isset($ev['carpools']['drivers']) && is_array($ev['carpools']['drivers'])) {
                foreach ($ev['carpools']['drivers'] as &$d) {
                    if (!is_array($d)) continue;
                    $isDriverOwner = (!empty($callerId) && !empty($d['participantId']) && $d['participantId'] === $callerId);
                    $d['isOwner'] = $isDriverOwner;
                    if (!$isDriverOwner) {
                        unset($d['participantId']);
                    }
                    if (isset($d['passengers']) && is_array($d['passengers'])) {
                        foreach ($d['passengers'] as &$p) {
                            if (is_array($p)) {
                                $isPassOwner = (!empty($callerId) && !empty($p['participantId']) && $p['participantId'] === $callerId);
                                $p['isOwner'] = $isPassOwner;
                                if (!$isPassOwner) {
                                    unset($p['participantId']);
                                }
                            }
                        }
                    }
                }
            }
            if (isset($ev['carpools']['seekers']) && is_array($ev['carpools']['seekers'])) {
                foreach ($ev['carpools']['seekers'] as &$s) {
                    if (!is_array($s)) continue;
                    $isSeekOwner = (!empty($callerId) && !empty($s['participantId']) && $s['participantId'] === $callerId);
                    $s['isOwner'] = $isSeekOwner;
                    if (!$isSeekOwner) {
                        unset($s['participantId']);
                    }
                }
            }
        }
    }
    return $events;
}

    $deletedIds = getDeletedIds($deletedFile);
    $callerPartId = !empty($_SERVER['HTTP_X_PARTICIPANT_ID']) ? trim($_SERVER['HTTP_X_PARTICIPANT_ID']) : '';

    if (file_exists($jsonFile)) {
        $raw = file_get_contents($jsonFile);
        $data = json_decode($raw, true);
        if (is_array($data)) {
            $filtered = array_values(array_filter($data, function($ev) use ($deletedIds) {
                return isset($ev['id']) && !in_array($ev['id'], $deletedIds);
            }));

            $sanitized = sanitizeEventsForPublic($filtered, $callerPartId);

            echo json_encode([
                "success" => true,
                "events" => $sanitized,
                "deletedIds" => $deletedIds
            ]);
            exit();
        }
    }

    echo json_encode([
        "success" => true,
        "events" => [],
        "deletedIds" => $deletedIds
    ]);
    exit();
}

// ── POST: Mutations (Organizers vs Participants) ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(["success" => false, "message" => "Ungültiges JSON-Format."]);
        exit();
    }

    $action = isset($input['action']) ? trim($input['action']) : '';
    $pin = isset($input['pin']) ? trim($input['pin']) : extractRequestPin();

    // Action: Verify PIN
    if ($action === 'verify_pin') {
        $authResult = verifyLeaderPin($pin, $authFile, $rateLimitFile);
        http_response_code($authResult['status']);
        echo json_encode(["success" => $authResult['success'], "message" => $authResult['message']]);
        exit();
    }

    // Action: Change PIN (Organizer Only: requires valid current PIN)
    if ($action === 'change_pin') {
        $currentPin = isset($input['current_pin']) ? trim($input['current_pin']) : '';
        $newPin = isset($input['new_pin']) ? trim($input['new_pin']) : '';

        $authResult = verifyLeaderPin($currentPin, $authFile, $rateLimitFile);
        if (!$authResult['success']) {
            http_response_code($authResult['status'] === 429 ? 429 : 403);
            echo json_encode(["success" => false, "message" => "Die aktuelle PIN ist nicht korrekt."]);
            exit();
        }

        if (strlen($newPin) < 4) {
            http_response_code(400);
            echo json_encode(["success" => false, "message" => "Die neue PIN muss mindestens 4 Zeichen lang sein."]);
            exit();
        }

        $newHash = password_hash($newPin, PASSWORD_DEFAULT);
        file_put_contents($authFile, json_encode([
            "hash" => $newHash,
            "updated_at" => date('c')
        ], JSON_PRETTY_PRINT), LOCK_EX);

        echo json_encode(["success" => true, "message" => "Leitungs-PIN erfolgreich aktualisiert."]);
        exit();
    }

    // Action: Delete Event (Organizer Only)
    if ($action === 'delete') {
        $authResult = verifyLeaderPin($pin, $authFile, $rateLimitFile);
        if (!$authResult['success']) {
            http_response_code(403);
            echo json_encode([
                "success" => false,
                "message" => "Berechtigung verweigert: Zum Löschen eines Events ist die Event-Leitungs-PIN erforderlich."
            ]);
            exit();
        }

        if (empty($input['id'])) {
            http_response_code(400);
            echo json_encode(["success" => false, "message" => "Fehlende Event-ID."]);
            exit();
        }

        deleteEventById($input['id'], $jsonFile, $deletedFile);
        exit();
    }

    // ── Save or Update Event ──────────────────────────────────────────────────
    if (!isset($input['id'])) {
        http_response_code(400);
        echo json_encode(["success" => false, "message" => "Fehlende Event-ID."]);
        exit();
    }

    $deletedIds = getDeletedIds($deletedFile);
    if (in_array($input['id'], $deletedIds)) {
        http_response_code(404);
        echo json_encode(["success" => false, "message" => "Dieses Event wurde gelöscht."]);
        exit();
    }

    $existingEvents = [];
    if (file_exists($jsonFile)) {
        $raw = file_get_contents($jsonFile);
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $existingEvents = $decoded;
        }
    }

    $foundIndex = -1;
    foreach ($existingEvents as $idx => $ev) {
        if (isset($ev['id']) && $ev['id'] === $input['id']) {
            $foundIndex = $idx;
            break;
        }
    }

    $authResult = verifyLeaderPin($pin, $authFile, $rateLimitFile);
    $isOrganizer = $authResult['success'];

    // CASE A: Creating a new master event
    if ($foundIndex < 0) {
        if (!$isOrganizer) {
            http_response_code(403);
            echo json_encode([
                "success" => false,
                "message" => "Berechtigung verweigert: Das Erstellen neuer Events erfordert die Leitungs-PIN."
            ]);
            exit();
        }

        array_unshift($existingEvents, $input);
    } 
    // CASE B: Updating an existing event
    else {
        $orig = $existingEvents[$foundIndex];

        if ($isOrganizer) {
            // Organizer has full authority over all fields
            $mergedEvent = array_merge($orig, $input);
            // CRITICAL: Preserve live gratitude wall photos if input omitted them or sent empty array
            if (!empty($orig['gratitudeWall']['photos'])) {
                if (empty($mergedEvent['gratitudeWall']['photos'])) {
                    $mergedEvent['gratitudeWall']['photos'] = $orig['gratitudeWall']['photos'];
                }
            }
            $existingEvents[$foundIndex] = $mergedEvent;
        } else {
            // Participant / Volunteer action: Strictly protect organizer-only fields
            $organizerFieldsChanged = false;

            // 1. Check details changes
            if (isset($input['details'])) {
                $origDetails = $orig['details'] ?? [];
                $newDetails = $input['details'];
                $protectedKeys = ['title', 'startDate', 'startTime', 'endDate', 'endTime', 'location', 'organizer', 'organizerEmail', 'extraInfo'];
                foreach ($protectedKeys as $k) {
                    if (isset($newDetails[$k]) && (!isset($origDetails[$k]) || (string)$newDetails[$k] !== (string)$origDetails[$k])) {
                        $organizerFieldsChanged = true;
                        break;
                    }
                }
            }

            // 2. Check templateId & enableCarpool changes
            if (isset($input['templateId']) && isset($orig['templateId']) && $input['templateId'] !== $orig['templateId']) {
                $organizerFieldsChanged = true;
            }
            if (isset($input['enableCarpool']) && isset($orig['enableCarpool']) && $input['enableCarpool'] !== $orig['enableCarpool']) {
                $organizerFieldsChanged = true;
            }

            // 3. Check roles schema changes (adding/removing/renaming ministry roles)
            if (isset($input['roles']) && is_array($input['roles'])) {
                $origRoles = $orig['roles'] ?? [];
                $origRoleIds = array_column($origRoles, 'id');
                $newRoleIds = array_column($input['roles'], 'id');
                if ($origRoleIds !== $newRoleIds) {
                    $organizerFieldsChanged = true;
                } else {
                    foreach ($input['roles'] as $ri => $newR) {
                        if (isset($origRoles[$ri]['name']) && $origRoles[$ri]['name'] !== $newR['name']) {
                            $organizerFieldsChanged = true;
                            break;
                        }
                    }
                }
            }

            if ($organizerFieldsChanged) {
                http_response_code(403);
                echo json_encode([
                    "success" => false,
                    "message" => "Berechtigung verweigert: Event-Stammdaten (Titel, Datum, Ort, Rollen-Definitionen) können nur mit gültiger Leitungs-PIN geändert werden."
                ]);
                exit();
            }

            // Extract participant identity for ownership verification
            $callerParticipantId = trim($_SERVER['HTTP_X_PARTICIPANT_ID'] ?? $input['participant_id'] ?? '');
            $callerParticipantName = trim($input['participant_name'] ?? '');

            // Safely merge allowed participant mutations while preserving organizer master structure
            $safeUpdated = $orig;

            // 1. Participant Ownership & Collision Protection for Volunteer Roles
            if (isset($input['roles']) && is_array($input['roles'])) {
                $safeRoles = $orig['roles'] ?? [];
                foreach ($input['roles'] as $inR) {
                    foreach ($safeRoles as &$sR) {
                        if ($sR['id'] === $inR['id'] && isset($inR['volunteers'])) {
                            $origVols = $sR['volunteers'] ?? [];
                            $inVols = is_array($inR['volunteers']) ? $inR['volunteers'] : [];
                            
                            $mergedVols = [];
                            $removedNames = [];
                            
                            // Check removals: participant can only remove their own registration
                            foreach ($origVols as $oV) {
                                $oName = is_array($oV) ? ($oV['name'] ?? '') : (string)$oV;
                                $oPartId = is_array($oV) ? ($oV['participantId'] ?? '') : '';
                                
                                $stillPresent = false;
                                foreach ($inVols as $iV) {
                                    $iName = is_array($iV) ? ($iV['name'] ?? '') : (string)$iV;
                                    if ($iName === $oName) {
                                        $stillPresent = true;
                                        break;
                                    }
                                }
                                
                                if ($stillPresent) {
                                    $mergedVols[] = $oV;
                                } else {
                                    $isOwner = false;
                                    if (!empty($oPartId) && !empty($callerParticipantId) && $oPartId === $callerParticipantId) {
                                        $isOwner = true;
                                    } else if (!empty($callerParticipantName) && $oName === $callerParticipantName) {
                                        $isOwner = true;
                                    }
                                    
                                    if ($isOwner) {
                                        $removedNames[] = $oName;
                                    } else {
                                        // Block unauthorized removal: preserve other participant's registration
                                        $mergedVols[] = $oV;
                                    }
                                }
                            }
                            
                            // Check additions: merge new signups with ownership tag
                            foreach ($inVols as $iV) {
                                $iName = trim(is_array($iV) ? ($iV['name'] ?? '') : (string)$iV);
                                if ($iName === '') continue;
                                
                                $alreadyPresent = false;
                                foreach ($mergedVols as $mV) {
                                    $mName = is_array($mV) ? ($mV['name'] ?? '') : (string)$mV;
                                    if ($mName === $iName) {
                                        $alreadyPresent = true;
                                        break;
                                    }
                                }
                                
                                if (!$alreadyPresent && !in_array($iName, $removedNames)) {
                                    if (is_array($iV)) {
                                        if (empty($iV['participantId']) && !empty($callerParticipantId)) {
                                            $iV['participantId'] = $callerParticipantId;
                                        }
                                        $mergedVols[] = $iV;
                                    } else {
                                        $mergedVols[] = [
                                            "name" => $iName,
                                            "participantId" => $callerParticipantId,
                                            "registeredAt" => date('c')
                                        ];
                                    }
                                }
                            }
                            
                            $sR['volunteers'] = array_values($mergedVols);
                        }
                    }
                }
                $safeUpdated['roles'] = $safeRoles;
            }

            // 2. Participant Ownership & Collision Protection for Gear Claims
            if (isset($input['gearClaims']) && is_array($input['gearClaims'])) {
                $origClaims = $orig['gearClaims'] ?? [];
                $newClaims = $input['gearClaims'];
                $mergedClaims = $origClaims;

                foreach ($newClaims as $gearKey => $inClaimList) {
                    $origList = isset($origClaims[$gearKey]) ? (array)$origClaims[$gearKey] : [];
                    $inList = is_array($inClaimList) ? $inClaimList : [];
                    
                    $mergedList = [];
                    $removedClaimants = [];
                    
                    foreach ($origList as $oC) {
                        $cName = is_array($oC) ? ($oC['name'] ?? '') : (string)$oC;
                        $cPartId = is_array($oC) ? ($oC['participantId'] ?? '') : '';
                        
                        $stillPresent = false;
                        foreach ($inList as $iC) {
                            $iName = is_array($iC) ? ($iC['name'] ?? '') : (string)$iC;
                            if ($iName === $cName) {
                                $stillPresent = true;
                                break;
                            }
                        }
                        
                        if ($stillPresent) {
                            $mergedList[] = $oC;
                        } else {
                            $isOwner = false;
                            if (!empty($cPartId) && !empty($callerParticipantId) && $cPartId === $callerParticipantId) {
                                $isOwner = true;
                            } else if (!empty($callerParticipantName) && $cName === $callerParticipantName) {
                                $isOwner = true;
                            }
                            
                            if ($isOwner) {
                                $removedClaimants[] = $cName;
                            } else {
                                $mergedList[] = $oC; // Preserve other person's claim
                            }
                        }
                    }
                    
                    foreach ($inList as $iC) {
                        $iName = trim(is_array($iC) ? ($iC['name'] ?? '') : (string)$iC);
                        if ($iName === '') continue;
                        
                        $already = false;
                        foreach ($mergedList as $mC) {
                            $mName = is_array($mC) ? ($mC['name'] ?? '') : (string)$mC;
                            if ($mName === $iName) {
                                $already = true;
                                break;
                            }
                        }
                        
                        if (!$already && !in_array($iName, $removedClaimants)) {
                            if (is_array($iC)) {
                                if (empty($iC['participantId']) && !empty($callerParticipantId)) {
                                    $iC['participantId'] = $callerParticipantId;
                                }
                                $mergedList[] = $iC;
                            } else {
                                $mergedList[] = [
                                    "name" => $iName,
                                    "participantId" => $callerParticipantId,
                                    "claimedAt" => date('c')
                                ];
                            }
                        }
                    }
                    
                    $mergedClaims[$gearKey] = array_values($mergedList);
                }
                $safeUpdated['gearClaims'] = $mergedClaims;
            }

            // 3. Collision Protection for Checklist Tasks
            if (isset($input['completedTasks']) && is_array($input['completedTasks'])) {
                $origTasks = $orig['completedTasks'] ?? [];
                $mergedCompleted = $origTasks;
                foreach ($input['completedTasks'] as $tId => $val) {
                    $mergedCompleted[$tId] = !empty($val);
                }
                $safeUpdated['completedTasks'] = $mergedCompleted;
            }

            // 4. Carpool Coordination with Ownership Protection
            if (isset($input['carpools']) && is_array($input['carpools'])) {
                $origCarpools = $orig['carpools'] ?? ['drivers' => [], 'seekers' => []];
                $inCarpools = $input['carpools'];
                $mergedCarpools = $origCarpools;

                // Merge driver offers
                if (isset($inCarpools['drivers']) && is_array($inCarpools['drivers'])) {
                    $origDrivers = $origCarpools['drivers'] ?? [];
                    $mergedDrivers = [];
                    $origDriverIds = array_column($origDrivers, 'id');

                    foreach ($origDrivers as $oD) {
                        $inD = null;
                        foreach ($inCarpools['drivers'] as $cand) {
                            if (isset($cand['id']) && $cand['id'] === $oD['id']) {
                                $inD = $cand;
                                break;
                            }
                        }

                        if ($inD !== null) {
                            $isDriverOwner = !empty($oD['participantId']) && $oD['participantId'] === $callerParticipantId;
                            if ($isDriverOwner) {
                                $mergedDrivers[] = array_merge($oD, $inD);
                            } else {
                                $safeD = $oD;
                                $origPass = $oD['passengers'] ?? [];
                                $inPass = $inD['passengers'] ?? [];
                                
                                $mergedPass = [];
                                foreach ($origPass as $p) {
                                    $pName = is_array($p) ? ($p['name'] ?? '') : (string)$p;
                                    $pId = is_array($p) ? ($p['participantId'] ?? '') : '';
                                    
                                    $inPassNames = array_map(function($x) { return is_array($x) ? ($x['name'] ?? '') : (string)$x; }, $inPass);
                                    if (in_array($pName, $inPassNames)) {
                                        $mergedPass[] = $p;
                                    } else {
                                        if (($pId && $pId === $callerParticipantId) || ($callerParticipantName && $pName === $callerParticipantName)) {
                                            // Passenger cancelled own seat
                                        } else {
                                            $mergedPass[] = $p; // Cannot cancel someone else's seat
                                        }
                                    }
                                }
                                
                                $mergedPassNames = array_map(function($x) { return is_array($x) ? ($x['name'] ?? '') : (string)$x; }, $mergedPass);
                                foreach ($inPass as $p) {
                                    $pName = trim(is_array($p) ? ($p['name'] ?? '') : (string)$p);
                                    if ($pName !== '' && !in_array($pName, $mergedPassNames)) {
                                        $mergedPass[] = is_array($p) ? $p : ["name" => $pName, "participantId" => $callerParticipantId];
                                    }
                                }
                                
                                $safeD['passengers'] = array_values($mergedPass);
                                $mergedDrivers[] = $safeD;
                            }
                        } else {
                            $isDriverOwner = !empty($oD['participantId']) && $oD['participantId'] === $callerParticipantId;
                            if ($isDriverOwner) {
                                // Owner deleted offer
                            } else {
                                $mergedDrivers[] = $oD; // Preserve offer
                            }
                        }
                    }

                    foreach ($inCarpools['drivers'] as $inD) {
                        if (isset($inD['id']) && !in_array($inD['id'], $origDriverIds)) {
                            if (empty($inD['participantId']) && !empty($callerParticipantId)) {
                                $inD['participantId'] = $callerParticipantId;
                            }
                            $mergedDrivers[] = $inD;
                        }
                    }
                    $mergedCarpools['drivers'] = array_values($mergedDrivers);
                }

                // Merge ride seekers
                if (isset($inCarpools['seekers']) && is_array($inCarpools['seekers'])) {
                    $origSeekers = $origCarpools['seekers'] ?? [];
                    $mergedSeekers = [];
                    $origSeekerIds = array_column($origSeekers, 'id');

                    foreach ($origSeekers as $oS) {
                        $inS = null;
                        foreach ($inCarpools['seekers'] as $cand) {
                            if (isset($cand['id']) && $cand['id'] === $oS['id']) {
                                $inS = $cand;
                                break;
                            }
                        }

                        if ($inS !== null) {
                            $isSeekerOwner = !empty($oS['participantId']) && $oS['participantId'] === $callerParticipantId;
                            if ($isSeekerOwner) {
                                $mergedSeekers[] = array_merge($oS, $inS);
                            } else {
                                $mergedSeekers[] = $oS;
                            }
                        } else {
                            $isSeekerOwner = !empty($oS['participantId']) && $oS['participantId'] === $callerParticipantId;
                            if ($isSeekerOwner) {
                                // Allowed deletion
                            } else {
                                $mergedSeekers[] = $oS; // Preserve
                            }
                        }
                    }

                    foreach ($inCarpools['seekers'] as $inS) {
                        if (isset($inS['id']) && !in_array($inS['id'], $origSeekerIds)) {
                            if (empty($inS['participantId']) && !empty($callerParticipantId)) {
                                $inS['participantId'] = $callerParticipantId;
                            }
                            $mergedSeekers[] = $inS;
                        }
                    }
                    $mergedCarpools['seekers'] = array_values($mergedSeekers);
                }

                $safeUpdated['carpools'] = $mergedCarpools;
            }

            // 5. Activity Log Audit Trail Preservation
            if (isset($input['activityLog']) && is_array($input['activityLog'])) {
                $origLogs = $orig['activityLog'] ?? [];
                $origLogIds = array_column($origLogs, 'id');
                $mergedLogs = $origLogs;
                foreach ($input['activityLog'] as $inLog) {
                    if (isset($inLog['id']) && !in_array($inLog['id'], $origLogIds)) {
                        array_unshift($mergedLogs, $inLog);
                    }
                }
                $safeUpdated['activityLog'] = array_slice($mergedLogs, 0, 100);
            }

            // 6. Custom Tasks Merging
            if (isset($input['customTasks']) && is_array($input['customTasks'])) {
                $origCustom = $orig['customTasks'] ?? [];
                $inCustom = $input['customTasks'];
                $mergedCustom = $origCustom;
                foreach ($inCustom as $phaseKey => $tasks) {
                    $origPTasks = $origCustom[$phaseKey] ?? [];
                    $origTaskIds = array_column($origPTasks, 'id');
                    $mergedP = $origPTasks;
                    foreach ((array)$tasks as $t) {
                        if (isset($t['id']) && !in_array($t['id'], $origTaskIds)) {
                            $mergedP[] = $t;
                        }
                    }
                    $mergedCustom[$phaseKey] = $mergedP;
                }
                $safeUpdated['customTasks'] = $mergedCustom;
            }

            // 7. Room Documentation & Photos Preservation
            if (isset($input['roomsDocumentation']) && is_array($input['roomsDocumentation'])) {
                $origRooms = $orig['roomsDocumentation'] ?? [];
                $inRooms = $input['roomsDocumentation'];
                if (empty($origRooms)) {
                    $safeUpdated['roomsDocumentation'] = $inRooms;
                } else {
                    $mergedRooms = [];
                    foreach ($origRooms as $rIdx => $origR) {
                        $inR = $inRooms[$rIdx] ?? null;
                        if ($inR) {
                            $mergedR = $origR;
                            $origTasks = $origR['tasks'] ?? [];
                            $inTasks = $inR['tasks'] ?? [];
                            foreach ($origTasks as &$oT) {
                                foreach ($inTasks as $iT) {
                                    if (isset($oT['id'], $iT['id']) && $oT['id'] === $iT['id']) {
                                        $oT['done'] = !empty($iT['done']);
                                    }
                                }
                            }
                            $mergedR['tasks'] = $origTasks;
                            
                            $origPhotos = $origR['photos'] ?? [];
                            $inPhotos = $inR['photos'] ?? [];
                            $origPhotoUrls = array_column($origPhotos, 'url');
                            $mergedPhotos = $origPhotos;
                            foreach ($inPhotos as $iP) {
                                if (isset($iP['url']) && !in_array($iP['url'], $origPhotoUrls)) {
                                    $mergedPhotos[] = $iP;
                                }
                            }
                            $mergedR['photos'] = $mergedPhotos;
                            $mergedRooms[] = $mergedR;
                        } else {
                            $mergedRooms[] = $origR;
                        }
                    }
                    $safeUpdated['roomsDocumentation'] = $mergedRooms;
                }
            }

            if (isset($orig['gratitudeWall'])) {
                $safeUpdated['gratitudeWall'] = $orig['gratitudeWall'];
            }
            $safeUpdated['updatedAt'] = time() * 1000;
            $existingEvents[$foundIndex] = $safeUpdated;
        }
    }

    // Filter out deleted
    $existingEvents = array_values(array_filter($existingEvents, function($ev) use ($deletedIds) {
        return isset($ev['id']) && !in_array($ev['id'], $deletedIds);
    }));

    $saved = file_put_contents($jsonFile, json_encode($existingEvents, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

    if ($saved !== false) {
        echo json_encode([
            "success" => true,
            "message" => "Event-Plan erfolgreich synchronisiert!",
            "events" => $existingEvents,
            "deletedIds" => $deletedIds
        ]);
    } else {
        http_response_code(500);
        echo json_encode(["success" => false, "message" => "Fehler beim Schreiben des Event-Speichers."]);
    }
    exit();
}

function deleteEventById(string $eventId, string $jsonFile, string $deletedFile): void {
    $deletedIds = getDeletedIds($deletedFile);
    if (!in_array($eventId, $deletedIds)) {
        $deletedIds[] = $eventId;
        file_put_contents($deletedFile, json_encode($deletedIds, JSON_PRETTY_PRINT), LOCK_EX);
    }

    $existingEvents = [];
    if (file_exists($jsonFile)) {
        $raw = file_get_contents($jsonFile);
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $existingEvents = $decoded;
        }
    }

    $filtered = array_values(array_filter($existingEvents, function($ev) use ($eventId) {
        return isset($ev['id']) && $ev['id'] !== $eventId;
    }));

    file_put_contents($jsonFile, json_encode($filtered, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

    echo json_encode([
        "success" => true,
        "message" => "Event erfolgreich gelöscht.",
        "deletedId" => $eventId,
        "events" => $filtered
    ]);
}
