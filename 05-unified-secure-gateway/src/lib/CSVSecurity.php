<?php
/**
 * 🔐 CSV Security Core Application
 * Refactored to use functions instead of classes
 */

declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../config.php';

/** CSRF Management */
function csv_csrf_token(): string {
    return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
}

function csv_validate_csrf(string $token): bool {
    return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
}

/** Rate Limiting (IP + Session Dimension) */
function csv_check_rate_limit(string $ip): bool {
    $db = getDB();
    $sessionId = session_id();
    
    // Check IP limit
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    $stmt->execute([$ip]);
    if ((int)$stmt->fetchColumn() >= CSV_RATE_LIMIT_PER_MINUTE) return true;

    // Check Session limit (if session exists)
    if ($sessionId) {
        $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute([$sessionId]);
        if ((int)$stmt->fetchColumn() >= CSV_RATE_LIMIT_PER_MINUTE) return true;
    }
    
    $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'upload')")->execute([$ip]);
    if ($sessionId) {
        $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'session', 'upload')")->execute([$sessionId]);
    }
    return false;
}

/** File Validation (Content-First) */
function csv_validate_file(array $file): array {
    if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload error: " . $file['error']];
    if ($file['size'] > CSV_MAX_FILE_SIZE) return ["File too large"];
    
    // 1. MIME Validation (Trust content, not extension)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);
    if (!in_array($mime, CSV_ALLOWED_MIME_TYPES)) {
        return ["Security Violation: Disallowed file type ($mime)"];
    }

    // 2. Full Content Signature Scan (Catch polyglots beyond 8KB)
    $content = file_get_contents($file['tmp_name']);
    foreach (CSV_BINARY_SIGNATURES as $sig => $name) {
        if (strpos($content, $sig) !== false) {
            return ["Security Violation: $name detected in file content"];
        }
    }
    return [];
}

/** Formula Validation (Rejection) */
function csv_validate_formulas(array $row): ?string {
    foreach ($row as $cell) {
        if (is_string($cell) && !empty($cell) && in_array($cell[0], CSV_FORMULA_TRIGGERS, true)) {
            return "Formula Injection Detected: Cell starts with '" . $cell[0] . "'";
        }
    }
    return null;
}

/** Encoding Validation + Normalization (Layer 5) */
function csv_validate_and_normalize(string $input): ?string {
    if (!mb_check_encoding($input, 'UTF-8')) return null;
    if (mb_convert_encoding($input, 'UTF-8', 'UTF-8') !== $input) return null;
    if (preg_match('/\+[A-Za-z0-9+\/]+-/', $input)) return null;

    // Secure Normalization (NFC) - requires 'intl' extension
    if (class_exists('Normalizer')) {
        $normalized = Normalizer::normalize($input, Normalizer::FORM_C);
        return $normalized !== false ? $normalized : $input;
    }
    return $input;
}

/** Business Logic Validation (Layer 7) */
function csv_validate_business_logic(array $row): array {
    $errors = [];
    
    // Example: Salary cannot be negative
    if (isset($row['salary']) && is_numeric($row['salary'])) {
        if ((float)$row['salary'] < 0) $errors[] = "Negative salary detected";
    }

    // Example: Email format
    if (isset($row['email']) && !filter_var($row['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format";
    }

    return $errors;
}

/** Returns list of implemented security features */
function csv_get_features(): array {
    return [
        ['name' => 'CSRF Protection', 'icon' => '🛡️', 'desc' => 'Cryptographic tokens for every state-changing request.'],
        ['name' => 'Rate Limiting', 'icon' => '⏳', 'desc' => 'Prevents DoS/Brute-force by limiting requests per IP.'],
        ['name' => 'Deep Inspection', 'icon' => '🔍', 'desc' => 'Scans file headers for binary signatures (ELF, EXE, PHP).'],
        ['name' => 'Formula Guard', 'icon' => '🧪', 'desc' => 'Identifies and rejects spreadsheet formula injection attempts.'],
        ['name' => 'Encoding Shield', 'icon' => '🔣', 'desc' => 'Detects UTF-7/Overlong encoding bypass attempts.'],
        ['name' => 'Business Logic', 'icon' => '⚖️', 'desc' => 'Validates data integrity (e.g. negative salaries, email formats).'],
        ['name' => 'Atomic Commits', 'icon' => '⚛️', 'desc' => 'Uses database transactions for all-or-nothing imports.'],
        ['name' => 'Isolated Quarantine', 'icon' => '☣️', 'desc' => 'Processes uploads outside the public web root.'],
        ['name' => 'Forensic Audit', 'icon' => '📔', 'desc' => 'Detailed trail of every action for accountability.'],
        ['name' => 'Hardened Headers', 'icon' => '🧱', 'desc' => 'CSP, HSTS, and Frame-Options to block XSS and Clickjacking.'],
    ];
}

/** 📔 Forensic Audit Logging Functions */
function csv_audit_start(string $batchId, string $filename, int $size): void {
    getDB()->prepare("INSERT INTO upload_audit (batch_id, ip_address, user_agent, filename, file_hash, file_size, status) VALUES (?, ?, ?, ?, ?, ?, 'processing')")
           ->execute([$batchId, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], $filename, 'pending', $size]);
}

function csv_audit_end(string $batchId, string $status, array $res): void {
    getDB()->prepare("UPDATE upload_audit SET status = ?, row_count = ?, neutralized_cells = ?, validation_errors = ?, completed_at = CURRENT_TIMESTAMP WHERE batch_id = ?")
           ->execute([$status, $res['rows'] ?? 0, $res['neutralized'] ?? 0, json_encode($res['errors'] ?? []), $batchId]);
}

/** Secure CSV Parser Function */
function csv_processor_run(string $path, string $batchId): array {
    $db = getDB();
    $handle = fopen($path, 'r');
    $headers = fgetcsv($handle, CSV_MAX_LINE_LENGTH);
    $results = ['rows' => 0, 'neutralized' => 0, 'errors' => []];

    try {
        $db->beginTransaction();
        while (($row = fgetcsv($handle, CSV_MAX_LINE_LENGTH)) !== false) {
            if (++$results['rows'] > CSV_MAX_ROWS) break;
            if (count($row) !== count($headers)) {
                $results['errors'][] = "Row {$results['rows']} structural mismatch";
                continue;
            }
            
            $data = array_combine($headers, $row);

            // Encoding Check & Normalization
            foreach ($data as $key => $cell) {
                $normalizedCell = csv_validate_and_normalize($cell);
                if ($normalizedCell === null) {
                    if (count($results['errors']) < CSV_MAX_ERROR_COUNT) {
                        $results['errors'][] = "Row {$results['rows']}: Invalid Encoding/UTF-7 detected";
                    }
                    continue 2;
                }
                $data[$key] = $normalizedCell;
            }

            // Formula Check (Strict Block)
            $formulaError = csv_validate_formulas($data);
            if ($formulaError) {
                if (count($results['errors']) < CSV_MAX_ERROR_COUNT) {
                    $results['errors'][] = "Row {$results['rows']}: {$formulaError}";
                }
                continue;
            }

            // Business Logic Check
            $logicErrors = csv_validate_business_logic($data);
            if (!empty($logicErrors)) {
                if (count($results['errors']) < CSV_MAX_ERROR_COUNT) {
                    $results['errors'][] = "Row {$results['rows']}: " . implode(", ", $logicErrors);
                }
                continue;
            }
            
            // Insert into staging
            $db->prepare("INSERT INTO csv_staging (batch_id, `row_number`, original_data, sanitized_data, validation_status) VALUES (?, ?, ?, ?, 'valid')")
               ->execute([$batchId, $results['rows'], json_encode($data), json_encode($data)]);
        }
        
        // Fail Closed: Only commit if NO errors occurred across the entire file
        if (empty($results['errors'])) {
            $db->prepare("INSERT INTO csv_imports (batch_id, `row_number`, original_data, sanitized_data) SELECT batch_id, `row_number`, original_data, sanitized_data FROM csv_staging WHERE batch_id = ?")->execute([$batchId]);
            $db->prepare("DELETE FROM csv_staging WHERE batch_id = ?")->execute([$batchId]);
            $db->commit();
        } else {
            $db->rollBack();
            $db->prepare("DELETE FROM csv_staging WHERE batch_id = ?")->execute([$batchId]);
        }
    } catch (Exception $e) {
        if ($db->inTransaction()) $db->rollBack();
        $results['errors'][] = "System Error: " . $e->getMessage();
    }
    
    fclose($handle);
    return $results;
}

/** Gateway Integration Wrapper */
function csv_process(array $file, string $targetPath): array {
    $findings = csv_validate_file($file);
    if (!empty($findings)) {
        return ['status' => 'rejected', 'error' => $findings[0]];
    }

    $batchId = bin2hex(random_bytes(8));
    
    // Original Logging
    csv_audit_start($batchId, $file['name'], $file['size']);

    $res = csv_processor_run($file['tmp_name'], $batchId);

    if (!empty($res['errors'])) {
        csv_audit_end($batchId, 'rejected', $res);
        return ['status' => 'rejected', 'error' => $res['errors'][0]];
    }

    // Move to final path
    move_uploaded_file($file['tmp_name'], $targetPath);
    
    csv_audit_end($batchId, 'sanitized', $res);

    return [
        'status' => 'sanitized',
        'path' => $targetPath,
        'details' => "Processed " . $res['rows'] . " rows successfully."
    ];
}
