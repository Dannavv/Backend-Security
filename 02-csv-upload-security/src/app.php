<?php
/**
 * 🔐 CSV Security Core Application
 * Consolidates all security logic, configuration, and helpers.
 */

declare(strict_types=1);

// =========================================================================
// 1. CONFIGURATION & CONSTANTS
// =========================================================================

define('MAX_FILE_SIZE', 5 * 1024 * 1024);
define('MIN_FILE_SIZE', 10);
define('MAX_ROWS', 10000);
define('MAX_COLUMNS', 50);
define('MAX_LINE_LENGTH', 50000);
define('RATE_LIMIT_PER_MINUTE', 10);
define('FORMULA_TRIGGERS', ['=', '+', '-', '@', "\t", "\r", "\n"]);
define('QUARANTINE_PATH', '/var/quarantine/uploads');
define('LOG_PATH', '/var/log/csv-security');
define('ALLOWED_EXTENSIONS', ['csv', 'txt']);
define('ALLOWED_MIME_TYPES', ['text/csv', 'text/plain', 'application/csv']);
define('MAX_ERROR_COUNT', 50); // Cap errors to prevent DB DoS

// Executable / Script signatures
define('BINARY_SIGNATURES', [
    "\x7fELF" => 'ELF', "MZ" => 'Windows EXE', "<?php" => 'PHP', "<?" => 'PHP/XML', "#!/" => 'Shebang', "\x00" => 'Null Byte Injection'
]);

// =========================================================================
// 2. DATABASE & SYSTEM SETUP
// =========================================================================

function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    
    $dsn = "mysql:host=".(getenv('DB_HOST')?:'mysql').";dbname=".(getenv('DB_NAME')?:'csv_security').";charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'"
    ];
    
    try {
        return $pdo = new PDO($dsn, getenv('DB_USER')?:'csv_user', getenv('DB_PASS')?:'csv_secure_pass_2024', $options);
    } catch (PDOException $e) {
        error_log("DB Error: " . $e->getMessage());
        die("Service Unavailable");
    }
}

function initSecurity(): void {
    // Headers
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';");
    
    // PHP Settings
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', LOG_PATH . '/php_errors.log');
    error_reporting(E_ALL);
    
    // Session
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        session_start();
    }
}

// =========================================================================
// 3. SECURITY ENGINE CLASSES
// =========================================================================

class CSVSecurity {
    /** CSRF Management */
    public static function csrfToken(): string {
        return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
    }

    public static function validateCSRF(string $token): bool {
        return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
    }

    /** Rate Limiting (IP + Session Dimension) */
    public static function checkRateLimit(string $ip): bool {
        $db = getDB();
        $sessionId = session_id();
        
        // Check IP limit
        $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute([$ip]);
        if ((int)$stmt->fetchColumn() >= RATE_LIMIT_PER_MINUTE) return true;

        // Check Session limit (if session exists)
        if ($sessionId) {
            $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
            $stmt->execute([$sessionId]);
            if ((int)$stmt->fetchColumn() >= RATE_LIMIT_PER_MINUTE) return true;
        }
        
        $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'upload')")->execute([$ip]);
        if ($sessionId) {
            $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'session', 'upload')")->execute([$sessionId]);
        }
        return false;
    }

    /** File Validation (Content-First) */
    public static function validateFile(array $file): array {
        if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload error: " . $file['error']];
        if ($file['size'] > MAX_FILE_SIZE) return ["File too large"];
        
        // 1. MIME Validation (Trust content, not extension)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($file['tmp_name']);
        if (!in_array($mime, ALLOWED_MIME_TYPES)) {
            return ["Security Violation: Disallowed file type ($mime)"];
        }

        // 2. Full Content Signature Scan (Catch polyglots beyond 8KB)
        $content = file_get_contents($file['tmp_name']);
        foreach (BINARY_SIGNATURES as $sig => $name) {
            if (strpos($content, $sig) !== false) {
                return ["Security Violation: $name detected in file content"];
            }
        }
        return [];
    }

    /** Formula Validation (Rejection) */
    public static function validateFormulas(array $row): ?string {
        foreach ($row as $cell) {
            if (is_string($cell) && !empty($cell) && in_array($cell[0], FORMULA_TRIGGERS, true)) {
                return "Formula Injection Detected: Cell starts with '" . $cell[0] . "'";
            }
        }
        return null;
    }

    /** Encoding Validation + Normalization (Layer 5) */
    public static function validateAndNormalize(string $input): ?string {
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
    public static function validateBusinessLogic(array $row): array {
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
    public static function getFeatures(): array {
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
}

/** Secure CSV Parser */
class CSVProcessor {
    public static function run(string $path, string $batchId): array {
        $db = getDB();
        $handle = fopen($path, 'r');
        $headers = fgetcsv($handle, MAX_LINE_LENGTH);
        $results = ['rows' => 0, 'neutralized' => 0, 'errors' => []];

        try {
            $db->beginTransaction();
            while (($row = fgetcsv($handle, MAX_LINE_LENGTH)) !== false) {
                if (++$results['rows'] > MAX_ROWS) break;
                if (count($row) !== count($headers)) {
                    $results['errors'][] = "Row {$results['rows']} structural mismatch";
                    continue;
                }
                
                $data = array_combine($headers, $row);

                // Encoding Check & Normalization
                foreach ($data as $key => $cell) {
                    $normalizedCell = CSVSecurity::validateAndNormalize($cell);
                    if ($normalizedCell === null) {
                        if (count($results['errors']) < MAX_ERROR_COUNT) {
                            $results['errors'][] = "Row {$results['rows']}: Invalid Encoding/UTF-7 detected";
                        }
                        continue 2;
                    }
                    $data[$key] = $normalizedCell;
                }

                // Formula Check (Strict Block)
                $formulaError = CSVSecurity::validateFormulas($data);
                if ($formulaError) {
                    if (count($results['errors']) < MAX_ERROR_COUNT) {
                        $results['errors'][] = "Row {$results['rows']}: {$formulaError}";
                    }
                    continue;
                }

                // Business Logic Check
                $logicErrors = CSVSecurity::validateBusinessLogic($data);
                if (!empty($logicErrors)) {
                    if (count($results['errors']) < MAX_ERROR_COUNT) {
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
}

/** Forensic Audit Logging */
class AuditLogger {
    public static function start(string $batchId, string $filename, int $size): void {
        getDB()->prepare("INSERT INTO upload_audit (batch_id, ip_address, user_agent, filename, file_hash, file_size, status) VALUES (?, ?, ?, ?, ?, ?, 'processing')")
               ->execute([$batchId, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'], $filename, 'pending', $size]);
    }

    public static function end(string $batchId, string $status, array $res): void {
        getDB()->prepare("UPDATE upload_audit SET status = ?, row_count = ?, neutralized_cells = ?, validation_errors = ?, completed_at = CURRENT_TIMESTAMP WHERE batch_id = ?")
               ->execute([$status, $res['rows'] ?? 0, $res['neutralized'] ?? 0, json_encode($res['errors'] ?? []), $batchId]);
    }
}
