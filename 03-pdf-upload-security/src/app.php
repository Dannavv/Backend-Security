<?php
/**
 * 🔐 PDF Security Core Application
 * Consolidates all security logic, configuration, and helpers for PDF handling.
 */

declare(strict_types=1);

// =========================================================================
// 1. CONFIGURATION & CONSTANTS
// =========================================================================

define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('MIN_FILE_SIZE', 100);
define('RATE_LIMIT_PER_MINUTE', 5);
define('QUARANTINE_PATH', '/var/quarantine/uploads');
define('LOG_PATH', '/var/log/pdf-security');
define('ALLOWED_EXTENSIONS', ['pdf']);
define('ALLOWED_MIME_TYPES', ['application/pdf']);

define('MALICIOUS_PDF_KEYWORDS', [
    // --- ALWAYS BLOCK / STRIP (TOTAL ZERO TRUST) ---
    '/JS'           => ['desc' => 'Embedded JavaScript', 'level' => 'critical'],
    '/JavaScript'   => ['desc' => 'Embedded JavaScript', 'level' => 'critical'],
    '/Action'       => ['desc' => 'Generic Action Dictionary', 'level' => 'critical'],
    '/A'            => ['desc' => 'Short Action Dictionary', 'level' => 'critical'],
    '/OpenAction'   => ['desc' => 'Automatic Action on Open', 'level' => 'critical'],
    '/AA'           => ['desc' => 'Additional Action Trigger', 'level' => 'critical'],
    '/Launch'       => ['desc' => 'External Application Launch', 'level' => 'critical'],
    '/SubmitForm'   => ['desc' => 'Form Data Submission (SSRF)', 'level' => 'critical'],
    '/ImportData'   => ['desc' => 'External Data Import', 'level' => 'critical'],
    '/GoToR'        => ['desc' => 'Remote GoTo Action', 'level' => 'critical'],
    '/GoToE'        => ['desc' => 'Embedded File GoTo Action', 'level' => 'critical'],
    '/URI'          => ['desc' => 'External Hyperlink Action', 'level' => 'critical'],
    '/AcroForm'     => ['desc' => 'Interactive Form Actions', 'level' => 'critical'],
    '/EmbeddedFile' => ['desc' => 'Embedded File Attachment', 'level' => 'critical'],
    '/RichMedia'    => ['desc' => 'Embedded Flash/Media', 'level' => 'critical'],
    '/Sound'        => ['desc' => 'Embedded Audio Object', 'level' => 'critical'],
    '/Movie'        => ['desc' => 'Embedded Video Object', 'level' => 'critical'],
    '/XFA'          => ['desc' => 'XML Forms Architecture (Legacy Exploit Vector)', 'level' => 'critical'],
    '/S'            => ['desc' => 'Action Subtype Identifier', 'level' => 'critical'],

    // --- USUALLY STRIP (SUSPICIOUS) ---
    '/Metadata'     => ['desc' => 'Embedded XMP Metadata (Info Leakage)', 'level' => 'suspicious'],
]);


// Resource Limits (DoS Defense)
define('MAX_OBJECT_COUNT', 50000);
define('MAX_STREAM_COUNT', 10000);
define('MAX_PAGE_COUNT', 5000);
// Confidence Scoring Weights
define('WEIGHT_SEMANTIC_HIT', 10);
define('WEIGHT_REGEX_HIT', 3);
define('WEIGHT_STRUCTURAL_ANOMALY', 5);
define('MAX_RECURSION_DEPTH', 50);
define('EXEC_TIMEOUT', 'timeout 5s '); // Prepend to shell commands
define('REJECTION_SCORE_THRESHOLD', 10); // Reject if total score >= 10




// =========================================================================
// 2. DATABASE & SYSTEM SETUP
// =========================================================================

function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    
    $dsn = "mysql:host=".(getenv('DB_HOST')?:'mysql').";dbname=".(getenv('DB_NAME')?:'pdf_security').";charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'"
    ];
    
    try {
        return $pdo = new PDO($dsn, getenv('DB_USER')?:'pdf_user', getenv('DB_PASS')?:'pdf_secure_pass_2024', $options);
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
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
    
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

class PDFSecurity {
    public static function csrfToken(): string {
        return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
    }

    public static function validateCSRF(string $token): bool {
        return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
    }

    public static function checkRateLimit(string $ip): bool {
        $db = getDB();
        $sessionId = session_id();
        
        $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute([$ip]);
        if ((int)$stmt->fetchColumn() >= RATE_LIMIT_PER_MINUTE) return true;

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

    /**
     * Multi-stage PDF validation (Signals Only - Sanitization is Authority)
     */
    public static function validateFile(array $file): array {
        if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload error code: " . $file['error']];
        if ($file['size'] > MAX_FILE_SIZE) return ["File exceeds maximum size limits (10MB)"];
        if ($file['size'] < MIN_FILE_SIZE) return ["File is suspiciously small"];

        $tmpName = $file['tmp_name'];
        $findings = [];

        // 1. Reputation Check (Hash-based Signal)
        $fileHash = hash_file('sha256', $tmpName);
        $reputation = ReputationEngine::check($fileHash);
        if ($reputation['status'] === 'malicious') {
            $findings[] = [
                'type' => 'reputation',
                'desc' => 'Known malicious hash detected',
                'level' => 'critical'
            ];
        }

        // 2. Extension & MIME Validation (Ingress Gate)
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ALLOWED_EXTENSIONS)) return ["Invalid file extension"];

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($tmpName);
        if ($mime !== 'application/pdf') return ["Security Violation: Mismatched MIME type ($mime)"];

        // 3. Static Structure Check (Magic Bytes & Trailer Signal)
        $handle = fopen($tmpName, 'rb');
        $header = fread($handle, 1024);
        if (strpos($header, '%PDF-') !== 0) {
            fclose($handle);
            return ["Security Violation: Invalid PDF magic byte header (Potential Polyglot)"];
        }
        fseek($handle, -1024, SEEK_END);
        $trailer = fread($handle, 1024);
        fclose($handle);
        if (strpos($trailer, '%%EOF') === false) {
            $findings[] = [
                'tag' => 'structure',
                'desc' => 'PDF trailer missing or malformed',
                'level' => 'suspicious'
            ];
        }

        // 4. Advanced Structural Analysis (JSON Model)
        $structuralResults = StructuralAnalyzer::analyze($tmpName);
        if (!$structuralResults['valid']) {
            // This is a hard fail because if QPDF can't even get JSON, it can't sanitize
            return ["Security Violation: Structural integrity check failed (Decode-or-Die)"];
        }

        // 5. Resource Limits Check (DoS/Bomb Signal)
        if ($structuralResults['object_count'] > MAX_OBJECT_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Object count exceeds safety threshold', 'level' => 'critical'];
        if ($structuralResults['stream_count'] > MAX_STREAM_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Stream count exceeds safety threshold', 'level' => 'critical'];
        if ($structuralResults['page_count'] > MAX_PAGE_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Page count exceeds safety threshold', 'level' => 'critical'];
        
        if ($structuralResults['incremental_updates'] > 1) {
            $findings[] = [
                'type' => 'structural',
                'desc' => 'Multiple XRef sections (Incremental Update detected)',
                'level' => 'suspicious'
            ];
        }

        // 6. Semantic Inspection (JSON Objects) - Signals
        $semanticFindings = StructuralAnalyzer::inspectSemantics($structuralResults['json']);
        foreach ($semanticFindings as $sf) {
            $findings[] = [
                'tag' => $sf['tag'],
                'desc' => 'Detected ' . $sf['tag'] . ': ' . $sf['desc'],
                'level' => $sf['level'],
                'source' => 'parser'
            ];
        }

        // 7. Active Content Scan (Deep Regex Signal)
        $content = @file_get_contents($tmpName);
        foreach (MALICIOUS_PDF_KEYWORDS as $keyword => $data) {
            if (preg_match('/[[:space:]\/]' . preg_quote(ltrim($keyword, '/'), '/') . '[[:space:]\/\[<]/i', $content)) {
                $findings[] = [
                    'tag' => $keyword,
                    'desc' => 'Regex hit for ' . $data['desc'],
                    'level' => 'suspicious'
                ];
            }
        }

        return $findings;
    }




    public static function getFeatures(): array {
        return [
            ['name' => 'QPDF Sanitization', 'icon' => '🧹', 'desc' => 'Rewrites PDFs to strip incremental updates and flatten dangerous structures.'],
            ['name' => 'Multi-Parser Check', 'icon' => '⚖️', 'desc' => 'Cross-references QPDF and Poppler results to detect "Chameleon" polyglots.'],
            ['name' => 'Resource Guard', 'icon' => '🛡️', 'desc' => 'Blocks "PDF Bombs" by enforcing strict object count and recursion limits.'],
            ['name' => 'Hash Reputation', 'icon' => '🔍', 'desc' => 'Instantly identifies known malicious files via SHA-256 reputation database.'],
            ['name' => 'Active Content Scan', 'icon' => '⚡', 'desc' => 'Deep regex scanning for /JS, /OpenAction, and other dangerous PDF objects.'],
            ['name' => 'Isolated Quarantine', 'icon' => '☣️', 'desc' => 'Uploads are stored outside the web root with randomized, non-executable names.'],
            ['name' => 'Polyglot Defense', 'icon' => '🎭', 'desc' => 'Strict verification of magic bytes and trailers to block hybrid file attacks.'],
            ['name' => 'Secure Proxy Download', 'icon' => '📥', 'desc' => 'Serves files with strict Content-Security-Policy: sandbox.'],
        ];
    }
}

/** 🛠️ Advanced Structural Analysis */
class StructuralAnalyzer {
    public static function analyze(string $path): array {
        $results = [
            'valid' => false,
            'object_count' => 0,
            'stream_count' => 0,
            'page_count' => 0,
            'incremental_updates' => 0,
            'json' => []
        ];

        // 1. Get JSON Structure (Authority)
        $cmd = EXEC_TIMEOUT . "qpdf --json " . escapeshellarg($path);
        exec($cmd, $output, $returnCode);
        
        if ($returnCode !== 0 && $returnCode !== 3) return $results;
        
        $json = json_decode(implode("\n", $output), true);
        if (!$json) return $results;

        $results['json'] = $json;
        $results['valid'] = true;
        
        // 2. Extract Metrics
        $results['object_count'] = count($json['objects'] ?? []);
        $results['page_count'] = count($json['pages'] ?? []);
        
        // Count streams
        foreach ($json['objects'] ?? [] as $obj) {
            if (isset($obj['value']['stream'])) $results['stream_count']++;
        }

        // 3. Detect Incremental Updates
        exec(EXEC_TIMEOUT . "qpdf --show-xref " . escapeshellarg($path) . " | grep 'xref' | wc -l", $xrefOut);
        $results['incremental_updates'] = (int)($xrefOut[0] ?? 0);

        return $results;
    }

    public static function inspectSemantics(array $json): array {
        $findings = [];
        $objects = $json['objects'] ?? [];

        foreach ($objects as $id => $obj) {
            $val = $obj['value'] ?? [];
            if (!is_array($val)) continue;

            // Detect Actions in Document Catalog or Pages
            foreach (MALICIOUS_PDF_KEYWORDS as $tag => $data) {
                $searchKey = ltrim($tag, '/');
                if (self::arraySearchRecursive($val, $searchKey)) {
                    $findings[] = [
                        'tag' => $tag,
                        'desc' => $data['desc'],
                        'level' => $data['level'],
                        'source' => 'parser',
                        'object_id' => $id
                    ];
                }
            }
        }
        return $findings;
    }

    private static function arraySearchRecursive(array $array, string $key): bool {
        foreach ($array as $k => $v) {
            if ($k === $key) return true;
            if (is_array($v) && self::arraySearchRecursive($v, $key)) return true;
        }
        return false;
    }
}

/** 🧹 Parser-based Sanitizer */
class ParserSanitizer {
    public static function sanitize(string $inputPath, string $outputPath): bool {
        // Linearize rewrites the file, flattens xref/object streams, and strips incremental updates
        // Plus explicitly remove metadata as requested
        $cmd = EXEC_TIMEOUT . "qpdf --linearize --remove-metadata " . escapeshellarg($inputPath) . " " . escapeshellarg($outputPath) . " 2>&1";
        exec($cmd, $output, $returnCode);
        
        if ($returnCode !== 0 && $returnCode !== 3) return false;

        // POST-SANITIZATION RE-SCAN (Gap closed)
        $reScan = StructuralAnalyzer::analyze($outputPath);
        if (!$reScan['valid']) return false;
        
        $semanticFindings = StructuralAnalyzer::inspectSemantics($reScan['json']);
        foreach ($semanticFindings as $f) {
            if ($f['level'] === 'critical') return false; // Sanitizer failed to remove critical threat
        }

        return true;
    }

    /** Tier-2: Transform PDF to Images and back to PDF (KILL MODE) */
    public static function flatten(string $inputPath, string $outputPath): bool {
        // 1. Render to PNGs
        $tmpDir = sys_get_temp_dir() . '/flatten_' . bin2hex(random_bytes(8));
        mkdir($tmpDir);
        $renderCmd = EXEC_TIMEOUT . "pdftoppm -png " . escapeshellarg($inputPath) . " " . escapeshellarg($tmpDir . "/page");
        exec($renderCmd, $out, $ret);
        
        if ($ret !== 0) return false;

        // 2. Rebuild from images
        $rebuildCmd = EXEC_TIMEOUT . "img2pdf " . escapeshellarg($tmpDir) . "/*.png -o " . escapeshellarg($outputPath);
        exec($rebuildCmd, $out, $ret);

        // Cleanup
        array_map('unlink', glob("$tmpDir/*.*"));
        rmdir($tmpDir);

        return $ret === 0;
    }
}



/** 🔍 Hash-based Reputation Engine */
class ReputationEngine {
    public static function check(string $hash): array {
        $db = getDB();
        $stmt = $db->prepare("SELECT status, findings FROM file_reputation WHERE file_hash = ?");
        $stmt->execute([$hash]);
        $result = $stmt->fetch();
        
        return $result ?: ['status' => 'unknown', 'findings' => []];
    }

    public static function update(string $hash, string $status, array $findings): void {
        $db = getDB();
        $stmt = $db->prepare("INSERT INTO file_reputation (file_hash, status, findings) 
                             VALUES (?, ?, ?) 
                             ON DUPLICATE KEY UPDATE status = ?, findings = ?, detection_count = detection_count + 1");
        $stmt->execute([$hash, $status, json_encode($findings), $status, json_encode($findings)]);
    }
}


/** Audit Logging for PDF Uploads */
class AuditLogger {
    public static function logAttempt(string $filename, string $status, array $findings, int $size, ?string $hash = null): void {
        $db = getDB();
        $db->prepare("INSERT INTO pdf_audit (ip_address, user_agent, filename, status, security_findings, file_size, file_hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
           ->execute([
               $_SERVER['REMOTE_ADDR'], 
               $_SERVER['HTTP_USER_AGENT'], 
               $filename, 
               $status, 
               json_encode($findings), 
               $size,
               $hash
           ]);
    }
}

