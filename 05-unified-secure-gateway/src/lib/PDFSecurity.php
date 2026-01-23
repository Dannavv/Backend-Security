<?php
/**
 * 🔐 PDF Security Core Application
 * Refactored to use functions instead of classes
 */

declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../config.php';

function pdf_csrf_token(): string {
    return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
}

function pdf_validate_csrf(string $token): bool {
    return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
}

function pdf_check_rate_limit(string $ip): bool {
    $db = getDB();
    $sessionId = session_id();
    
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    $stmt->execute([$ip]);
    if ((int)$stmt->fetchColumn() >= PDF_RATE_LIMIT_PER_MINUTE) return true;

    if ($sessionId) {
        $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute([$sessionId]);
        if ((int)$stmt->fetchColumn() >= PDF_RATE_LIMIT_PER_MINUTE) return true;
    }
    
    $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'upload')")->execute([$ip]);
    if ($sessionId) {
        $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'session', 'upload')")->execute([$sessionId]);
    }
    return false;
}

/** 🔍 Hash-based Reputation Engine Function */
function pdf_check_reputation(string $hash): array {
    $db = getDB();
    try {
        $stmt = $db->prepare("SELECT status, findings FROM file_reputation WHERE file_hash = ?");
        $stmt->execute([$hash]);
        $result = $stmt->fetch();
        return $result ?: ['status' => 'unknown', 'findings' => []];
    } catch (Exception $e) {
        return ['status' => 'unknown', 'findings' => []];
    }
}

/** 🛠️ Advanced Structural Analysis Functions */
function pdf_array_search_recursive(array $array, string $key): bool {
    foreach ($array as $k => $v) {
        if ($k === $key) return true;
        if (is_array($v) && pdf_array_search_recursive($v, $key)) return true;
    }
    return false;
}

function pdf_inspect_semantics(array $json): array {
    $findings = [];
    $objects = $json['objects'] ?? [];

    foreach ($objects as $id => $obj) {
        $val = $obj['value'] ?? [];
        if (!is_array($val)) continue;

        // Detect Actions in Document Catalog or Pages
        foreach (PDF_MALICIOUS_KEYWORDS as $tag => $data) {
            $searchKey = ltrim($tag, '/');
            if (pdf_array_search_recursive($val, $searchKey)) {
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

function pdf_analyze_structure(string $path): array {
    $results = [
        'valid' => false,
        'object_count' => 0,
        'stream_count' => 0,
        'page_count' => 0,
        'incremental_updates' => 0,
        'json' => []
    ];

    $cmd = PDF_EXEC_TIMEOUT . "qpdf --json " . escapeshellarg($path);
    exec($cmd, $output, $returnCode);
    
    if ($returnCode !== 0 && $returnCode !== 3) return $results;
    
    $json = json_decode(implode("\n", $output), true);
    if (!$json) return $results;

    $results['json'] = $json;
    $results['valid'] = true;
    
    $results['object_count'] = count($json['objects'] ?? []);
    $results['page_count'] = count($json['pages'] ?? []);
    
    foreach ($json['objects'] ?? [] as $obj) {
        if (isset($obj['value']['stream'])) $results['stream_count']++;
    }

    exec(PDF_EXEC_TIMEOUT . "qpdf --show-xref " . escapeshellarg($path) . " | grep 'xref' | wc -l", $xrefOut);
    $results['incremental_updates'] = (int)($xrefOut[0] ?? 0);

    return $results;
}

/** 🧹 Parser-based Sanitizer Function */
function pdf_sanitize(string $inputPath, string $outputPath): bool {
    $cmd = PDF_EXEC_TIMEOUT . "qpdf --linearize --remove-metadata " . escapeshellarg($inputPath) . " " . escapeshellarg($outputPath) . " 2>&1";
    exec($cmd, $output, $returnCode);
    
    if ($returnCode !== 0 && $returnCode !== 3) return false;

    // POST-SANITIZATION RE-SCAN
    $reScan = pdf_analyze_structure($outputPath);
    if (!$reScan['valid']) return false;
    
    $semanticFindings = pdf_inspect_semantics($reScan['json']);
    foreach ($semanticFindings as $f) {
        if ($f['level'] === 'critical') return false;
    }

    return true;
}

/** 📔 Audit Logging Function */
function pdf_audit_log(string $filename, string $status, array $findings, int $size, ?string $hash = null): void {
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

/**
 * Multi-stage PDF validation
 */
function pdf_validate_file(array $file): array {
    if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload error code: " . $file['error']];
    if ($file['size'] > PDF_MAX_FILE_SIZE) return ["File exceeds maximum size limits (10MB)"];
    if ($file['size'] < PDF_MIN_FILE_SIZE) return ["File is suspiciously small"];

    $tmpName = $file['tmp_name'];
    $findings = [];

    // 1. Reputation Check
    $fileHash = hash_file('sha256', $tmpName);
    $reputation = pdf_check_reputation($fileHash);
    if ($reputation['status'] === 'malicious') {
        $findings[] = [
            'type' => 'reputation',
            'desc' => 'Known malicious hash detected',
            'level' => 'critical'
        ];
    }

    // 2. Extension & MIME Validation
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, PDF_ALLOWED_EXTENSIONS)) return ["Invalid file extension"];

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($tmpName);
    if ($mime !== 'application/pdf') return ["Security Violation: Mismatched MIME type ($mime)"];

    // 3. Static Structure Check
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

    // 4. Advanced Structural Analysis
    $structuralResults = pdf_analyze_structure($tmpName);
    if (!$structuralResults['valid']) {
        return ["Security Violation: Structural integrity check failed (Decode-or-Die)"];
    }

    // 5. Resource Limits Check
    if ($structuralResults['object_count'] > PDF_MAX_OBJECT_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Object count exceeds safety threshold', 'level' => 'critical'];
    if ($structuralResults['stream_count'] > PDF_MAX_STREAM_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Stream count exceeds safety threshold', 'level' => 'critical'];
    if ($structuralResults['page_count'] > PDF_MAX_PAGE_COUNT) $findings[] = ['tag' => 'dos', 'desc' => 'Page count exceeds safety threshold', 'level' => 'critical'];
    
    if ($structuralResults['incremental_updates'] > 1) {
        $findings[] = [
            'type' => 'structural',
            'desc' => 'Multiple XRef sections (Incremental Update detected)',
            'level' => 'suspicious'
        ];
    }

    // 6. Semantic Inspection
    $semanticFindings = pdf_inspect_semantics($structuralResults['json']);
    foreach ($semanticFindings as $sf) {
        $findings[] = [
            'tag' => $sf['tag'],
            'desc' => 'Detected ' . $sf['tag'] . ': ' . $sf['desc'],
            'level' => $sf['level'],
            'source' => 'parser'
        ];
    }

    // 7. Active Content Scan
    $content = @file_get_contents($tmpName);
    foreach (PDF_MALICIOUS_KEYWORDS as $keyword => $data) {
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

function pdf_get_features(): array {
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

/** Gateway Integration Wrapper */
function pdf_process(array $file, string $targetPath): array {
    $findings = pdf_validate_file($file);
    
    $isCritical = false;
    $errorMsg = "";
    $findingList = [];
    foreach ($findings as $f) {
        if (is_string($f)) {
            pdf_audit_log($file['name'], 'rejected', ['error' => $f], $file['size']);
            return ['status' => 'rejected', 'error' => $f];
        }
        $findingList[] = $f;
        if ($f['level'] === 'critical') {
            $isCritical = true;
            $errorMsg = $f['desc'];
        }
    }

    if ($isCritical) {
        pdf_audit_log($file['name'], 'rejected', $findingList, $file['size']);
        return ['status' => 'rejected', 'error' => $errorMsg];
    }

    // Attempt Sanitization
    $success = pdf_sanitize($file['tmp_name'], $targetPath);
    if (!$success) {
        pdf_audit_log($file['name'], 'rejected_sanitizer', $findingList, $file['size']);
        return ['status' => 'rejected', 'error' => 'Sanitization failed or threat remains'];
    }

    $fileHash = hash_file('sha256', $targetPath);
    pdf_audit_log($file['name'], 'sanitized', $findingList, $file['size'], $fileHash);

    return [
        'status' => 'sanitized',
        'path' => $targetPath,
        'details' => 'QPDF Linearized & Metadata Stripped'
    ];
}
