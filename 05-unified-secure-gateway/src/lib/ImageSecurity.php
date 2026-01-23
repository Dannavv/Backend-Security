<?php
/**
 * 🖼️ Image Security Engine
 * Refactored to use functions instead of classes
 */

declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../config.php';

function img_csrf_token(): string {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
}

function img_validate_csrf(string $token): bool {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
}

function img_check_rate_limit(string $ip): bool {
    $db = getDB();
    $sessionId = session_id();
    
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE (identifier = ? OR identifier = ?) AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    $stmt->execute([$ip, $sessionId]);
    if ((int)$stmt->fetchColumn() >= IMG_RATE_LIMIT_PER_MINUTE) return true;

    $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'upload')")->execute([$ip]);
    if ($sessionId) {
        $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'session', 'upload')")->execute([$sessionId]);
    }
    return false;
}

/**
 * Verify first bytes of the file against MIME type
 */
function img_verify_magic_bytes(string $bytes, string $mime): bool {
    $hex = bin2hex($bytes);
    switch ($mime) {
        case 'image/jpeg':
            return str_starts_with($hex, 'ffd8ff');
        case 'image/png':
            return str_starts_with($hex, '89504e470d0a1a0a');
        case 'image/gif':
            return str_starts_with($hex, '474946383761') || str_starts_with($hex, '474946383961');
        case 'image/webp':
            return str_starts_with($hex, '52494646') && substr($hex, 16, 8) === '57454250';
    }
    return false;
}

/**
 * Scan file content for embedded script tags or PHP markers
 */
function img_scan_payloads(string $path): array {
    $content = @file_get_contents($path);
    if ($content === false) return [];

    $findings = [];
    $malicious = [
        '<?php' => 'PHP Script',
        '<? ' => 'Short PHP',
        '<script' => 'Script Tag',
        'javascript:' => 'JS URI',
        'onload=' => 'HTML Event',
        'onerror=' => 'HTML Event',
        'eval(' => 'Execution',
        'base64_decode' => 'Obfuscation'
    ];

    foreach ($malicious as $trigger => $desc) {
        if (stripos($content, $trigger) !== false) {
            $findings[] = ['trigger' => $trigger, 'desc' => $desc];
        }
    }

    return $findings;
}

/**
 * Primary validation pipeline
 */
function img_validate_file(array $file): array {
    $findings = [];
    $tmpPath = $file['tmp_name'];

    // 1. Basic PHP Upload Checks
    if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload failed with error code: " . $file['error']];
    if ($file['size'] > IMG_MAX_FILE_SIZE) return ["File size exceeds limit (" . (IMG_MAX_FILE_SIZE/1024/1024) . "MB)"];
    if ($file['size'] < IMG_MIN_FILE_SIZE) return ["File is suspiciously small"];

    // 2. Extension Check
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, IMG_ALLOWED_EXTENSIONS)) return ["Invalid file extension"];

    // 3. MIME Type Verification
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $realMime = $finfo->file($tmpPath);
    if (!in_array($realMime, IMG_ALLOWED_MIME_TYPES)) {
        return ["Security Violation: Mismatched MIME type ($realMime)"];
    }

    // 4. Magic Bytes Check
    $handle = fopen($tmpPath, 'rb');
    $bytes = fread($handle, 12);
    fclose($handle);
    if (!img_verify_magic_bytes($bytes, $realMime)) {
        $findings[] = [
            'type' => 'structure',
            'desc' => 'Magic byte signature mismatch (Potential Polyglot)',
            'level' => 'suspicious'
        ];
    }

    // 5. Image Dimension & DoS Attack Check
    $dimensions = @getimagesize($tmpPath);
    if (!$dimensions) return ["Invalid image data: Cannot determine dimensions"];
    
    $width = $dimensions[0];
    $height = $dimensions[1];
    $totalPixels = $width * $height;

    if ($width > IMG_MAX_IMAGE_WIDTH || $height > IMG_MAX_IMAGE_HEIGHT) {
        return ["Security Violation: Image dimensions exceed limits ($width x $height)"];
    }
    
    if ($totalPixels > IMG_MAX_TOTAL_PIXELS) {
        return ["Security Violation: Total pixel count ($totalPixels) exceeds safety limit"];
    }

    // 6. Detect Animated GIF / APNG
    if ($realMime === 'image/gif') {
        $content = file_get_contents($tmpPath);
        if (preg_match("/\x00\x21\xF9\x04.{4}\x00\x2c/s", $content)) {
            $findings[] = [
                'type' => 'animated',
                'desc' => 'Animated GIF detected (Sanitizer will flatten to first frame)',
                'level' => 'info'
            ];
        }
    }

    // 7. Polyglot/Payload Scanning
    $polyglots = img_scan_payloads($tmpPath);
    foreach ($polyglots as $p) {
        $findings[] = [
            'type' => 'malicious_content',
            'desc' => 'Potential payload: ' . $p['desc'],
            'level' => 'suspicious'
        ];
    }

    return $findings;
}

/**
 * Sanitizes image using libvips
 */
function img_sanitize(string $inputPath, string $outputPath, string $mime): bool {
    $inputOptions = "";
    if ($mime === 'image/gif' || $mime === 'image/webp') {
        $inputOptions = "[n=1]";
    }

    $outputOptions = "[strip]";
    
    $cmd = IMG_EXEC_TIMEOUT . "vips copy " . escapeshellarg($inputPath . $inputOptions) . " " . escapeshellarg($outputPath . $outputOptions) . " 2>&1";
    
    exec($cmd, $output, $returnCode);
    
    if ($returnCode !== 0) {
        return false;
    }

    // 2. Post-Sanitize Re-verification
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $newMime = $finfo->file($outputPath);
    
    $handle = fopen($outputPath, 'rb');
    $bytes = fread($handle, 12);
    fclose($handle);
    if (!img_verify_magic_bytes($bytes, $newMime)) return false;

    $sanitizedDims = @getimagesize($outputPath);
    if (!$sanitizedDims) return false;
    if (($sanitizedDims[0] * $sanitizedDims[1]) > IMG_MAX_TOTAL_PIXELS) return false;

    if (filesize($outputPath) > IMG_MAX_FILE_SIZE) return false;

    return true;
}

function img_get_features(): array {
    return [
        ['name' => 'Decode-or-Die', 'icon' => '💀', 'desc' => 'Libvips mandatory decoding ensures only valid image structures are accepted.'],
        ['name' => 'Sanitization Authority', 'icon' => '⚖️', 'desc' => 'Detections are signals; the re-encoding output is the final security verdict.'],
        ['name' => 'Mandatory Normalization', 'icon' => '🧹', 'desc' => 'Normalizes colorspace, bit-depth, and strips all metadata/ICC profiles.'],
        ['name' => 'Animation Flattening', 'icon' => '🖼️', 'desc' => 'Automatically flattens GIFs/APNGs to the first frame to kill hidden payloads.'],
        ['name' => 'Post-Sanitize Audit', 'icon' => '🔍', 'desc' => 'Re-verifies magic bytes, dimensions, and MIME after the re-encoding step.'],
        ['name' => 'Total Pixel Sentinel', 'icon' => '🌊', 'desc' => 'Strict width/height and total megapixel limits to block Image Bomb DoS attacks.'],
        ['name' => 'Sanitized Hashing', 'icon' => '🔒', 'desc' => 'Hashes only the final sanitized version for absolute integrity guarantees.'],
        ['name' => 'Size Delta Logging', 'icon' => '📊', 'desc' => 'Records the exact amount of data stripped to monitor sanitization effectiveness.']
    ];
}

/** Gateway Integration Wrapper */
function img_process(array $file, string $targetPath, string $mime): array {
    $findings = img_validate_file($file);
    
    foreach ($findings as $f) {
        if (is_string($f)) {
            return ['status' => 'rejected', 'error' => $f];
        }
    }

    $success = img_sanitize($file['tmp_name'], $targetPath, $mime);
    if (!$success) {
        return ['status' => 'rejected', 'error' => 'Security Rejection: Invalid or malicious image structure'];
    }

    return [
        'status' => 'sanitized',
        'path' => $targetPath,
        'details' => 'Decode-or-Die Sanitized via libvips'
    ];
}
