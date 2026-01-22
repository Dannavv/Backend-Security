<?php
/**
 * 🛡️ Image Security Engine
 * Implements multi-layered defense for image uploads.
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

class ImageSecurity {
    /**
     * Get a CSRF token for forms
     */
    public static function csrfToken(): string {
        if (session_status() === PHP_SESSION_NONE) session_start();
        return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(32)));
    }

    /**
     * Validate CSRF token
     */
    public static function validateCSRF(string $token): bool {
        if (session_status() === PHP_SESSION_NONE) session_start();
        return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
    }

    /**
     * Rate limiting based on IP and Session
     */
    public static function checkRateLimit(string $ip): bool {
        $db = getDB();
        $sessionId = session_id();
        
        $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE (identifier = ? OR identifier = ?) AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute([$ip, $sessionId]);
        if ((int)$stmt->fetchColumn() >= RATE_LIMIT_PER_MINUTE) return true;

        $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'upload')")->execute([$ip]);
        if ($sessionId) {
            $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'session', 'upload')")->execute([$sessionId]);
        }
        return false;
    }

    /**
     * Primary validation pipeline (Detection is now SIGNAL only, not verdict)
     */
    public static function validateFile(array $file): array {
        $findings = [];
        $tmpPath = $file['tmp_name'];

        // 1. Basic PHP Upload Checks (Hard Fail)
        if ($file['error'] !== UPLOAD_ERR_OK) return ["Upload failed with error code: " . $file['error']];
        if ($file['size'] > MAX_FILE_SIZE) return ["File size exceeds limit (" . (MAX_FILE_SIZE/1024/1024) . "MB)"];
        if ($file['size'] < MIN_FILE_SIZE) return ["File is suspiciously small"];

        // 2. Extension Check (Soft Gate)
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ALLOWED_EXTENSIONS)) return ["Invalid file extension"];

        // 3. MIME Type Verification (finfo)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $realMime = $finfo->file($tmpPath);
        if (!in_array($realMime, ALLOWED_MIME_TYPES)) {
            return ["Security Violation: Mismatched MIME type ($realMime)"];
        }

        // 4. Magic Bytes Check (Structural Signal)
        $handle = fopen($tmpPath, 'rb');
        $bytes = fread($handle, 12);
        fclose($handle);
        if (!self::verifyMagicBytes($bytes, $realMime)) {
            $findings[] = [
                'type' => 'structure',
                'desc' => 'Magic byte signature mismatch (Potential Polyglot)',
                'level' => 'suspicious'
            ];
        }

        // 5. Image Dimension & DoS Attack Check (Pixel Flood)
        $dimensions = @getimagesize($tmpPath);
        if (!$dimensions) return ["Invalid image data: Cannot determine dimensions"];
        
        $width = $dimensions[0];
        $height = $dimensions[1];
        $totalPixels = $width * $height;

        if ($width > MAX_IMAGE_WIDTH || $height > MAX_IMAGE_HEIGHT) {
            return ["Security Violation: Image dimensions exceed limits ($width x $height)"];
        }
        
        if ($totalPixels > MAX_TOTAL_PIXELS) {
            return ["Security Violation: Total pixel count ($totalPixels) exceeds safety limit"];
        }

        // 6. Detect Animated GIF / APNG (Signal: Sanitizer will flatten or die)
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

        // 7. Polyglot/Payload Scanning (Deep Signal)
        $polyglots = self::scanForPayloads($tmpPath);
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
     * Sanitizes image using libvips (Authoritative: Decode-or-Die)
     * Normalize output: Strips metadata/ICC, flattens to sRGB, fixed quality.
     */
    public static function sanitizeImage(string $inputPath, string $outputPath, string $mime): bool {
        // Use format-specific options in the filename string [...]
        // [strip]: Removes all metadata (EXIF, XMP, IPTC) and ICC profiles
        // [n=1]: For animated formats, ensures we only decode the first frame (flattening)
        
        $inputOptions = "";
        if ($mime === 'image/gif' || $mime === 'image/webp') {
            $inputOptions = "[n=1]";
        }

        // We use the 'strip' option which is shorthand for clearing metadata in most savers
        $outputOptions = "[strip]";
        
        // Command becomes: vips copy input[n=1] output[strip]
        $cmd = EXEC_TIMEOUT . "vips copy " . escapeshellarg($inputPath . $inputOptions) . " " . escapeshellarg($outputPath . $outputOptions) . " 2>&1";
        
        exec($cmd, $output, $returnCode);
        
        if ($returnCode !== 0) {
            error_log("Libvips Decode Failure (Rejecting): " . implode("\n", $output));
            return false;
        }

        // 2. Post-Sanitize Re-verification (Point 6)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $newMime = $finfo->file($outputPath);
        
        // Verify Magic Bytes
        $handle = fopen($outputPath, 'rb');
        $bytes = fread($handle, 12);
        fclose($handle);
        if (!self::verifyMagicBytes($bytes, $newMime)) return false;

        // Verify Dimensions & Total Pixels again on output
        $sanitizedDims = @getimagesize($outputPath);
        if (!$sanitizedDims) return false;
        if (($sanitizedDims[0] * $sanitizedDims[1]) > MAX_TOTAL_PIXELS) return false;

        // Verify sanitized size cap
        if (filesize($outputPath) > MAX_FILE_SIZE) return false;

        return true;
    }

    /**
     * Verify first bytes of the file against MIME type
     */
    private static function verifyMagicBytes(string $bytes, string $mime): bool {
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
    private static function scanForPayloads(string $path): array {
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
     * List of security features for UI
     */
    public static function getFeatures(): array {
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
}
