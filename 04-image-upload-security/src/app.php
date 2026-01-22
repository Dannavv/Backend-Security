<?php
/**
 * 🔐 Global Application Initialization
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/ImageSecurity.php';

function initSecurity(): void {
    // Security Headers
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:;");
    
    // PHP Settings
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', LOG_DIR . '/php_errors.log');
    error_reporting(E_ALL);
    
    // Session Security
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', '1');
        session_start();
    }
}

/**
 * Audit Logger Class
 */
class AuditLogger {
    public static function logAttempt(string $filename, string $status, array $findings, int $size, ?string $hash = null): void {
        try {
            $db = getDB();
            $db->prepare("INSERT INTO image_audit (ip_address, user_agent, filename, status, security_findings, file_size, file_hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
               ->execute([
                   $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', 
                   $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 
                   $filename, 
                   $status, 
                   json_encode($findings), 
                   $size,
                   $hash
               ]);
        } catch (Exception $e) {
            error_log("Audit Log Failed: " . $e->getMessage());
        }
    }
}

/**
 * Image Registry for Storage
 */
class ImageRegistry {
    public static function register(string $uuid, string $name, string $mime, int $w, int $h, int $size, string $hash, string $path): bool {
        try {
            $db = getDB();
            $stmt = $db->prepare("INSERT INTO uploaded_images (uuid, original_name, mime_type, width, height, file_size, file_hash, storage_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            return $stmt->execute([$uuid, $name, $mime, $w, $h, $size, $hash, $path]);
        } catch (Exception $e) {
            error_log("Registry Failed: " . $e->getMessage());
            return false;
        }
    }
}
