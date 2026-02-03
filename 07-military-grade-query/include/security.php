<?php
/**
 * Chapter 7: Security Utilities
 * HTTP headers, CSRF, rate limiting, logging (adapted from Ch01 security.php)
 */

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

// ============================================
// CONSTANTS
// ============================================

define('SECURE_QUERY_DEBUG_MODE', getenv('DEBUG_MODE') === 'true');
define('SECURE_QUERY_LOG_PATH', __DIR__ . '/../logs/security.log');
define('SECURE_QUERY_RATE_LIMIT', 100);
define('SECURE_QUERY_MAX_PARAMS', 50);

// ============================================
// SECURITY HEADERS (From Ch01 security.php)
// ============================================

function set_security_headers(): void {
    global $securityHeaders;
    
    foreach ($securityHeaders as $header => $value) {
        header("$header: $value");
    }
    header_remove('X-Powered-By');
}

// ============================================
// DATABASE CONNECTION
// ============================================

function get_db(): mysqli {
    static $conn = null;
    if ($conn !== null) return $conn;
    
    $host = getenv('DB_HOST') ?: 'mysql';
    $name = getenv('DB_NAME') ?: 'secure_query_demo';
    $user = getenv('DB_USER') ?: 'demo_user';
    $pass = getenv('DB_PASS') ?: 'demo_secure_pass';
    
    $conn = new mysqli($host, $user, $pass, $name);
    if ($conn->connect_error) {
        secure_log('CRITICAL', 'Database connection failed', ['error' => $conn->connect_error]);
        throw new Exception('Database connection failed');
    }
    
    $conn->set_charset('utf8mb4');
    $conn->query("SET SESSION sql_mode = 'STRICT_ALL_TABLES'");
    
    return $conn;
}

// ============================================
// CSRF PROTECTION (From Ch02)
// ============================================

function csrf_ensure_token(): string {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_validate(string $token): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return !empty($token) && hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

// ============================================
// RATE LIMITING (From Ch02)
// ============================================

function check_rate_limit(string $ip): bool {
    try {
        $db = get_db();
        $stmt = $db->prepare(
            "SELECT COUNT(*) as cnt FROM rate_limits 
             WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)"
        );
        $stmt->bind_param('s', $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        $count = (int)$result->fetch_assoc()['cnt'];
        $stmt->close();
        
        if ($count >= SECURE_QUERY_RATE_LIMIT) {
            secure_log('WARNING', 'Rate limit exceeded', ['ip' => $ip, 'count' => $count]);
            return false;
        }
        
        $stmt = $db->prepare("INSERT INTO rate_limits (identifier, identifier_type, action) VALUES (?, 'ip', 'query')");
        $stmt->bind_param('s', $ip);
        $stmt->execute();
        $stmt->close();
        
        return true;
    } catch (Exception $e) {
        secure_log('ERROR', 'Rate limit check failed', ['error' => $e->getMessage()]);
        return true; // Fail open
    }
}

// ============================================
// IP DETECTION (From Ch06)
// ============================================

function get_client_ip(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ============================================
// LOGGING (From Ch06)
// ============================================

function secure_log(string $level, string $message, array $context = []): void {
    $timestamp = date('Y-m-d\TH:i:s.vP');
    $ip = get_client_ip();
    $rid = $_SERVER['HTTP_X_REQUEST_ID'] ?? substr(bin2hex(random_bytes(8)), 0, 16);
    
    $safeContext = redact_pii($context);
    
    $logLine = sprintf(
        "[%s] [%s] [%s] [RID:%s] %s | %s\n",
        $timestamp,
        strtoupper($level),
        $ip,
        $rid,
        sanitize_log_message($message),
        json_encode($safeContext, JSON_UNESCAPED_SLASHES)
    );
    
    file_put_contents(SECURE_QUERY_LOG_PATH, $logLine, FILE_APPEND | LOCK_EX);
}

function sanitize_log_message(string $msg): string {
    return str_replace(["\n", "\r", "\t"], ' ', $msg);
}

function redact_pii(array $context): array {
    $sensitiveKeys = ['password', 'passwd', 'secret', 'token', 'api_key', 'credit_card', 'cc'];
    
    array_walk_recursive($context, function(&$value, $key) use ($sensitiveKeys) {
        $keyStr = (string)$key;
        
        foreach ($sensitiveKeys as $sensitive) {
            if (stripos($keyStr, $sensitive) !== false) {
                $value = '[REDACTED]';
                return;
            }
        }
        if (is_string($value) && preg_match('/^\d{13,19}$/', $value) && luhn_check($value)) {
            $value = '[CC_REDACTED]';
        }
    });
    
    return $context;
}

function luhn_check(string $number): bool {
    $number = preg_replace('/\D/', '', $number);
    $sum = 0;
    $alt = false;
    for ($i = strlen($number) - 1; $i >= 0; $i--) {
        $n = (int)$number[$i];
        if ($alt) {
            $n *= 2;
            if ($n > 9) $n -= 9;
        }
        $sum += $n;
        $alt = !$alt;
    }
    return $sum % 10 === 0;
}
