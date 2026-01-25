<?php
/**
 * Chapter 06: Military-Grade Logging Architecture
 * This file implements the structured logging system described in the guide.
 */

// ============================================
// ENVIRONMENT CONFIGURATION
// ============================================
define('APP_ENV', getenv('APP_ENV') ?: 'development');
define('IS_PRODUCTION', APP_ENV === 'production');

// 🧬 Correlation ID & Trust Boundary
// Only accept inbound ID if it matches our format (hex). Prevention against ID Poisoning.
$inboundID = $_SERVER['HTTP_X_REQUEST_ID'] ?? '';
$isInvalidPropagated = false;

if (!empty($inboundID) && !preg_match('/^[a-f0-9]{16,32}$/i', $inboundID)) {
    $isInvalidPropagated = true; // Flag for later security logging
    define('REQUEST_ID', bin2hex(random_bytes(8))); // Generate fresh
    define('REQUEST_ID_SOURCE', 'GENERATED_FALLBACK');
} elseif (!empty($inboundID)) {
    define('REQUEST_ID', $inboundID);
    define('REQUEST_ID_SOURCE', 'PROPAGATED');
} else {
    define('REQUEST_ID', bin2hex(random_bytes(8)));
    define('REQUEST_ID_SOURCE', 'GENERATED');
}
header("X-Request-ID: " . REQUEST_ID);

// 🛡️ Log Integrity Secret (Should be in ENV or Secret Manager)
define('LOG_SECRET_KEY', getenv('LOG_SECRET') ?: 'change_me_to_something_strong_in_prod');
define('LOG_KEY_ID', getenv('LOG_KEY_ID') ?: 'v1'); // Key ID for rotation support

// 🌐 Trusted Proxy Configuration for Accurate IP
// Define CIDRs or IPs that are trusted proxies
define('TRUSTED_PROXIES', ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '::1']);

// Configure PHP error handling
if (IS_PRODUCTION) {
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
    error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
} else {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    ini_set('log_errors', '1');
    error_reporting(E_ALL);
}

// ============================================
// LOG PATHS
// ============================================
$logBaseDir = __DIR__ . '/../logs';
if (!is_dir($logBaseDir)) {
    mkdir($logBaseDir, 0750, true);
}

define('LOG_FILE_PATH', $logBaseDir . '/app.log');
define('SECURITY_LOG_PATH', $logBaseDir . '/security.log');
define('AUDIT_LOG_PATH', $logBaseDir . '/audit.log');
define('PERFORMANCE_LOG_PATH', $logBaseDir . '/performance.log');

// ============================================
// STRUCTURED APPLICATION LOGGING
// ============================================

/**
 * Helper: Sanitize log message to prevent log injection (newlines)
 */
function sanitize_entry(string $input): string {
    return str_replace(["\r", "\n"], ' ', $input);
}

// Helper: Luhn Algorithm for confident CC detection
function is_luhn_valid(string $number): bool {
    $sum = 0;
    $flag = 0; 
    for ($i = strlen($number) - 1; $i >= 0; $i--) {
        $add = $flag++ & 1 ? $number[$i] * 2 : $number[$i];
        $sum += $add > 9 ? $add - 9 : $add;
    }
    return $sum % 10 === 0;
}

/**
 * Helper: Recursively sanitize context data
 * - Redacts sensitive keys
 * - Strips newlines from string values
 * - Validates CCs with Luhn
 */
function sanitize_context_data(array $context): array {
    $sensitiveKeys = ['password', 'token', 'secret', 'cvv', 'card_number', 'api_key', 'auth', 'pass'];
    
    // Canonicalize: Sort keys for stable signatures
    ksort($context);

    foreach ($context as $key => $value) {
        // Recursion
        if (is_array($value)) {
            $context[$key] = sanitize_context_data($value);
            continue;
        }
        
        // Redaction (Case-insensitive check)
        $lowerKey = strtolower($key);
        foreach ($sensitiveKeys as $sensitive) {
             if (strpos($lowerKey, $sensitive) !== false) {
                 $context[$key] = '***REDACTED***';
                 continue 2; // Move to next item
             }
        }
        
        // Sanitize newlines in string values to prevent injection via context
        if (is_string($value)) {
            // Pattern-Based Redaction (Regex + Logic)
            
            // 1. Bearer Tokens / JWT (roughly)
            if (preg_match('/(Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*)|(eyJ[a-zA-Z0-9\-\._~\+\/]+=*)/', $value)) {
                $context[$key] = '***REDACTED_TOKEN***';
            }
            // 2. Credit Card Numbers (Luhn Check)
            elseif (preg_match_all('/\b(?:\d[ -]*?){13,19}\b/', $value, $matches)) {
                 foreach ($matches[0] as $match) {
                     $cleanNum = preg_replace('/\D/', '', $match);
                     if (is_luhn_valid($cleanNum)) {
                         $value = str_replace($match, '***REDACTED_CC***', $value);
                         $context[$key] = $value;
                     }
                 }
            }
            // 3. Email Addresses (PII)
            elseif (filter_var($value, FILTER_VALIDATE_EMAIL)) {
                 $parts = explode('@', $value);
                 $context[$key] = substr($parts[0], 0, 3) . '***@' . $parts[1];
            }
            
            // Always strip CRLF
            $context[$key] = sanitize_entry($context[$key]);
        }
    }
    return $context;
}

/**
 * Helper: Parse Client IP respecting Trusted Proxies
 * Returns [client_ip, peer_ip]
 */
function get_ip_details(): array {
    $peer_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $client_ip = $peer_ip;
    
    // Check if peer is trusted proxy
    $is_trusted = false;
    foreach (TRUSTED_PROXIES as $proxy_cidr) {
        // Simplified CIDR check (for demo purposes, checks explicit IP or basic subnet logic)
        // In prod use symfony/http-foundation IpUtils::checkIp
        if ($peer_ip === $proxy_cidr || strpos($peer_ip, '127.') === 0 || strpos($peer_ip, '10.') === 0 || strpos($peer_ip, '172.') === 0) {
            $is_trusted = true;
            break;
        }
    }

    if ($is_trusted && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $xff_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        // Trust chain logic: if trusted, take the left-most valid IP 
        // (Assuming standard config where proxy adds to right)
        $potential_ip = trim($xff_list[0]);
        if (filter_var($potential_ip, FILTER_VALIDATE_IP)) {
            $client_ip = $potential_ip;
        }
    }
    
    return [$client_ip, $peer_ip];
}

/**
 * Military-Grade Structured Logger
 * 
 * Format: [ISO8601] [LEVEL] [FILE:LINE] [USER] [IP(REAL|PEER)] [RID(SRC)] [SEQ] [KEY_ID] MESSAGE | CONTEXT | [SIG]
 */
function erp_log(string $level, string $message, array $context = [], ?string $logFile = null): void
{
    global $isInvalidPropagated; // Access flag if called during init (edge case)

    $logFile = $logFile ?? LOG_FILE_PATH;
    
    // 1. Sanitize Message & Cap Size (DoS Prevention)
    $cleanMessage = sanitize_entry(substr($message, 0, 2048)); // Cap message at 2KB
    
    // 2. Sanitize Context (Keys + Patterns)
    $cleanContext = sanitize_context_data($context);
    
    // 3. Optimize Backtrace
    $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
    $caller = $backtrace[1] ?? $backtrace[0]; 
    
    // 4. Resolve Identity & Sequence
    $user = $_SESSION['user_id'] ?? $_SESSION['username'] ?? 'anonymous';
    list($client_ip, $peer_ip) = get_ip_details();
    
    // Hash Chaining: Get & Increment Log Sequence
    if (session_status() === PHP_SESSION_DISABLED || session_status() === PHP_SESSION_NONE) {
        // Fallback for CLI/early init
        $sequence = 0; 
        $prev_hash = '0000000000000000000000000000000000000000000000000000000000000000'; 
    } else {
        $sequence = ++$_SESSION['log_sequence'];
        $prev_hash = $_SESSION['last_log_hash'];
    }

    // Capture Full XFF Chain for Context
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $cleanContext['xff_chain'] = sanitize_entry($_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    // Build Entry Base (Canonicalized for signing)
    
    $timestamp = date('c');
    $level_pad = str_pad(strtoupper($level), 8);
    $file_loc = basename($caller['file'] ?? 'unknown') . ':' . ($caller['line'] ?? 0);
    $rid_str = REQUEST_ID . ':' . (REQUEST_ID_SOURCE === 'GENERATED' || REQUEST_ID_SOURCE === 'GENERATED_FALLBACK' ? 'GEN' : 'PRP');
    
    // Explicit IP logging: Client (Real) | Peer (Direct Connection)
    $ip_str = "$client_ip|$peer_ip";

    $logContent = sprintf(
        "[%s] [%s] [%s] [%s] [%s] [%s] [%06d] [%s] %s",
        $timestamp,
        $level_pad,
        $file_loc,
        $user,
        $ip_str,
        $rid_str,
        $sequence,
        LOG_KEY_ID,
        $cleanMessage
    );
    
    // 5. Append JSON Context
    if (!empty($cleanContext)) {
        // Safe Encoding with Sorting (Canonicalization)
        $jsonContext = json_encode($cleanContext, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        
        // Cap context size for DoS prevention with Explicit Marker
        if (strlen($jsonContext) > 8192) { // 8KB Limit
             $orig_len = strlen($jsonContext);
             $jsonContext = substr($jsonContext, 0, 8192) . "... [TRUNCATED:len=$orig_len]";
        }
        if ($jsonContext === false) {
             $jsonContext = json_encode(['error' => 'JSON_FAIL']);
        }
        $logContent .= ' | CONTEXT=' . $jsonContext;
    }
    
    // 6. 🔒 Cryptographic Signing with Hash Chaining
    // Sign( Secret + PrevHash + Content )
    $signaturePayload = LOG_SECRET_KEY . $prev_hash . $logContent;
    $signature = hash_hmac('sha256', $signaturePayload, LOG_SECRET_KEY);
    
    // Update session chain
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['last_log_hash'] = $signature;
    }
    
    $finalEntry = $logContent . " | [SIG:$signature]";
    
    // 7. Atomic Write
    file_put_contents($logFile, $finalEntry . PHP_EOL, FILE_APPEND | LOCK_EX);
    
    if (in_array(strtoupper($level), ['SECURITY', 'CRITICAL'])) {
        file_put_contents(SECURITY_LOG_PATH, $finalEntry . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}

/**
 * Metadata Bridge for Rotation
 * Call this before rotating logs to link chains
 */
function log_rotate_bridge(string $newFileId) {
    erp_log('SYSTEM', 'ROTATION_BRIDGE: Switching to new log file', ['next_file' => $newFileId]);
}

// Convenience functions
function log_debug(string $msg, array $ctx = []): void { erp_log('DEBUG', $msg, $ctx); }
function log_info(string $msg, array $ctx = []): void { erp_log('INFO', $msg, $ctx); }
function log_warn(string $msg, array $ctx = []): void { erp_log('WARN', $msg, $ctx); }
function log_error(string $msg, array $ctx = []): void { erp_log('ERROR', $msg, $ctx); }
function log_critical(string $msg, array $ctx = []): void { erp_log('CRITICAL', $msg, $ctx); }
function log_security(string $msg, array $ctx = []): void { erp_log('SECURITY', $msg, $ctx, SECURITY_LOG_PATH); }
function log_audit(string $msg, array $ctx = []): void { erp_log('AUDIT', $msg, $ctx, AUDIT_LOG_PATH); }
function log_performance(string $msg, array $ctx = []): void { erp_log('PERFORMANCE', $msg, $ctx, PERFORMANCE_LOG_PATH); }

// ============================================
// GLOBAL EXCEPTION HANDLER
// ============================================
set_exception_handler(function (Throwable $e) {
    log_critical("Uncaught Exception: " . $e->getMessage(), [
        'exception' => get_class($e),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString()
    ]);
    
    if (IS_PRODUCTION) {
        if (!headers_sent()) {
            http_response_code(500);
        }
        die('An internal error occurred. Reference: ' . (defined('REQUEST_ID') ? REQUEST_ID : 'N/A'));
    } else {
        // In dev, show the error
        echo "<h1>Uncaught Exception</h1>";
        echo "<p><b>Message:</b> " . htmlspecialchars($e->getMessage()) . "</p>";
        echo "<pre>" . htmlspecialchars($e->getTraceAsString()) . "</pre>";
    }
});

// ============================================
// GLOBAL ERROR HANDLER
// ============================================
set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline) {
    if (!(error_reporting() & $errno)) {
        return false;
    }

    $level = match($errno) {
        E_ERROR, E_USER_ERROR, E_CORE_ERROR, E_COMPILE_ERROR => 'CRITICAL',
        E_WARNING, E_USER_WARNING, E_CORE_WARNING, E_COMPILE_WARNING => 'WARN',
        E_NOTICE, E_USER_NOTICE => 'DEBUG',
        E_DEPRECATED, E_USER_DEPRECATED => 'DEBUG',
        default => 'ERROR'
    };
    
    erp_log($level, $errstr, [
        'errno' => $errno,
        'file' => basename($errfile),
        'line' => $errline
    ]);
    
    return true; // Don't execute PHP's internal error handler
});

// Helper to Log Genesis Block (Startup)
function log_genesis_block() {
    if (!defined('GENESIS_LOGGED')) {
        define('GENESIS_LOGGED', true);
        erp_log('SYSTEM', 'GENESIS_BLOCK: Logger initialized', [
            'scope' => 'process_' . getmypid(),
            'php_version' => PHP_VERSION,
            'log_key_id' => LOG_KEY_ID
        ]);
    }
}

// Log Genesis on script load
log_genesis_block();

// Log invalid propagated ID attempt if detected earlier
if (isset($isInvalidPropagated) && $isInvalidPropagated) {
    // Log immediately as a security warning, but avoid infinite recursion
    erp_log('SECURITY', 'Invalid X-Request-ID format detected from upstream', [
        'received_id' => substr($_SERVER['HTTP_X_REQUEST_ID'], 0, 50), // Cap length
        'action' => 'regenerated_new_id'
    ]);
    unset($isInvalidPropagated);
}

// Start session if not started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// Init session-based hash chain sequence if needed
if (!isset($_SESSION['log_sequence'])) {
    $_SESSION['log_sequence'] = 0;
    $_SESSION['last_log_hash'] = str_repeat('0', 64); // Initial chaining hash
    // Log a session genesis to link the chain
    erp_log('SYSTEM', 'SESSION_GENESIS: New hash chain started', ['session_id' => session_id()]);
}
