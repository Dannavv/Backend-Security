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

// 🧬 Correlation ID (The "Military-Grade" Backbone)
// Generate this early so it's available for all logs and headers
if (!defined('REQUEST_ID')) {
    define('REQUEST_ID', substr(bin2hex(random_bytes(8)), 0, 16));
}
header("X-Request-ID: " . REQUEST_ID);

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

/**
 * Helper: Recursively sanitize context data
 * - Redacts sensitive keys
 * - Strips newlines from string values
 */
function sanitize_context_data(array $context): array {
    $sensitiveKeys = ['password', 'token', 'secret', 'cvv', 'card_number', 'api_key', 'auth', 'pass'];
    
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
            $context[$key] = sanitize_entry($value);
        }
    }
    return $context;
}

/**
 * Military-Grade Structured Logger
 * 
 * Format: [ISO8601] [LEVEL] [FILE:LINE] [USER|IP] [REQUEST_ID] MESSAGE
 */
function erp_log(string $level, string $message, array $context = [], ?string $logFile = null): void
{
    $logFile = $logFile ?? LOG_FILE_PATH;
    
    // 1. Sanitize Message (Log Injection Prevention)
    $cleanMessage = sanitize_entry($message);
    
    // 2. Sanitize Context (Sensitive Data Redaction & Injection Prevention)
    $cleanContext = sanitize_context_data($context);
    
    // 3. Optimize Backtrace (Memory Safety)
    // Limit to 2 frames to save memory, ignore args
    $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
    $caller = $backtrace[1] ?? $backtrace[0]; 
    
    // Build structured log entry
    $entry = sprintf(
        "[%s] [%s] [%s:%d] [%s|%s] [%s] %s",
        date('c'),                                                    // ISO8601 timestamp
        str_pad(strtoupper($level), 8),                              // Log level (padded for alignment)
        basename($caller['file'] ?? 'unknown'),                      // Source file
        $caller['line'] ?? 0,                                        // Line number
        $_SESSION['user_id'] ?? $_SESSION['username'] ?? 'anonymous', // User identifier
        $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',                       // Client IP
        REQUEST_ID,                                                   // Correlation ID
        $cleanMessage                                                 // Message
    );
    
    // 4. Safe JSON Encoding
    if (!empty($cleanContext)) {
        $jsonContext = json_encode($cleanContext, JSON_UNESCAPED_SLASHES);
        if ($jsonContext === false) {
             // Fallback for resources or malformed UTF-8 preventing silent data loss
             $jsonContext = json_encode([
                 'error' => 'JSON_ENCODE_FAILED', 
                 'reason' => json_last_error_msg(),
                 'raw_preview' => substr(serialize($cleanContext), 0, 100) . '...'
             ]);
        }
        $entry .= ' | CONTEXT=' . $jsonContext;
    }
    
    // 5. Atomic Write with Locking (Race Condition Handling)
    // file_put_contents with LOCK_EX prevents interleaved writes under load
    file_put_contents($logFile, $entry . PHP_EOL, FILE_APPEND | LOCK_EX);
    
    // Also log security events to dedicated security log
    if (in_array(strtoupper($level), ['SECURITY', 'CRITICAL'])) {
        file_put_contents(SECURITY_LOG_PATH, $entry . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
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

// Start session if not started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
