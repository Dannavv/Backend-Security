<?php
/**
 * Chapter 7: Military-Grade Secure Query Function
 * 
 * Consolidates scattered security layers into ONE enforced gateway.
 * Reuses components from Chapters 1-6.
 */

declare(strict_types=1);

require_once __DIR__ . '/validator.php';
require_once __DIR__ . '/security.php';

/**
 * Military-grade secure query execution
 * 
 * @param string $sql SQL query with placeholders
 * @param array $params ['types', val1, val2, ...] format (backward compatible with ERP)
 * @param array $options Security options
 * @return array Standardized response ['success', 'data', 'error', 'affected_rows', 'insert_id']
 */
function execute_query_d1(
    string $sql, 
    array $params = [], 
    array $options = []
): array {
    // Default options
    $opts = array_merge([
        'require_post' => is_write_query($sql),
        'require_csrf' => true,
        'max_lengths' => [],
        'log_query' => true,
        'skip_rate_limit' => false,
    ], $options);
    
    $startTime = microtime(true);
    $ip = get_client_ip();
    
    // ========================================
    // LAYER 1: REQUEST METHOD CHECK
    // ========================================
    if ($opts['require_post'] && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        secure_log('WARNING', 'POST required but got ' . ($_SERVER['REQUEST_METHOD'] ?? 'GET'), [
            'query_type' => get_query_type($sql)
        ]);
        return error_response('Request method not allowed', 'METHOD_NOT_ALLOWED');
    }
    
    // ========================================
    // LAYER 2: CSRF VALIDATION
    // ========================================
    if ($opts['require_csrf']) {
        $csrfToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!csrf_validate($csrfToken)) {
            secure_log('WARNING', 'CSRF validation failed', ['ip' => $ip]);
            return error_response('CSRF validation failed', 'CSRF_FAILED');
        }
    }
    
    // ========================================
    // LAYER 3: RATE LIMITING
    // ========================================
    if (!$opts['skip_rate_limit'] && !check_rate_limit($ip)) {
        return error_response('Rate limit exceeded. Please try again later.', 'RATE_LIMITED');
    }
    
    // ========================================
    // LAYER 4: PARAMETER COUNT CHECK
    // ========================================
    if (count($params) > SECURE_QUERY_MAX_PARAMS + 1) { // +1 for types string
        secure_log('WARNING', 'Too many parameters', ['count' => count($params)]);
        return error_response('Too many parameters', 'PARAM_OVERFLOW');
    }
    
    // ========================================
    // LAYER 5: INPUT VALIDATION
    // ========================================
    if (!empty($params)) {
        $types = $params[0] ?? '';
        $values = array_slice($params, 1);
        
        if (strlen($types) !== count($values)) {
            return error_response('Parameter type count mismatch', 'PARAM_MISMATCH');
        }
        
        $validatedParams = [''];  // Will hold types string
        $allErrors = [];
        
        for ($i = 0; $i < strlen($types); $i++) {
            $type = $types[$i];
            $value = $values[$i] ?? null;
            $maxLen = $opts['max_lengths'][$i] ?? null;
            
            $validation = validate_param($value, $type, $maxLen ? ['max_length' => $maxLen] : []);
            
            if (!$validation['valid']) {
                $allErrors["param_$i"] = $validation['errors'];
            } else {
                $validatedParams[0] .= $type;
                $validatedParams[] = $validation['value'];
            }
        }
        
        if (!empty($allErrors)) {
            secure_log('INFO', 'Parameter validation failed', ['errors' => $allErrors]);
            return error_response('Validation failed', 'VALIDATION_FAILED', $allErrors);
        }
        
        $params = $validatedParams;
    }
    
    // ========================================
    // LAYER 6: QUERY BLACKLIST
    // ========================================
    $blacklistViolation = check_query_blacklist($sql);
    if ($blacklistViolation !== null) {
        return error_response('Query contains forbidden pattern', 'QUERY_BLOCKED');
    }
    
    // ========================================
    // LAYER 7: PREPARED STATEMENT EXECUTION
    // ========================================
    try {
        $conn = get_db();
        $stmt = $conn->prepare($sql);
        
        if ($stmt === false) {
            $error = $conn->error;
            secure_log('ERROR', 'Query preparation failed', [
                'error' => SECURE_QUERY_DEBUG_MODE ? $error : 'hidden'
            ]);
            return error_response(
                SECURE_QUERY_DEBUG_MODE ? "Prepare failed: $error" : 'Database error',
                'PREPARE_FAILED'
            );
        }
        
        // Bind parameters
        if (!empty($params) && strlen($params[0]) > 0) {
            $types = $params[0];
            $values = array_slice($params, 1);
            $stmt->bind_param($types, ...$values);
        }
        
        // Execute
        $result = $stmt->execute();
        
        if (!$result) {
            $error = $stmt->error;
            $stmt->close();
            secure_log('ERROR', 'Query execution failed', [
                'error' => SECURE_QUERY_DEBUG_MODE ? $error : 'hidden'
            ]);
            return error_response(
                SECURE_QUERY_DEBUG_MODE ? "Execute failed: $error" : 'Database error',
                'EXECUTE_FAILED'
            );
        }
        
        // Get results for SELECT queries
        $queryResult = $stmt->get_result();
        $data = [];
        
        if ($queryResult) {
            while ($row = $queryResult->fetch_assoc()) {
                $data[] = $row;
            }
        }
        
        $affectedRows = $conn->affected_rows;
        $insertId = $conn->insert_id;
        $stmt->close();
        
        // ========================================
        // LAYER 8: AUDIT LOGGING
        // ========================================
        $duration = round((microtime(true) - $startTime) * 1000, 2);
        
        if ($opts['log_query']) {
            secure_log('INFO', 'Query executed', [
                'type' => get_query_type($sql),
                'rows' => is_write_query($sql) ? $affectedRows : count($data),
                'duration_ms' => $duration
            ]);
        }
        
        return [
            'success' => true,
            'error' => null,
            'error_code' => null,
            'data' => $data,
            'affected_rows' => $affectedRows,
            'insert_id' => $insertId,
            'duration_ms' => $duration
        ];
        
    } catch (Exception $e) {
        secure_log('CRITICAL', 'Query exception', [
            'error' => SECURE_QUERY_DEBUG_MODE ? $e->getMessage() : 'hidden'
        ]);
        return error_response(
            SECURE_QUERY_DEBUG_MODE ? $e->getMessage() : 'A database error occurred',
            'EXCEPTION'
        );
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function is_write_query(string $sql): bool {
    $writePatterns = '/^\s*(INSERT|UPDATE|DELETE|REPLACE|TRUNCATE|ALTER|DROP|CREATE)/i';
    return (bool)preg_match($writePatterns, trim($sql));
}

function get_query_type(string $sql): string {
    if (preg_match('/^\s*(\w+)/i', trim($sql), $matches)) {
        return strtoupper($matches[1]);
    }
    return 'UNKNOWN';
}

function error_response(string $message, string $code, array $details = []): array {
    return [
        'success' => false,
        'error' => $message,
        'error_code' => $code,
        'error_details' => $details,
        'data' => [],
        'affected_rows' => 0,
        'insert_id' => 0
    ];
}

// ============================================
// BACKWARD COMPATIBILITY - Matches ERP execute_query_d() signature
// ============================================

/**
 * Drop-in replacement for execute_query_d()
 * Use this for gradual migration
 */
function execute_query_d1_compat(string $sql, array $params = [], ?string $role = null): array {
    return execute_query_d1($sql, $params, [
        'require_csrf' => false,  // ERP handles CSRF at page level
        'require_post' => false,  // ERP handles at page level
        'log_query' => true
    ]);
}
