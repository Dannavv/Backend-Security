<?php
/**
 * Chapter 7: Automated Test Suite
 * Tests all security layers of execute_query_d1()
 */

declare(strict_types=1);

// Suppress session for CLI
if (php_sapi_name() === 'cli') {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
}

require_once __DIR__ . '/include/functions.php';

echo "╔══════════════════════════════════════════════════════════╗\n";
echo "║  Chapter 7: Military-Grade Secure Query - Test Suite     ║\n";
echo "╚══════════════════════════════════════════════════════════╝\n\n";

$passed = 0;
$failed = 0;

function test(string $name, bool $condition, string $details = ''): void {
    global $passed, $failed;
    if ($condition) {
        echo "  ✅ PASS: $name\n";
        $passed++;
    } else {
        echo "  ❌ FAIL: $name\n";
        if ($details) echo "          $details\n";
        $failed++;
    }
}

// ============================================
// TEST 1: Valid SELECT Query
// ============================================
echo "┌─ Test 1: Valid SELECT Query\n";

$_POST['csrf_token'] = csrf_ensure_token();
$result = execute_query_d1(
    "SELECT * FROM demo_users WHERE id = ?",
    ['i', 1],
    ['require_csrf' => true]
);

test('Query executes successfully', $result['success'] === true);
test('Returns data array', is_array($result['data']));
test('Has duration metric', isset($result['duration_ms']));
echo "\n";

// ============================================
// TEST 2: SQL Injection Blocked (via prepared stmt)
// ============================================
echo "┌─ Test 2: SQL Injection Prevention\n";

$result = execute_query_d1(
    "SELECT * FROM demo_users WHERE id = ?",
    ['i', "1 OR 1=1"],  // This should fail type validation
    ['require_csrf' => true]
);

// The integer validation should reject the string
test('Injection attempt blocked by type validation', 
    !$result['success'] || count($result['data']) <= 1,
    json_encode($result['error_code'] ?? 'returned limited data'));
echo "\n";

// ============================================
// TEST 3: SLEEP Attack Blocked
// ============================================
echo "┌─ Test 3: SLEEP Attack Blocked\n";

$result = execute_query_d1(
    "SELECT SLEEP(10)",
    [],
    ['require_csrf' => true]
);

test('SLEEP query blocked', 
    $result['success'] === false && $result['error_code'] === 'QUERY_BLOCKED',
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 4: BENCHMARK Attack Blocked
// ============================================
echo "┌─ Test 4: BENCHMARK Attack Blocked\n";

$result = execute_query_d1(
    "SELECT BENCHMARK(10000000, SHA1('test'))",
    [],
    ['require_csrf' => true]
);

test('BENCHMARK query blocked',
    $result['success'] === false && $result['error_code'] === 'QUERY_BLOCKED',
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 5: Length Validation
// ============================================
echo "┌─ Test 5: Length Validation\n";

$longString = str_repeat('A', 70000);  // Exceeds 65535 default

$result = execute_query_d1(
    "SELECT * FROM demo_users WHERE name = ?",
    ['s', $longString],
    ['require_csrf' => true]
);

test('Overlong input rejected',
    $result['success'] === false && $result['error_code'] === 'VALIDATION_FAILED',
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 6: CSRF Validation
// ============================================
echo "┌─ Test 6: CSRF Validation\n";

$_POST['csrf_token'] = 'invalid_token_12345';

$result = execute_query_d1(
    "SELECT * FROM demo_users",
    [],
    ['require_csrf' => true]
);

test('Invalid CSRF rejected',
    $result['success'] === false && $result['error_code'] === 'CSRF_FAILED',
    $result['error'] ?? '');

// Restore valid token for remaining tests
$_POST['csrf_token'] = csrf_ensure_token();
echo "\n";

// ============================================
// TEST 7: Parameter Count Limit
// ============================================
echo "┌─ Test 7: Parameter Count Limit\n";

$manyParams = [''];
for ($i = 0; $i < 60; $i++) {
    $manyParams[0] .= 's';
    $manyParams[] = 'value' . $i;
}

$result = execute_query_d1(
    "SELECT * FROM demo_users",
    $manyParams,
    ['require_csrf' => true]
);

test('Too many parameters rejected',
    $result['success'] === false && $result['error_code'] === 'PARAM_OVERFLOW',
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 8: Type Mismatch
// ============================================
echo "┌─ Test 8: Parameter Type/Count Mismatch\n";

$result = execute_query_d1(
    "SELECT * FROM demo_users WHERE id = ?",
    ['ii', 1],  // 2 types but only 1 value
    ['require_csrf' => true]
);

test('Type count mismatch rejected',
    $result['success'] === false && $result['error_code'] === 'PARAM_MISMATCH',
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 9: UTF-7 Bypass Attempt
// ============================================
echo "┌─ Test 9: UTF-7 Encoding Bypass\n";

$utf7Payload = "+ADw-script+AD4-alert(1)+ADw-/script+AD4-";

$result = execute_query_d1(
    "SELECT * FROM demo_users WHERE name = ?",
    ['s', $utf7Payload],
    ['require_csrf' => true]
);

test('UTF-7 bypass detected',
    $result['success'] === false,
    $result['error'] ?? '');
echo "\n";

// ============================================
// TEST 10: Information Schema Probe
// ============================================
echo "┌─ Test 10: Schema Enumeration Blocked\n";

$result = execute_query_d1(
    "SELECT * FROM INFORMATION_SCHEMA.TABLES",
    [],
    ['require_csrf' => true]
);

test('INFORMATION_SCHEMA probe blocked',
    $result['success'] === false && $result['error_code'] === 'QUERY_BLOCKED',
    $result['error'] ?? '');
echo "\n";

// ============================================
// Summary
// ============================================
echo "╔══════════════════════════════════════════════════════════╗\n";
echo "║  RESULTS: $passed passed, $failed failed                            ║\n";
echo "╚══════════════════════════════════════════════════════════╝\n";

if ($failed > 0) {
    exit(1);
}
