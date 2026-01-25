<?php
// Ensure session is fresh for test
session_id('test_forensic_session_' . time());
require_once __DIR__ . '/include/config.php';

// Simulate Trusted Proxy
$_SERVER['REMOTE_ADDR'] = '127.0.0.1'; 
$_SERVER['HTTP_X_FORWARDED_FOR'] = '192.168.1.50, 10.0.0.9';

echo "1. Testing Luhn Redaction (Real vs Fake)...\n";
$realCC = '4539 1482 0456 7890'; // Valid Visa (dummy generated)
$fakeCC = '1234 5678 1234 5678'; // Invalid Luhn
log_info("CC Test", ['real' => $realCC, 'fake' => $fakeCC]);

echo "2. Testing Truncation Marker...\n";
$hugeData = str_repeat("D", 9000);
log_info("Big Data", ['payload' => $hugeData]);

echo "3. Testing Rotation Bridge...\n";
log_rotate_bridge("app.log.2026-01-26");

echo "\nDone. Checking Logs for GENESIS, Luhn, and BRIDGE:\n";
echo "---------------------------------------------------\n";
echo file_get_contents(LOG_FILE_PATH);
echo "---------------------------------------------------\n";
