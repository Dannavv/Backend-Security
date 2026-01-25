<?php
require_once __DIR__ . '/include/config.php';

echo "Testing Logging Engine...\n";

log_info("System self-test started");
log_security("Test security event", ['trigger' => 'cli_test']);
log_audit("Test audit event", ['action' => 'verify_logging']);
log_error("Test error event");

$files = [LOG_FILE_PATH, SECURITY_LOG_PATH, AUDIT_LOG_PATH];

foreach ($files as $file) {
    if (file_exists($file)) {
        echo "[SUCCESS] File created: " . basename($file) . " (" . filesize($file) . " bytes)\n";
        // Show last line
        $lines = file($file);
        echo "   Last entry: " . trim(end($lines)) . "\n";
    } else {
        echo "[FAILURE] File missing: " . basename($file) . "\n";
    }
}
