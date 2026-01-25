<?php
require_once __DIR__ . '/../include/config.php';

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // Disable nginx buffering

// Log file paths
$logFiles = [
    'app' => LOG_FILE_PATH,
    'security' => SECURITY_LOG_PATH,
    'audit' => AUDIT_LOG_PATH,
    'performance' => PERFORMANCE_LOG_PATH,
    'apache' => __DIR__ . '/../logs/apache/erp_access.log',
    'mysql' => __DIR__ . '/../logs/mysql/slow.log'
];

function get_log_tail($file, $lines = 10) {
    if (!file_exists($file)) return [];
    if (!is_readable($file)) return [];
    
    clearstatcache(true, $file);
    $data = file($file);
    if (empty($data)) return [];
    
    // Filter out reset actions
    $data = array_filter($data, function($line) {
        return strpos($line, 'action=reset_logs') === false && 
               strpos($line, 'reset=success') === false;
    });
    
    if (empty($data)) return [];
    
    return array_slice($data, -$lines);
}

// Send initial data
$logData = [];
foreach ($logFiles as $name => $file) {
    $logData[$name] = get_log_tail($file, 10);
}

echo "data: " . json_encode($logData) . "\n\n";
flush();

// Keep connection alive and send updates every 1 second
while (true) {
    sleep(1);
    
    $logData = [];
    foreach ($logFiles as $name => $file) {
        $logData[$name] = get_log_tail($file, 10);
    }
    
    echo "data: " . json_encode($logData) . "\n\n";
    
    if (ob_get_level() > 0) {
        ob_flush();
    }
    flush();
    
    // Check if connection is still alive
    if (connection_aborted()) {
        break;
    }
}
