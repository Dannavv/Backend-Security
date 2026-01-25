<?php
require_once __DIR__ . '/../include/config.php';

// Log definitions
define('APACHE_ACCESS_LOG', __DIR__ . '/../logs/apache/erp_access.log');
define('MYSQL_SLOW_LOG', __DIR__ . '/../logs/mysql/slow.log');

// Simulate some application logic
$action = $_GET['action'] ?? 'view';
$message = null;

if (isset($_GET['reset']) && $_GET['reset'] === 'success') {
    $message = "Logs successfully cleared! Starting fresh.";
}

// 🛢️ Database connection for slow query testing
function get_db_conn() {
    $host = getenv('DB_HOST') ?: 'mysql_db';
    $name = getenv('DB_NAME') ?: 'erp_db';
    $user = getenv('DB_USER') ?: 'erp_user';
    $pass = getenv('DB_PASS') ?: 'erp_password';
    
    try {
        return new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 10
        ]);
    } catch (PDOException $e) {
        log_error("DB connection failed for slow query test", ['error' => $e->getMessage()]);
        return null;
    }
}

switch ($action) {
    // === SECURITY EVENTS ===
    case 'login_fail':
        log_security("Failed login attempt", ['username' => 'admin', 'attempts' => 5, 'ip' => $_SERVER['REMOTE_ADDR']]);
        $message = "Security: Failed login attempt logged (5 attempts on 'admin')";
        break;
    
    case 'brute_force':
        log_security("Brute force attack detected", [
            'username' => 'root', 
            'attempts' => 50, 
            'timeframe' => '60 seconds',
            'action' => 'IP temporarily blocked'
        ]);
        $message = "Security: Brute force attack detected and blocked";
        break;
    
    case 'sql_injection':
        log_security("SQL injection attempt detected", [
            'payload' => "' OR '1'='1", 
            'endpoint' => '/api/users',
            'blocked' => true
        ]);
        $message = "Security: SQL injection attempt blocked";
        break;
    
    case 'suspicious_file':
        log_security("Suspicious file upload attempt", [
            'filename' => 'shell.php.jpg',
            'mime_type' => 'application/x-php',
            'user_id' => 'guest_user',
            'action' => 'rejected'
        ]);
        $message = "Security: Malicious file upload attempt rejected";
        break;
    
    // === AUDIT EVENTS ===
    case 'data_change':
        log_audit("Student record modified", [
            'student_id' => 123, 
            'field' => 'grade', 
            'old' => 'B', 
            'new' => 'A',
            'modified_by' => 'teacher_john'
        ]);
        $message = "Audit: Student grade change recorded";
        break;
    
    case 'permission_change':
        log_audit("User permissions elevated", [
            'user_id' => 456,
            'username' => 'jane_doe',
            'old_role' => 'student',
            'new_role' => 'admin',
            'granted_by' => 'system_admin'
        ]);
        $message = "Audit: User permission elevation logged";
        break;
    
    case 'data_export':
        log_audit("Sensitive data exported", [
            'export_type' => 'student_records',
            'record_count' => 1500,
            'format' => 'CSV',
            'exported_by' => 'principal_smith',
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        $message = "Audit: Data export activity recorded";
        break;
    
    case 'config_change':
        log_audit("System configuration modified", [
            'setting' => 'max_upload_size',
            'old_value' => '10MB',
            'new_value' => '50MB',
            'changed_by' => 'admin_user'
        ]);
        $message = "Audit: Configuration change logged";
        break;
    
    // === PERFORMANCE EVENTS ===
    case 'slow_query':
        $pdo = get_db_conn();
        if ($pdo) {
            $start = microtime(true);
            $pdo->query("SELECT SLEEP(2.5)");
            $duration = microtime(true) - $start;
            log_performance("Slow database operation detected", [
                'duration' => round($duration, 3), 
                'query' => 'SELECT SLEEP(2.5)',
                'threshold' => '2.0s'
            ]);
            $message = "Performance: Real MySQL slow query logged (2.5s)";
        } else {
            $message = "Error: Database connection failed";
        }
        break;
    
    case 'memory_spike':
        $memory_usage = memory_get_usage(true) / 1024 / 1024;
        log_performance("High memory usage detected", [
            'current_usage' => round($memory_usage, 2) . 'MB',
            'peak_usage' => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . 'MB',
            'threshold' => '128MB',
            'process' => 'report_generation'
        ]);
        $message = "Performance: Memory spike logged";
        break;
    
    case 'api_timeout':
        log_performance("External API timeout", [
            'api_endpoint' => 'https://payment-gateway.example.com/process',
            'timeout' => '30s',
            'retry_count' => 3,
            'status' => 'failed'
        ]);
        $message = "Performance: API timeout logged";
        break;
    
    // === ERROR EVENTS ===
    case 'error':
        log_error("Failed to connect to external API", [
            'api' => 'payment_gateway', 
            'response_code' => 500,
            'error_message' => 'Internal Server Error'
        ]);
        $message = "Error: API failure logged";
        break;
    
    case 'file_not_found':
        log_error("Required file missing", [
            'file' => '/uploads/student_photo_123.jpg',
            'requested_by' => 'profile_page',
            'fallback' => 'default_avatar.jpg'
        ]);
        $message = "Error: File not found error logged";
        break;
    
    case 'validation_error':
        log_error("Data validation failed", [
            'field' => 'email',
            'value' => 'invalid-email-format',
            'rule' => 'valid_email',
            'form' => 'student_registration'
        ]);
        $message = "Error: Validation error logged";
        break;
    
    case 'db_connection_fail':
        log_error("Database connection lost", [
            'host' => 'mysql_db',
            'port' => 3306,
            'error' => 'Connection timeout',
            'retry_attempt' => 1
        ]);
        $message = "Error: Database connection failure logged";
        break;

    case 'exception':
        throw new Exception("This is a simulated uncaught exception!");

    case 'reset_logs':
        $logFiles = [
            'App' => LOG_FILE_PATH, 
            'Security' => SECURITY_LOG_PATH, 
            'Audit' => AUDIT_LOG_PATH, 
            'Performance' => PERFORMANCE_LOG_PATH,
            'Apache' => APACHE_ACCESS_LOG,
            'MySQL' => MYSQL_SLOW_LOG
        ];
        $cleared = [];
        $failed = [];
        foreach ($logFiles as $name => $file) {
            if (file_exists($file)) {
                if (is_writable($file)) {
                    if (file_put_contents($file, "") !== false) {
                        $cleared[] = $name;
                    } else {
                        $failed[] = "$name (Write failed)";
                    }
                } else {
                    $failed[] = "$name (Not writable: " . substr(sprintf('%o', fileperms($file)), -4) . ")";
                }
            } else {
                $failed[] = "$name (Not found at " . basename($file) . ")";
            }
        }
        if (empty($failed)) {
            header("Location: index.php?reset=success");
            exit;
        }
        $message = "Reset. Cleared: " . (empty($cleared) ? "None" : implode(", ", $cleared));
        if (!empty($failed)) {
            $message .= " | Failed: " . implode(", ", $failed);
        }
        break;

    default:
        log_info("Dashboard viewed");
        $message = "Welcome to the Military-Grade Logging Dashboard.";
        break;
}

// Get the last few lines from logs for display
function get_last_logs($file, $lines = 10) {
    if (!file_exists($file)) return "File not found: " . basename($file);
    if (!is_readable($file)) return "Access Denied: " . basename($file);
    
    // Force file system sync for Apache logs
    if (strpos($file, 'apache') !== false || strpos($file, 'mysql') !== false) {
        clearstatcache(true, $file);
    }
    
    $data = file($file);
    if (empty($data)) return "Log file is empty.";
    
    // Filter out the "Reset" action noise to keep the UI clean
    $data = array_filter($data, function($line) {
        return strpos($line, 'action=reset_logs') === false && 
               strpos($line, 'reset=success') === false;
    });

    if (empty($data)) return "Log file is empty.";

    // Show more lines for Apache logs since they lag behind
    $actualLines = (strpos($file, 'apache') !== false) ? $lines + 2 : $lines;
    $last_lines = array_slice($data, -$actualLines);
    return implode("", $last_lines);
}

// Force output buffering flush at the end
register_shutdown_function(function() {
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
});

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERP Logging Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --primary: #38bdf8;
            --accent: #c084fc;
            --success: #4ade80;
            --warning: #fbbf24;
            --error: #f87171;
            --security: #f472b6;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }

        .header {
            background: var(--card-bg);
            border-bottom: 2px solid #334155;
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            align-items: center;
            gap: 1rem;
        }

        h1 {
            color: var(--primary);
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
        }

        .header-status {
            text-align: center;
            padding: 0.5rem 1rem;
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid var(--primary);
            border-radius: 6px;
            font-size: 0.85rem;
        }

        .header-status b {
            color: var(--primary);
        }

        .header-status small {
            display: block;
            margin-top: 0.25rem;
            color: #94a3b8;
            font-size: 0.75rem;
        }

        .header-actions {
            display: flex;
            justify-content: flex-end;
        }

        .header-reset-btn {
            background: #64748b;
            color: white;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
            border: none;
            font-size: 0.9rem;
            transition: all 0.2s;
            white-space: nowrap;
        }

        .header-reset-btn:hover {
            background: #475569;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(100, 116, 139, 0.3);
        }

        .layout {
            display: flex;
            height: calc(100vh - 80px);
            overflow: hidden;
        }

        .sidebar {
            width: 280px;
            min-width: 280px;
            background: var(--card-bg);
            border-right: 2px solid #334155;
            padding: 1rem;
            overflow-y: auto;
            overflow-x: hidden;
        }

        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: #1e293b;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }

        .sidebar h2 {
            color: var(--primary);
            font-size: 1rem;
            margin-top: 0;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #334155;
        }

        .main-content {
            flex: 1;
            padding: 1.5rem 2rem;
            overflow-y: auto;
            overflow-x: hidden;
        }

        .action-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, #1a2332 100%);
            padding: 0.875rem;
            border-radius: 8px;
            border: 1px solid #334155;
            margin-bottom: 0.875rem;
            transition: all 0.2s;
        }

        .action-card:hover {
            transform: translateX(4px);
            border-color: var(--primary);
            box-shadow: -3px 0 0 var(--primary);
        }

        .action-card h3 {
            margin: 0 0 0.4rem 0;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .action-card p {
            margin: 0 0 0.625rem 0;
            font-size: 0.75rem;
            color: #94a3b8;
            line-height: 1.3;
        }

        .btn {
            display: block;
            width: auto;
            background: var(--primary);
            color: #0f172a;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
            border: none;
            text-align: center;
            transition: all 0.2s;
            font-size: 0.8rem;
            margin-bottom: 0.5rem;
        }

        .btn:last-child {
            margin-bottom: 0;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3);
        }

        .btn-security { background: var(--security); }
        .btn-security:hover { box-shadow: 0 4px 12px rgba(244, 114, 182, 0.3); }
        
        .btn-audit { background: var(--accent); }
        .btn-audit:hover { box-shadow: 0 4px 12px rgba(192, 132, 252, 0.3); }
        
        .btn-perf { background: var(--warning); }
        .btn-perf:hover { box-shadow: 0 4px 12px rgba(251, 191, 36, 0.3); }
        
        .btn-error { background: var(--error); }
        .btn-error:hover { box-shadow: 0 4px 12px rgba(248, 113, 113, 0.3); }
        
        .btn-reset { background: #64748b; color: white; }
        .btn-reset:hover { box-shadow: 0 4px 12px rgba(100, 116, 139, 0.3); }

        .log-vessel {
            margin-bottom: 1.5rem;
            background: #000;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid #334155;
            display: flex;
            flex-direction: column;
        }

        .log-vessel:first-child {
            margin-top: 0;
        }

        pre {
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            margin: 0;
            color: #cbd5e1;
            overflow-x: auto;
            white-space: pre;
            padding-bottom: 0.5rem;
        }

        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
            background: rgba(0, 0, 0, 0.3);
            box-shadow: inset 0 0 0 2px #9e9e9e;
            padding: 0.5rem;
            border-radius: 4px;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .log-header-left {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .log-header-right {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .log-timestamp {
            font-size: 0.7rem;
            color: #64748b;
            font-style: italic;
        }

        .badge {
            font-size: 0.7rem;
            text-transform: uppercase;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }

        .status-msg {
            background: rgba(56, 189, 248, 0.1);
            color: var(--primary);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border: 1px dashed var(--primary);
        }

        .logs-title {
            color: var(--primary);
            font-size: 1.2rem;
            margin-top: 0;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧠 ERP Logging System <span class="badge" style="background: var(--primary); color: #000;">Level 2</span></h1>
        
        <?php if (isset($message)): ?>
            <div class="header-status">
                <b><?php echo htmlspecialchars($message); ?></b>
                <small>Request ID: <?php echo REQUEST_ID; ?></small>
            </div>
        <?php else: ?>
            <div></div>
        <?php endif; ?>
        
        <div class="header-actions">
            <a href="?action=reset_logs" class="header-reset-btn">🧹 Reset All Logs</a>
        </div>
    </div>

    <div class="layout">
        <!-- Left Sidebar: Action Buttons -->
        <div class="sidebar">
            <h2>⚡ Actions</h2>
            
            <div class="action-card">
                <h3>🔒 Security Events</h3>
                <p>Simulate authentication failures and attack attempts</p>
                <a href="?action=login_fail" class="btn btn-security">Failed Login</a>
                <a href="?action=brute_force" class="btn btn-security">Brute Force Attack</a>
                <a href="?action=sql_injection" class="btn btn-security">SQL Injection</a>
                <a href="?action=suspicious_file" class="btn btn-security">Malicious Upload</a>
            </div>

            <div class="action-card">
                <h3>📝 Audit Trail</h3>
                <p>Track data changes and administrative actions</p>
                <a href="?action=data_change" class="btn btn-audit">Grade Change</a>
                <a href="?action=permission_change" class="btn btn-audit">Permission Elevation</a>
                <a href="?action=data_export" class="btn btn-audit">Data Export</a>
                <a href="?action=config_change" class="btn btn-audit">Config Change</a>
            </div>

            <div class="action-card">
                <h3>⚡ Performance</h3>
                <p>Monitor slow queries and resource usage</p>
                <a href="?action=slow_query" class="btn btn-perf">Slow Query (2.5s)</a>
                <a href="?action=memory_spike" class="btn btn-perf">Memory Spike</a>
                <a href="?action=api_timeout" class="btn btn-perf">API Timeout</a>
            </div>

            <div class="action-card">
                <h3>⚠️ Error Events</h3>
                <p>Capture application errors and failures</p>
                <a href="?action=error" class="btn btn-error">API Failure</a>
                <a href="?action=file_not_found" class="btn btn-error">File Not Found</a>
                <a href="?action=validation_error" class="btn btn-error">Validation Error</a>
                <a href="?action=db_connection_fail" class="btn btn-error">DB Connection Lost</a>
            </div>
        </div>

        <!-- Right Main Content: Logs -->
        <div class="main-content">
            <h2 class="logs-title">🕵️ Real-time Log View (Tail)</h2>

            <div class="log-vessel">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>app.log</b>
                        <span class="badge" style="background: var(--success); color: #000;">General</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(LOG_FILE_PATH)); ?></pre>
            </div>

            <div class="log-vessel">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>security.log</b>
                        <span class="badge" style="background: var(--security); color: #000;">Critical</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(SECURITY_LOG_PATH)); ?></pre>
            </div>

            <div class="log-vessel" style="border-color: var(--accent);">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>audit.log</b>
                        <span class="badge" style="background: var(--accent); color: #000;">History</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(AUDIT_LOG_PATH)); ?></pre>
            </div>

            <div class="log-vessel" style="border-color: var(--warning);">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>performance.log (Runtime Stats)</b>
                        <span class="badge" style="background: var(--warning); color: #000;">Performance</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(PERFORMANCE_LOG_PATH)); ?></pre>
            </div>

            <div class="log-vessel" style="border-color: #94a3b8;">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>apache/erp_access.log (Forensic)</b>
                        <span class="badge" style="background: #94a3b8; color: #000;">Infrastructure</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(APACHE_ACCESS_LOG)); ?></pre>
            </div>

            <div class="log-vessel" style="border-color: var(--error);">
                <div class="log-header">
                    <div class="log-header-left">
                        <b>mysql/slow.log (Database Latency)</b>
                        <span class="badge" style="background: var(--error); color: #000;">Database</span>
                    </div>
                    <div class="log-header-right">
                        <span class="log-timestamp">Updated: <?php echo date('H:i:s'); ?></span>
                    </div>
                </div>
                <pre><?php echo htmlspecialchars(get_last_logs(MYSQL_SLOW_LOG)); ?></pre>
            </div>
        </div>
    </div>

    <script>
        // Real-time log streaming using Server-Sent Events
        let eventSource = null;
        let updateInterval = null;
        
        function startLogStream() {
            if (eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource('stream_logs.php');
            
            eventSource.onmessage = function(event) {
                const logs = JSON.parse(event.data);
                
                // Update each log section
                updateLog('app', logs.app);
                updateLog('security', logs.security);
                updateLog('audit', logs.audit);
                updateLog('performance', logs.performance);
                updateLog('apache', logs.apache);
                updateLog('mysql', logs.mysql);
                
                // Update timestamps
                const now = new Date();
                const timeStr = now.toTimeString().split(' ')[0];
                document.querySelectorAll('.log-timestamp').forEach(el => {
                    el.textContent = 'Updated: ' + timeStr;
                });
            };
            
            eventSource.onerror = function() {
                console.error('EventSource failed, retrying...');
            };
        }
        
        function updateLog(name, lines) {
            const logMap = {
                'app': 0,
                'security': 1,
                'audit': 2,
                'performance': 3,
                'apache': 4,
                'mysql': 5
            };
            
            const index = logMap[name];
            if (index === undefined) return;
            
            const preElement = document.querySelectorAll('.log-vessel pre')[index];
            if (!preElement) return;
            
            if (!lines || lines.length === 0) {
                preElement.textContent = 'Log file is empty.';
            } else {
                preElement.textContent = lines.join('');
            }
        }
        
        // Check if we just performed an action
        const urlParams = new URLSearchParams(window.location.search);
        const action = urlParams.get('action');
        
        if (action && action !== 'view') {
            // Action was just performed, wait 1 second for logs to be written
            setTimeout(() => {
                startLogStream();
            }, 1000);
        } else {
            // No action, start streaming immediately
            startLogStream();
        }
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (eventSource) {
                eventSource.close();
            }
        });
    </script>
</body>
</html>
