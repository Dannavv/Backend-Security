<?php
/**
 * Chapter 7: Demo Dashboard
 * Interactive demonstration of execute_query_d1()
 */

declare(strict_types=1);

require_once __DIR__ . '/../include/functions.php';

set_security_headers();

// Initialize CSRF token
$csrfToken = csrf_ensure_token();

// Handle form submission
$result = null;
$testType = $_POST['test_type'] ?? null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $testType) {
    switch ($testType) {
        case 'valid_select':
            $result = execute_query_d1(
                "SELECT id, name, email, role FROM demo_users WHERE id = ?",
                ['i', (int)($_POST['user_id'] ?? 1)],
                ['require_csrf' => true]
            );
            break;
            
        case 'sql_injection':
            $result = execute_query_d1(
                "SELECT * FROM demo_users WHERE id = ?",
                ['i', $_POST['malicious_input'] ?? '1'],
                ['require_csrf' => true]
            );
            break;
            
        case 'sleep_attack':
            $result = execute_query_d1(
                $_POST['sleep_query'] ?? "SELECT SLEEP(10)",
                [],
                ['require_csrf' => true]
            );
            break;
            
        case 'length_overflow':
            $longValue = str_repeat('A', 70000);
            $result = execute_query_d1(
                "SELECT * FROM demo_users WHERE name = ?",
                ['s', $longValue],
                ['require_csrf' => true]
            );
            break;
    }
}

// Read recent logs
$recentLogs = '';
$logFile = __DIR__ . '/../logs/security.log';
if (file_exists($logFile)) {
    $lines = file($logFile);
    $recentLogs = implode('', array_slice($lines, -8));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chapter 7: Military-Grade Secure Query</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --bg-card-hover: #1a1a25;
            --accent: #00d4ff;
            --accent-glow: rgba(0, 212, 255, 0.3);
            --accent-green: #00ff88;
            --accent-red: #ff4757;
            --accent-yellow: #ffc107;
            --accent-purple: #a855f7;
            --text: #f0f0f5;
            --text-muted: #6b7280;
            --border: rgba(255,255,255,0.08);
            --gradient-1: linear-gradient(135deg, #00d4ff 0%, #00ff88 100%);
            --gradient-2: linear-gradient(135deg, #a855f7 0%, #00d4ff 100%);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        /* Header */
        .header {
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50px;
            left: 50%;
            transform: translateX(-50%);
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
            pointer-events: none;
            opacity: 0.5;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            position: relative;
        }
        
        .header .subtitle {
            color: var(--text-muted);
            font-size: 1rem;
            font-weight: 400;
        }
        
        .header .badge {
            display: inline-block;
            background: var(--gradient-2);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-top: 1rem;
        }
        
        /* Grid Layout */
        .main-grid {
            display: grid;
            grid-template-columns: 400px 1fr;
            gap: 2rem;
        }
        
        @media (max-width: 1024px) {
            .main-grid { grid-template-columns: 1fr; }
        }
        
        /* Cards */
        .card {
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .card:hover {
            border-color: rgba(0, 212, 255, 0.2);
            box-shadow: 0 0 40px rgba(0, 212, 255, 0.05);
        }
        
        .card-header {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .card-header h2 {
            font-size: 1rem;
            font-weight: 600;
        }
        
        .card-header .icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }
        
        .card-body { padding: 1.5rem; }
        
        /* Test Forms */
        .test-form {
            margin-bottom: 1rem;
        }
        
        .test-form:last-child { margin-bottom: 0; }
        
        .test-input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            transition: all 0.2s;
        }
        
        .test-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        
        .test-btn {
            width: 100%;
            padding: 0.875rem 1rem;
            border: none;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .test-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        }
        
        .test-btn:active { transform: translateY(0); }
        
        .btn-valid {
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            color: white;
        }
        
        .btn-attack {
            background: linear-gradient(135deg, #dc2626 0%, #f87171 100%);
            color: white;
        }
        
        .btn-warning {
            background: linear-gradient(135deg, #d97706 0%, #fbbf24 100%);
            color: #1a1a25;
        }
        
        /* Security Layers */
        .layers-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        
        @media (max-width: 768px) {
            .layers-grid { grid-template-columns: 1fr; }
        }
        
        .layer-item {
            background: var(--bg-dark);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            gap: 1rem;
            transition: all 0.2s;
            border: 1px solid transparent;
        }
        
        .layer-item:hover {
            border-color: var(--border);
            background: var(--bg-card-hover);
        }
        
        .layer-num {
            width: 28px;
            height: 28px;
            min-width: 28px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 700;
            color: white;
        }
        
        .layer-1 { background: linear-gradient(135deg, #3b82f6, #60a5fa); }
        .layer-2 { background: linear-gradient(135deg, #8b5cf6, #a78bfa); }
        .layer-3 { background: linear-gradient(135deg, #ec4899, #f472b6); }
        .layer-4 { background: linear-gradient(135deg, #f59e0b, #fbbf24); }
        .layer-5 { background: linear-gradient(135deg, #10b981, #34d399); }
        .layer-6 { background: linear-gradient(135deg, #ef4444, #f87171); }
        .layer-7 { background: linear-gradient(135deg, #06b6d4, #22d3ee); }
        .layer-8 { background: linear-gradient(135deg, #6366f1, #818cf8); }
        
        .layer-content h4 {
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .layer-content p {
            font-size: 0.75rem;
            color: var(--text-muted);
            line-height: 1.5;
        }
        
        /* Validation Rules */
        .rules-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }
        
        .rule-card {
            background: var(--bg-dark);
            border-radius: 12px;
            padding: 1rem;
            border: 1px solid var(--border);
        }
        
        .rule-card .rule-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }
        
        .rule-card .type-name {
            font-weight: 600;
            color: var(--accent);
        }
        
        .rule-card .type-code {
            background: rgba(0, 212, 255, 0.1);
            color: var(--accent);
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
        }
        
        .rule-card ul {
            list-style: none;
        }
        
        .rule-card li {
            font-size: 0.75rem;
            color: var(--text-muted);
            padding: 0.25rem 0;
            display: flex;
            gap: 0.5rem;
        }
        
        .rule-card li::before {
            content: '✓';
            color: var(--accent-green);
        }
        
        /* Result Box */
        .result-box {
            background: var(--bg-dark);
            border-radius: 12px;
            padding: 1.25rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--border);
        }
        
        .result-box.success {
            border-left: 4px solid var(--accent-green);
        }
        
        .result-box.error {
            border-left: 4px solid var(--accent-red);
        }
        
        /* Logs */
        .logs-box {
            background: var(--bg-dark);
            border-radius: 12px;
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            overflow-x: auto;
            white-space: pre;
            max-height: 180px;
            overflow-y: auto;
            color: var(--text-muted);
            line-height: 1.8;
            border: 1px solid var(--border);
        }
        
        /* Status indicator */
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 0.5rem;
            animation: pulse 2s infinite;
        }
        
        .status-dot.online { background: var(--accent-green); }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-dark); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
        
        .full-width { grid-column: 1 / -1; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>🛡️ Military-Grade Secure Query</h1>
            <p class="subtitle">Chapter 7: execute_query_d1() — 8-Layer Security Gateway</p>
        </header>
        
        <div class="main-grid">
            <!-- Left Column: Test Cases -->
            <div>
                <div class="card">
                    <div class="card-header">
                        <div class="icon" style="background: linear-gradient(135deg, #10b981, #34d399);">🧪</div>
                        <h2>Attack Simulator</h2>
                    </div>
                    <div class="card-body">
                        <form method="POST" class="test-form">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <input type="hidden" name="test_type" value="valid_select">
                            <input type="number" name="user_id" value="1" min="1" max="10" class="test-input" placeholder="User ID">
                            <button type="submit" class="test-btn btn-valid">✓ Valid SELECT Query</button>
                        </form>
                        
                        <form method="POST" class="test-form">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <input type="hidden" name="test_type" value="sql_injection">
                            <input type="text" name="malicious_input" value="1 OR 1=1" class="test-input">
                            <button type="submit" class="test-btn btn-attack">⚠ SQL Injection Attack</button>
                        </form>
                        
                        <form method="POST" class="test-form">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <input type="hidden" name="test_type" value="sleep_attack">
                            <input type="text" name="sleep_query" value="SELECT SLEEP(10)" class="test-input">
                            <button type="submit" class="test-btn btn-attack">⏱ Time-Based Attack</button>
                        </form>
                        
                        <form method="POST" class="test-form">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <input type="hidden" name="test_type" value="length_overflow">
                            <button type="submit" class="test-btn btn-warning">📏 70,000 Char Overflow</button>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Right Column: Security Layers -->
            <div>
                <div class="card">
                    <div class="card-header">
                        <div class="icon" style="background: linear-gradient(135deg, #6366f1, #818cf8);">🔐</div>
                        <h2>Security Layers</h2>
                    </div>
                    <div class="card-body">
                        <div class="layers-grid">
                            <div class="layer-item">
                                <div class="layer-num layer-1">1</div>
                                <div class="layer-content">
                                    <h4>POST Enforcement</h4>
                                    <p>Blocks GET for write operations. Prevents CSRF via URL sharing.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-2">2</div>
                                <div class="layer-content">
                                    <h4>CSRF Validation</h4>
                                    <p>Cryptographic token ensures request from your site only.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-3">3</div>
                                <div class="layer-content">
                                    <h4>Rate Limiting</h4>
                                    <p>100 queries/IP/min. Stops brute-force and DoS attacks.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-4">4</div>
                                <div class="layer-content">
                                    <h4>Param Count</h4>
                                    <p>Max 50 params. Blocks pollution and memory exhaustion.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-5">5</div>
                                <div class="layer-content">
                                    <h4>Input Validation</h4>
                                    <p>Type/length/encoding checks. Null-byte removal.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-6">6</div>
                                <div class="layer-content">
                                    <h4>Query Blacklist</h4>
                                    <p>Blocks SLEEP, BENCHMARK, schema enumeration.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-7">7</div>
                                <div class="layer-content">
                                    <h4>Prepared Statement</h4>
                                    <p>Parameterized queries separate code from data.</p>
                                </div>
                            </div>
                            <div class="layer-item">
                                <div class="layer-num layer-8">8</div>
                                <div class="layer-content">
                                    <h4>Error Masking</h4>
                                    <p>Safe messages to users. Detailed audit logs.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Validation Rules -->
            <div class="card full-width">
                <div class="card-header">
                    <div class="icon" style="background: linear-gradient(135deg, #f59e0b, #fbbf24);">📋</div>
                    <h2>Validation Rules (Layer 5)</h2>
                </div>
                <div class="card-body">
                    <div class="rules-grid">
                        <?php foreach (get_validation_rules() as $type => $rule): ?>
                        <div class="rule-card">
                            <div class="rule-header">
                                <span class="type-name"><?= htmlspecialchars($rule['name']) ?></span>
                                <span class="type-code"><?= $type ?></span>
                            </div>
                            <ul>
                                <?php foreach (array_slice($rule['checks'], 0, 4) as $desc): ?>
                                <li><?= htmlspecialchars($desc) ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            
            <!-- Result -->
            <div class="card full-width">
                <div class="card-header">
                    <div class="icon" style="background: linear-gradient(135deg, #06b6d4, #22d3ee);">📊</div>
                    <h2>Result</h2>
                </div>
                <div class="card-body">
                    <?php if ($result !== null): ?>
                        <div class="result-box <?= $result['success'] ? 'success' : 'error' ?>">
<?= htmlspecialchars(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?>
                        </div>
                    <?php else: ?>
                        <div class="result-box">Click a test button to see results...</div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Logs -->
            <div class="card full-width">
                <div class="card-header">
                    <div class="icon" style="background: linear-gradient(135deg, #ec4899, #f472b6);">📝</div>
                    <h2>Security Audit Log</h2>
                </div>
                <div class="card-body">
                    <div class="logs-box"><?= htmlspecialchars($recentLogs ?: 'No security events logged yet...') ?></div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
