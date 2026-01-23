<?php
/**
 * 🛰️ Unified Secure Upload Gateway - Modern UI
 */
require_once __DIR__ . '/Gateway.php';
require_once __DIR__ . '/db.php';
initSecurity();

$result = $_SESSION['last_result'] ?? null;
unset($_SESSION['last_result']);

// Fetch stats for dashboard
function getStats() {
    try {
        $db = getDB();
        $total = $db->query("SELECT COUNT(*) FROM unified_audit")->fetchColumn();
        $rejected = $db->query("SELECT COUNT(*) FROM unified_audit WHERE security_status = 'rejected'")->fetchColumn();
        $sanitized = $db->query("SELECT COUNT(*) FROM unified_audit WHERE security_status = 'sanitized'")->fetchColumn();
        return ['total' => $total, 'rejected' => $rejected, 'sanitized' => $sanitized];
    } catch (Exception $e) {
        return ['total' => 0, 'rejected' => 0, 'sanitized' => 0];
    }
}

// Fetch history from DB
function getHistory() {
    try {
        $db = getDB();
        return $db->query("SELECT * FROM unified_audit ORDER BY created_at DESC LIMIT 8")->fetchAll();
    } catch (Exception $e) {
        return [];
    }
}

$history = getHistory();
$stats = getStats();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Gateway</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #05070a;
            --card: rgba(17, 24, 39, 0.7);
            --primary: #6366f1; /* Indigo */
            --primary-glow: rgba(99, 102, 241, 0.4);
            --success: #10b981;
            --danger: #f43f5e;
            --text: #f9fafb;
            --text-muted: #94a3b8;
            --border: rgba(255, 255, 255, 0.08);
            --glass: rgba(255, 255, 255, 0.03);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            overflow-x: hidden;
            padding: 2rem;
        }

        .container {
            max-width: 900px;
            width: 100%;
        }

        /* Header */
        header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .logo-box {
            display: inline-flex;
            align-items: center;
            gap: 0.75rem;
            background: var(--glass);
            border: 1px solid var(--border);
            padding: 0.5rem 1.25rem;
            border-radius: 999px;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
        }

        .logo-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--success);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        h1 {
            font-size: 2.5rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            margin-bottom: 0.5rem;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.1rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 1.25rem;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(20px);
        }

        .stat-card::after {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(45deg, transparent, rgba(255,255,255,0.02), transparent);
            pointer-events: none;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.875rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stat-value {
            font-size: 2.25rem;
            font-weight: 700;
            margin-top: 0.5rem;
        }

        /* Upload Section */
        .upload-section {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 2rem;
            padding: 3rem;
            margin-bottom: 3rem;
            position: relative;
            backdrop-filter: blur(20px);
        }

        .drop-zone {
            border: 2px dashed var(--border);
            border-radius: 1.5rem;
            padding: 4rem 2rem;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            background: var(--glass);
        }

        .drop-zone:hover {
            border-color: var(--primary);
            background: rgba(99, 102, 241, 0.05);
            transform: translateY(-2px);
        }

        .drop-zone input {
            position: absolute;
            inset: 0;
            opacity: 0;
            width: 100%;
            cursor: pointer;
        }

        .upload-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            display: inline-block;
            filter: drop-shadow(0 0 15px var(--primary-glow));
        }

        .drop-zone h3 {
            font-size: 1.25rem;
            margin-bottom: 0.5rem;
        }

        .drop-zone p {
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        /* Result Panel */
        .result-panel {
            margin-top: 2rem;
            padding: 1.5rem;
            border-radius: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            animation: slideUp 0.4s ease-out;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .result-sanitized { background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success); }
        .result-rejected { background: rgba(244, 63, 94, 0.1); border: 1px solid var(--danger); }

        .result-icon { font-size: 1.5rem; }
        .result-text h4 { font-size: 1rem; margin-bottom: 0.25rem; }
        .result-text p { font-size: 0.875rem; color: var(--text-muted); }

        /* Audit Table */
        .audit-section h3 {
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 700;
        }

        .table-container {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 1.25rem;
            overflow: hidden;
            backdrop-filter: blur(20px);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: rgba(255, 255, 255, 0.02);
            padding: 1rem 1.5rem;
            text-align: left;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.875rem;
        }

        .status-pill {
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }

        .pill-sanitized { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .pill-rejected { background: rgba(244, 63, 94, 0.15); color: #f43f5e; }

        .empty-state {
            padding: 4rem;
            text-align: center;
            color: var(--text-muted);
        }

        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
            .container { padding: 1rem; }
            h1 { font-size: 2rem; }
        }
    </style>
</head>
<body>

    <div class="container">
        <header>
            <div class="logo-box">
                <div class="logo-dot"></div>
                <span style="font-weight: 700; font-size: 0.875rem; letter-spacing: 0.1em; color: var(--text-muted);">ACTIVE PROTECTION</span>
            </div>
            <h1>Unified Security Gateway</h1>
            <p>Advanced cross-engine file sanitization & threat detection</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Inspected</div>
                <div class="stat-value"><?php echo $stats['total']; ?></div>
            </div>
            <div class="stat-card" style="border-bottom: 3px solid var(--success);">
                <div class="stat-label">Sanitized</div>
                <div class="stat-value"><?php echo $stats['sanitized']; ?></div>
            </div>
            <div class="stat-card" style="border-bottom: 3px solid var(--danger);">
                <div class="stat-label">Blocked</div>
                <div class="stat-value"><?php echo $stats['rejected']; ?></div>
            </div>
        </div>

        <div class="upload-section">
            <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
                <div class="drop-zone" id="dropZone">
                    <span class="upload-icon">💠</span>
                    <h3>Secure Upload Portal</h3>
                    <p>PDF, CSV, or Images allowed (Max 10MB)</p>
                    <input type="file" name="file" id="fileInput" onchange="this.form.submit()">
                </div>
            </form>

            <?php if ($result): ?>
                <div class="result-panel result-<?php echo $result['status']; ?>">
                    <div class="result-icon"><?php echo $result['status'] === 'sanitized' ? '✅' : '🛡️'; ?></div>
                    <div class="result-text">
                        <h4><?php echo $result['status'] === 'sanitized' ? 'Security Cleared' : 'Threat Intercepted'; ?></h4>
                        <p><?php echo htmlspecialchars($result['filename']); ?> | <?php echo $result['engine']; ?> Engine</p>
                        <?php if ($result['status'] === 'rejected' && isset($result['error'])): ?>
                            <p style="color: var(--danger); margin-top: 0.25rem;"><strong>Reason:</strong> <?php echo htmlspecialchars($result['error']); ?></p>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div class="protection-capabilities">
            <h3>Protection Capabilities</h3>
            <div class="capabilities-grid">
                <div class="cap-card">
                    <span class="cap-icon">📄</span>
                    <h4>PDF Shield</h4>
                    <p>QPDF Linearization, XRef flattening, and metadata stripping.</p>
                </div>
                <div class="cap-card">
                    <span class="cap-icon">📊</span>
                    <h4>CSV Guard</h4>
                    <p>Formula injection blocking, UTF-8 normalization, and signature scanning.</p>
                </div>
                <div class="cap-card">
                    <span class="cap-icon">🖼️</span>
                    <h4>Image Sentinel</h4>
                    <p>Decode-or-Die sanitization via libvips and metadata removal.</p>
                </div>
                <div class="cap-card">
                    <span class="cap-icon">🔍</span>
                    <h4>Deep Scan</h4>
                    <p>Active content detection and polyglot signature matching.</p>
                </div>
            </div>
        </div>

        <div class="audit-section">
            <h3>Integrity Logs</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Engine</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($history as $row): ?>
                        <tr>
                            <td style="font-weight: 500;"><?php echo htmlspecialchars($row['filename']); ?></td>
                            <td style="color: var(--text-muted);"><?php echo $row['detected_engine']; ?></td>
                            <td>
                                <span class="status-pill pill-<?php echo $row['security_status']; ?>">
                                    <?php echo $row['security_status']; ?>
                                </span>
                            </td>
                            <td style="color: var(--text-muted); font-size: 0.75rem;">
                                <?php echo date('H:i:s', strtotime($row['created_at'])); ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if (empty($history)): ?>
                        <tr>
                            <td colspan="4" class="empty-state">No recent activity detected.</td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <style>
        /* Protection Capabilities Styles */
        .protection-capabilities {
            margin-bottom: 3rem;
        }

        .protection-capabilities h3 {
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 700;
        }

        .capabilities-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.25rem;
        }

        .cap-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 1.25rem;
            padding: 1.25rem;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            backdrop-filter: blur(20px);
            transition: all 0.3s ease;
        }

        .cap-card:hover {
            border-color: var(--primary);
            background: rgba(99, 102, 241, 0.05);
            transform: translateY(-2px);
        }

        .cap-icon {
            font-size: 1.5rem;
            background: var(--glass);
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 10px;
            flex-shrink: 0;
        }

        .cap-card h4 {
            font-size: 0.875rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
            color: var(--text);
        }

        .cap-card p {
            font-size: 0.75rem;
            color: var(--text-muted);
            line-height: 1.4;
        }

        @media (max-width: 640px) {
            .capabilities-grid { grid-template-columns: 1fr; }
        }
    </style>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-over'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-over'), false);
        });

        dropZone.addEventListener('drop', e => {
            fileInput.files = e.dataTransfer.files;
            document.getElementById('uploadForm').submit();
        });
    </script>
</body>
</html>
