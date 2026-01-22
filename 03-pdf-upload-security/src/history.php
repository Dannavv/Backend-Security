<?php
require_once __DIR__ . '/app.php';
initSecurity();

$db = getDB();
$stmt = $db->query("SELECT * FROM pdf_audit ORDER BY created_at DESC LIMIT 50");
$logs = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Audit Logs | PDF Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f1f5f9;
            --primary: #8b5cf6;
            --success: #22c55e;
            --danger: #ef4444;
        }
        body { font-family: 'Outfit', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { margin-bottom: 2rem; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card);
            border-radius: 16px;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05);
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        th { background: rgba(255,255,255,0.05); color: #94a3b8; font-weight: 400; font-size: 0.85rem; }
        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .status-accepted { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
        .status-rejected { background: rgba(239, 68, 68, 0.2); color: #f87171; }
        .findings { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #94a3b8; }
        .back-link { margin-bottom: 1rem; display: inline-block; color: var(--primary); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.php" class="back-link">← Back to Dashboard</a>
        <h1>Security Audit Logs</h1>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Filename</th>
                    <th>Hash (SHA-256)</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>IP</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                <tr>
                    <td style="font-size: 0.8rem;"><?= $log['created_at'] ?></td>
                    <td><?= htmlspecialchars($log['filename']) ?></td>
                    <td style="font-family: 'JetBrains Mono'; font-size: 0.7rem; color: #94a3b8;">
                        <?= $log['file_hash'] ? substr($log['file_hash'], 0, 12) . '...' : 'N/A' ?>
                    </td>
                    <td>
                        <span class="status-badge status-<?= $log['status'] ?>">
                            <?= strtoupper($log['status']) ?>
                        </span>
                    </td>
                    <td class="findings">
                        <?php 
                        $f = json_decode($log['security_findings'], true);
                        if (empty($f)) echo "None (Clean)";
                        else {
                            foreach($f as $finding) echo "• " . htmlspecialchars($finding) . "<br>";
                        }
                        ?>
                    </td>
                    <td style="font-size: 0.8rem;"><?= $log['ip_address'] ?></td>
                </tr>
                <?php endforeach; ?>

            </tbody>
        </table>
    </div>
</body>
</html>
