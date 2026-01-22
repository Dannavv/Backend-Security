<?php
require_once __DIR__ . '/app.php';
initSecurity();

$db = getDB();
$stmt = $db->query("SELECT * FROM image_audit ORDER BY created_at DESC LIMIT 50");
$logs = $stmt->fetchAll();

$stmt = $db->query("SELECT * FROM uploaded_images ORDER BY created_at DESC LIMIT 20");
$images = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Logs | Image Shield</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #f43f5e;
            --secondary: #ec4899;
            --bg: #0b0f19;
            --card-bg: #161b2a;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        header { margin-bottom: 3rem; }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .back-link { color: var(--primary); text-decoration: none; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }

        .card {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 2rem;
            border: 1px solid rgba(255,255,255,0.05);
            margin-bottom: 2rem;
            overflow: hidden;
        }

        .section-title { font-size: 1.5rem; font-weight: 600; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.75rem; }

        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th { text-align: left; padding: 1rem; color: var(--text-dim); border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 0.9rem; }
        td { padding: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.95rem; }

        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 99px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-safe { background: rgba(16, 185, 129, 0.1); color: var(--success); }
        .badge-sanitized { background: rgba(245, 158, 11, 0.1); color: var(--warning); }
        .badge-rejected { background: rgba(239, 68, 68, 0.1); color: var(--danger); }
        .badge-blocked { background: #000; color: #fff; border: 1px solid #333; }

        .findings { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-dim); }
        
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }
        .gallery-item {
            background: rgba(255,255,255,0.02);
            border-radius: 12px;
            padding: 0.5rem;
            border: 1px solid rgba(255,255,255,0.05);
            text-align: center;
        }
        .gallery-item img {
            width: 100%;
            height: 120px;
            object-fit: cover;
            border-radius: 8px;
            margin-bottom: 0.5rem;
        }
        .gallery-item .name { font-size: 0.8rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        @media (max-width: 768px) {
            td:nth-child(2), th:nth-child(2), td:nth-child(5), th:nth-child(5) { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <a href="index.php" class="back-link">← Return to Portal</a>
            <h1>Security Audit Trail</h1>
            <p style="color: var(--text-dim);">Real-time monitoring of all file upload attempts and sanitation events.</p>
        </header>

        <div class="card">
            <div class="section-title">🖼️ Recent Sanitized Assets</div>
            <div class="gallery">
                <?php foreach ($images as $img): ?>
                <div class="gallery-item">
                    <img src="download.php?uuid=<?= $img['uuid'] ?>" alt="Uploaded Image">
                    <div class="name"><?= htmlspecialchars($img['original_name']) ?></div>
                    <div style="font-size: 0.7rem; color: var(--text-dim);"><?= $img['width'] ?>x<?= $img['height'] ?>px</div>
                </div>
                <?php endforeach; ?>
                <?php if (empty($images)): ?>
                    <p style="color: var(--text-dim); grid-column: 1/-1;">No sanitized assets found.</p>
                <?php endif; ?>
            </div>
        </div>

        <div class="card" style="padding: 1rem 0;">
            <div class="section-title" style="padding: 0 2rem;">📜 Deep Scan Activity</div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Filename</th>
                            <th>Status</th>
                            <th>Security Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <tr>
                            <td style="white-space: nowrap;"><?= date('H:i:s', strtotime($log['created_at'])) ?></td>
                            <td style="font-family: 'JetBrains Mono'; font-size: 0.85rem;"><?= $log['ip_address'] ?></td>
                            <td><?= htmlspecialchars($log['filename']) ?></td>
                            <td>
                                <span class="badge badge-<?= $log['status'] ?>"><?= $log['status'] ?></span>
                            </td>
                            <td class="findings">
                                <?php 
                                    $f = json_decode($log['security_findings'], true);
                                    if (empty($f)) echo "None (Safe)";
                                    else {
                                        foreach($f as $finding) {
                                            if (is_string($finding)) echo htmlspecialchars($finding) . "<br>";
                                            else echo htmlspecialchars($finding['desc'] ?? 'Unknown risk') . "<br>";
                                        }
                                    }
                                ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
