<?php
require_once __DIR__ . '/app.php';
initSecurity();

try {
    $stats = getDB()->query("SELECT COUNT(*) as total, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as success FROM upload_audit")->fetch();
} catch (Exception $e) { $stats = ['total'=>0, 'success'=>0]; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSV Security Dashboard</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 CSV Security</h1>
            <nav><a href="index.php" class="active">Dashboard</a><a href="upload.php">Upload File</a><a href="history.php">Audit Log</a></nav>
        </header>

        <section class="hero">
            <div class="hero-content">
                <h1>Secure CSV Import Engine</h1>
                <p>Advanced defense-in-depth system protecting against Formula Injection, Binary Disguise, and Resource Exhaustion.</p>
                <div class="hero-actions">
                    <a href="upload.php" class="btn btn-primary btn-lg">Deploy New Import</a>
                    <a href="history.php" class="btn btn-secondary btn-lg">View Audit Trail</a>
                </div>
            </div>
            <div class="hero-stats">
                <div class="stat-mini">
                    <span class="label">Total Imports</span>
                    <span class="value"><?php echo number_format((float)$stats['total']); ?></span>
                </div>
                <div class="stat-mini">
                    <span class="label">Safe Commits</span>
                    <span class="value success"><?php echo number_format((float)($stats['success']??0)); ?></span>
                </div>
            </div>
        </section>

        <section class="features-section">
            <div class="section-header">
                <h2>Active Security Layers</h2>
                <p>Every upload passes through these 10 distinct security modules</p>
            </div>
            <div class="features-grid">
                <?php foreach (CSVSecurity::getFeatures() as $feature): ?>
                <div class="feature-card">
                    <div class="feature-icon"><?php echo $feature['icon']; ?></div>
                    <div class="feature-info">
                        <h3><?php echo $feature['name']; ?></h3>
                        <p><?php echo $feature['desc']; ?></p>
                    </div>
                    <div class="feature-status"><span class="badge pulse">Active</span></div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>
    </div>
</body>
</html>
