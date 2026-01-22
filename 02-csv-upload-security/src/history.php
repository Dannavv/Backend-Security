<?php
require_once __DIR__ . '/app.php';
initSecurity();
$logs = getDB()->query("SELECT * FROM upload_audit ORDER BY created_at DESC LIMIT 15")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Audit Log</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>📜 Audit Log</h1>
            <nav><a href="index.php">Home</a><a href="upload.php">Upload</a><a href="history.php" class="active">Audit</a></nav>
        </header>

        <table class="audit-table">
            <thead><tr><th>Time</th><th>File</th><th>Status</th><th>Rows</th><th>Neutralized</th></tr></thead>
            <tbody>
                <?php foreach($logs as $l): ?>
                <tr>
                    <td><?php echo date('H:i:s', strtotime($l['created_at'])); ?></td>
                    <td><?php echo htmlspecialchars($l['filename']); ?></td>
                    <td><span class="status status-<?php echo $l['status']; ?>"><?php echo $l['status']; ?></span></td>
                    <td><?php echo $l['row_count']; ?></td>
                    <td><?php echo $l['neutralized_cells']; ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
