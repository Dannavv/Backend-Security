<?php
require_once __DIR__ . '/app.php';
initSecurity();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Upload</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 CSV Security</h1>
            <nav><a href="index.php">Dashboard</a><a href="upload.php" class="active">Upload File</a><a href="history.php">Audit Log</a></nav>
        </header>

        <section class="section-header">
            <h2>Secure Upload Portal</h2>
            <p>Your file will be processed in an isolated quarantine environment</p>
        </section>

        <form action="process.php" method="POST" enctype="multipart/form-data" class="secure-form">
            <input type="hidden" name="csrf_token" value="<?php echo CSVSecurity::csrfToken(); ?>">
            
            <div class="form-group">
                <label for="csv_file">Select CSV File</label>
                <input type="file" id="csv_file" name="csv_file" accept=".csv" required>
                <p class="form-help" style="margin-top: 0.5rem; color: var(--text-muted); font-size: 0.85rem;">
                    Max size: 5MB. Multi-layer scan will be performed.
                </p>
            </div>
            
            <button type="submit" class="btn btn-primary btn-lg" style="width: 100%">Verify & Process</button>
            
            <div class="security-notice" style="margin-top: 2rem; padding: 1rem; background: rgba(99, 102, 241, 0.05); border-radius: 0.75rem; border: 1px solid rgba(99, 102, 241, 0.1);">
                <p style="margin: 0; font-size: 0.9rem; color: var(--text-muted);">
                    <span style="margin-right: 0.5rem">🛡️</span> 
                    <strong>Deep Scan Active:</strong> We check for binary disguises, PHP tags, and spreadsheet formula injection before the file touches our database.
                </p>
            </div>
        </form>
    </div>
</body>
</html>
