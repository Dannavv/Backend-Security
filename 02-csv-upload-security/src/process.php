<?php
require_once __DIR__ . '/app.php';
initSecurity();

if (!CSVSecurity::validateCSRF($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    die("Forbidden: CSRF token invalid");
}

$ip = $_SERVER['REMOTE_ADDR'] ?: '0.0.0.0';
if (CSVSecurity::checkRateLimit($ip)) {
    http_response_code(429);
    die("Rate limit exceeded");
}

if (!isset($_FILES['csv_file'])) die("No file");
$file = $_FILES['csv_file'];
// Initial validation
$errors = CSVSecurity::validateFile($file);
$batchId = bin2hex(random_bytes(16));
$results = ['rows' => 0, 'neutralized' => 0, 'errors' => $errors];
$status = 'rejected';

if (empty($errors)) {
    // Move to quarantine
    $path = QUARANTINE_PATH . '/' . bin2hex(random_bytes(16)) . '.csv';
    if (!move_uploaded_file($file['tmp_name'], $path)) {
        http_response_code(500);
        die("Internal Error: Storage failure");
    }

    // Process
    AuditLogger::start($batchId, $file['name'], $file['size']);
    $results = CSVProcessor::run($path, $batchId);
    $status = empty($results['errors']) ? 'completed' : 'failed';
    AuditLogger::end($batchId, $status, $results);
} else {
    // Log rejection in UI-friendly way
    AuditLogger::start($batchId, $file['name'], $file['size']);
    AuditLogger::end($batchId, 'rejected', ['errors' => $errors]);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload Status</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="container">
        <h1><?php echo $status === 'completed' ? '✅ Success' : '❌ Failed'; ?></h1>
        <p>Batch ID: <code><?php echo $batchId; ?></code></p>
        <p>Rows: <?php echo $results['rows']; ?> | Neutralized: <?php echo $results['neutralized']; ?></p>
        <?php if (!empty($results['errors'])): ?>
        <div class="errors">
            <h3>❌ Errors</h3>
            <ul>
                <?php foreach ($results['errors'] as $error): ?>
                <li><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>
        <div class="actions">
            <a href="history.php" class="btn btn-primary">View History</a>
            <a href="index.php" class="btn">Dashboard</a>
        </div>
    </div>
</body>
</html>
