<?php
require_once __DIR__ . '/app.php';
initSecurity();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$csrfToken = $_POST['csrf_token'] ?? '';
if (!PDFSecurity::validateCSRF($csrfToken)) {
    die("Invalid CSRF Token");
}

if (PDFSecurity::checkRateLimit($_SERVER['REMOTE_ADDR'])) {
    die("Rate limit exceeded. Please wait a minute.");
}

$file = $_FILES['pdf_file'] ?? null;
if (!$file) {
    die("No file uploaded");
}

// 1. Initial Identity & Meta
$fileHashOriginal = hash_file('sha256', $file['tmp_name']);

// 2. Ingress & Proof (SIGNALS ONLY)
$signals = PDFSecurity::validateFile($file);
$status = 'processing';
$findingMessages = [];

foreach ($signals as $s) {
    if (is_array($s)) {
        $msg = strtoupper($s['level']) . ": " . ($s['tag'] ?? $s['desc']);
        $findingMessages[] = $msg;
    } else {
        // Hard fail for structural anomalies that prevent sanitization
        AuditLogger::logAttempt($file['name'], 'rejected', [$s], $file['size'], $fileHashOriginal);
        die("Security Rejection: " . htmlspecialchars($s));
    }
}

// 3. Authoritative Sanitization (Decode-or-Die)
$storageName = bin2hex(random_bytes(16)) . '.pdf';
$destination = QUARANTINE_PATH . '/' . $storageName;

if (!ParserSanitizer::sanitize($file['tmp_name'], $destination)) {
    AuditLogger::logAttempt($file['name'], 'rejected', array_merge($findingMessages, ["CRITICAL: Sanitization Authority (QPDF) failed to decode/normalize file"]), $file['size'], $fileHashOriginal);
    @unlink($file['tmp_name']);
    header('Location: index.php?status=error&msg=Security+Rejection:+Invalid+or+malicious+PDF+structure');
    exit;
}

// 4. Post-Sanitize Verification
$postSanitizeSignals = PDFSecurity::validateFile(['tmp_name' => $destination, 'error' => 0, 'size' => filesize($destination), 'name' => $file['name']]);
$hasFinalThreats = false;
foreach ($postSanitizeSignals as $ps) {
    if (is_array($ps) && $ps['level'] === 'critical') {
        $hasFinalThreats = true;
        $findingMessages[] = "FAILED VERIFICATION: " . ($ps['tag'] ?? $ps['desc']);
    }
}

if ($hasFinalThreats) {
    @unlink($destination);
    @unlink($file['tmp_name']);
    AuditLogger::logAttempt($file['name'], 'rejected', $findingMessages, $file['size'], $fileHashOriginal);
    header('Location: index.php?status=error&msg=Security+Rejection:+Threats+persisted+after+sanitization');
    exit;
}

// 5. Success - Final Hash & Audit
$sanitizedSize = filesize($destination);
$sanitizedHash = hash_file('sha256', $destination);
$status = 'accepted';

// Finalize finding messages with deltas
$delta = $file['size'] - $sanitizedSize;
$findingMessages[] = "Sanitized: Removed " . number_format($delta) . " bytes of data.";
$findingMessages[] = "Normalized: Flattened XRefs, removed metadata, and linearized structure.";

AuditLogger::logAttempt($file['name'], $status, $findingMessages, $sanitizedSize, $sanitizedHash);
ReputationEngine::update($sanitizedHash, 'safe', $findingMessages);
@unlink($file['tmp_name']);


// 5. Log the attempt
AuditLogger::logAttempt($file['name'], $status, $findingMessages, $file['size'], $fileHash);




?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Scan Results | PDF Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f1f5f9;
            --success: #22c55e;
            --danger: #ef4444;
            --primary: #8b5cf6;
        }
        body { font-family: 'Outfit', sans-serif; background: var(--bg); color: var(--text); padding: 4rem 2rem; }
        .result-card {
            max-width: 600px;
            margin: 0 auto;
            background: var(--card);
            padding: 3rem;
            border-radius: 24px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .status-icon { font-size: 4rem; margin-bottom: 1rem; }
        .status-title { font-size: 2rem; font-weight: 700; margin-bottom: 2rem; }
        .accepted { color: var(--success); }
        .rejected { color: var(--danger); }
        .findings {
            text-align: left;
            background: rgba(0,0,0,0.2);
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }
        .finding-item { color: #fda4af; margin-bottom: 0.5rem; font-size: 0.9rem; }
        .btn {
            display: inline-block;
            background: var(--primary);
            color: white;
            padding: 0.75rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="result-card">
        <?php if ($status === 'accepted'): ?>
            <div class="status-icon">✅</div>
            <div class="status-title accepted">File Accepted</div>
            <p style="margin-bottom: 2rem; color: #94a3b8;">The file passed security checks (or was successfully sanitized). It is now in secure quarantine.</p>
            
            <?php if (!empty($findingMessages)): ?>
                <div class="findings" style="background: rgba(139, 92, 246, 0.1);">
                    <div style="font-weight: 600; margin-bottom: 1rem; color: var(--primary);">Security Notes (Sanitized):</div>
                    <?php foreach ($findingMessages as $msg): ?>
                        <div class="finding-item" style="color: #94a3b8;">ℹ️ <?= htmlspecialchars($msg) ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
        <?php else: ?>
            <div class="status-icon">❌</div>
            <div class="status-title rejected">File Rejected</div>
            <div class="findings">
                <div style="font-weight: 600; margin-bottom: 1rem;">Security Violations:</div>
                <?php foreach ($findingMessages as $msg): ?>
                    <div class="finding-item">⚠️ <?= htmlspecialchars($msg) ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <a href="index.php" class="btn">Return to Dashboard</a>
    </div>
</body>
</html>
