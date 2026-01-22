<?php
/**
 * 🚀 Image Upload Handler
 */

require_once __DIR__ . '/app.php';
initSecurity();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

// 1. CSRF Verification
if (!ImageSecurity::validateCSRF($_POST['csrf_token'] ?? '')) {
    AuditLogger::logAttempt('N/A', 'blocked', ['CSRF missing or invalid'], 0);
    header('Location: index.php?status=error&msg=Invalid+Security+Token');
    exit;
}

// 2. Rate Limiting
if (ImageSecurity::checkRateLimit($_SERVER['REMOTE_ADDR'])) {
    AuditLogger::logAttempt('N/A', 'blocked', ['Rate limit exceeded'], 0);
    header('Location: index.php?status=error&msg=Too+many+attempts.+Cool+down.');
    exit;
}

$file = $_FILES['image_file'] ?? null;
if (!$file || $file['error'] === UPLOAD_ERR_NO_FILE) {
    header('Location: index.php?status=error&msg=No+file+provided');
    exit;
}

// 3. Initial Security Validation (SIGNALS ONLY)
$signals = ImageSecurity::validateFile($file);
$hashOriginal = hash_file('sha256', $file['tmp_name']);

// 4. Processing & Sanitization (AUTHORITY)
$uuid = bin2hex(random_bytes(16));
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);

// Ensure upload directories exist
if (!is_dir(UPLOAD_BASE_DIR)) mkdir(UPLOAD_BASE_DIR, 0755, true);
if (!is_dir(QUARANTINE_DIR)) mkdir(QUARANTINE_DIR, 0755, true);

$quarantinePath = QUARANTINE_DIR . '/' . $uuid . '.tmp';
$finalPath = UPLOAD_BASE_DIR . '/' . $uuid . '.' . $ext;

// Move to quarantine first
if (!move_uploaded_file($file['tmp_name'], $quarantinePath)) {
    header('Location: index.php?status=error&msg=Storage+error');
    exit;
}

// 5. Active Sanitization (Re-encoding via Libvips - DECODE OR DIE)
$sanitized = ImageSecurity::sanitizeImage($quarantinePath, $finalPath, $mime);

if (!$sanitized) {
    unlink($quarantinePath);
    // If sanitization fails, we check signals to explain why
    AuditLogger::logAttempt($file['name'], 'rejected', array_merge($signals, ['Core sanitization failure (Decode-or-Die triggered)']), $file['size'], $hashOriginal);
    header('Location: index.php?status=error&msg=Security+Rejection:+Invalid+or+malicious+image+structure');
    exit;
}

// 6. Post-Sanitization Metadata & Normalization
$sanitizedSize = filesize($finalPath);
$sanitizedHash = hash_file('sha256', $finalPath);
$delta = $file['size'] - $sanitizedSize;

// Final Findings (Signals + Delta)
$finalFindings = $signals;
$finalFindings[] = "Sanitized Output: Removed " . number_format($delta) . " bytes of potentially malicious/hidden data.";
if ($delta > 0) $finalFindings[] = "Normalization: Fixed bit-depth, removed ICC profiles, and flattened frames.";

// 7. Success - Register and Log
$dimensions = getimagesize($finalPath);
ImageRegistry::register(
    $uuid,
    $file['name'],
    $mime,
    $dimensions[0],
    $dimensions[1],
    $sanitizedSize,
    $sanitizedHash,
    $finalPath
);

AuditLogger::logAttempt($file['name'], 'sanitized', $finalFindings, $sanitizedSize, $sanitizedHash);

// Cleanup quarantine
unlink($quarantinePath);

header('Location: index.php?status=success');
exit;

// Cleanup quarantine
unlink($quarantinePath);

header('Location: index.php?status=success');
exit;
