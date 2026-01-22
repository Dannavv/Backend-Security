<?php
require_once __DIR__ . '/app.php';
initSecurity();

// Only authenticated sessions should be able to download (Simplified here)
$fileId = $_GET['id'] ?? '';
if (empty($fileId)) {
    die("No file ID specified");
}

$db = getDB();
$stmt = $db->prepare("SELECT * FROM accepted_files WHERE id = ?");
$stmt->execute([$fileId]);
$fileInfo = $stmt->fetch();

if (!$fileInfo) {
    die("File not found");
}

$filePath = QUARANTINE_PATH . '/' . $fileInfo['storage_name'];

if (!file_exists($filePath)) {
    die("File missing from storage");
}

/**
 * 🛡️ SECURE SERVING HEADERS
 */

// 1. Force Download (Prevents browser from trying to render and execute JS)
header('Content-Description: File Transfer');
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . basename($fileInfo['original_name']) . '"');
header('Content-Transfer-Encoding: binary');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . filesize($filePath));

// 2. Security Hardening
header('X-Content-Type-Options: nosniff');
header('Content-Security-Policy: sandbox'); // Disables ALL scripts and plugins if opened directly

// 3. Prevent Information Leakage
// Ensure no other output exists
ob_clean();
flush();

readfile($filePath);
exit;
