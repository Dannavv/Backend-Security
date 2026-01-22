<?php
/**
 * 📥 Secure Image Proxy
 * Serves images with strict Content-Type and security headers.
 */

require_once __DIR__ . '/app.php';
initSecurity();

$uuid = $_GET['uuid'] ?? '';

if (!preg_match('/^[a-f0-9]{32}$/', $uuid)) {
    header('HTTP/1.1 400 Bad Request');
    exit;
}

$db = getDB();
$stmt = $db->prepare("SELECT * FROM uploaded_images WHERE uuid = ?");
$stmt->execute([$uuid]);
$image = $stmt->fetch();

if (!$image) {
    header('HTTP/1.1 404 Not Found');
    exit;
}

$path = $image['storage_path'];

if (!file_exists($path)) {
    header('HTTP/1.1 404 Not Found');
    exit;
}

// 🔐 SECURITY HEADERS FOR DELIVERY
header('Content-Type: ' . $image['mime_type']);
header('Content-Length: ' . filesize($path));
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; img-src 'self';");
header('Cache-Control: private, max-age=31536000');

// Use X-Sendfile if available, otherwise readfile
readfile($path);
exit;
