<?php
/**
 * 📥 Unified Secure Download Proxy
 */

declare(strict_types=1);

$filename = $_GET['file'] ?? '';
if (!$filename || !preg_match('/^[a-f0-9]{32}\.[a-z0-9]+$/i', $filename)) {
    die("Invalid file request");
}

$path = __DIR__ . '/../uploads/' . $filename;
if (!file_exists($path)) {
    die("File not found");
}

$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($path);

// Security Headers
header('X-Content-Type-Options: nosniff');

if ($mime === 'application/pdf') {
    header('Content-Security-Policy: sandbox');
    header('Content-Type: application/pdf');
} elseif (str_starts_with($mime, 'image/')) {
    header('Content-Type: ' . $mime);
} else {
    // Force download for CSV/Text
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="sanitized_export.' . pathinfo($filename, PATHINFO_EXTENSION) . '"');
}

readfile($path);
