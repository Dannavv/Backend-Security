<?php
/**
 * 📦 Unified Upload Controller
 */

declare(strict_types=1);

require_once __DIR__ . '/Gateway.php';

require_once __DIR__ . '/db.php';
initSecurity();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $result = Gateway::handle($file);

    // Audit Log & Session Storage
    try {
        $db = getDB();
        $stmt = $db->prepare("INSERT INTO unified_audit (filename, true_mime, detected_engine, security_status, threat_details, sanitized_path, file_hash, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        
        $status = ($result['status'] === 'sanitized') ? 'sanitized' : (($result['status'] === 'rejected') ? 'rejected' : 'error');
        $threat = $result['error'] ?? ($result['message'] ?? null);
        $path = $result['path'] ?? null;
        $hash = $path ? hash_file('sha256', $path) : null;
        $ip = $_SERVER['REMOTE_ADDR'];

        $stmt->execute([
            $file['name'],
            $result['mime'] ?? 'unknown',
            $result['engine'] ?? 'none',
            $status,
            $threat,
            $path ? basename($path) : null,
            $hash,
            $ip
        ]);
    } catch (Exception $e) {
        // Fallback: Continue even if DB log fails
        error_log("Audit Log Failure: " . $e->getMessage());
    }

    // Store result in session for redirect
    $_SESSION['last_result'] = $result;
    header('Location: index.php?status=' . ($result['status'] ?? 'error'));
    exit;
}

header('Location: index.php');
