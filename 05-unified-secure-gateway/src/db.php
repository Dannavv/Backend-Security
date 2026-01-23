<?php
/**
 * 🗄️ Unified Database Connection Helper
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    
    $dsn = "mysql:host=" . (getenv('DB_HOST') ?: 'db') . ";dbname=" . (getenv('DB_NAME') ?: 'unified_security_db') . ";charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'"
    ];
    
    try {
        return $pdo = new PDO($dsn, getenv('DB_USER') ?: 'security_user', getenv('DB_PASS') ?: 'security_pass', $options);
    } catch (PDOException $e) {
        error_log("DB Connection Failed: " . $e->getMessage());
        throw $e;
    }
}

function initSecurity(): void {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
    
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    error_reporting(E_ALL);
    
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        session_start();
    }
}
