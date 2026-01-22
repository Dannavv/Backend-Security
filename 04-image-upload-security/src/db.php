<?php
/**
 * 🗄️ Database Connection Helper
 */

require_once __DIR__ . '/config.php';

function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'"
    ];
    
    try {
        return $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    } catch (PDOException $e) {
        error_log("DB Connection Failed: " . $e->getMessage());
        header('HTTP/1.1 503 Service Unavailable');
        exit("Database connection failed. Please check logs.");
    }
}
