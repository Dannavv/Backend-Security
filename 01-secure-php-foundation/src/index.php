<?php
require_once 'security.php';

$host = getenv('DB_HOST');
$user = getenv('DB_USER');
$pass = getenv('DB_PASS');
$dbname = getenv('DB_NAME');

// Suppress default error reporting to screen
mysqli_report(MYSQLI_REPORT_OFF);

$conn = @mysqli_connect($host, $user, $pass, $dbname);

if (!$conn) {
    // Log the actual error to the server's error log
    error_log("Connection failed: " . mysqli_connect_error());
    // Show generic message to user
    die("System Error: Unable to connect to the database. Please try again later.");
}
echo "Successfully connected to MySQL database: " . htmlspecialchars($dbname);
?>
