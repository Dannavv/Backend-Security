<?php
// DB Helper functions to avoid classes but keep code clean

function get_db_connection() {
    $host = getenv('DB_HOST');
    $user = getenv('DB_USER');
    $pass = getenv('DB_PASS');
    $dbname = getenv('DB_NAME');

    // Suppress errors during connection to prevent leakage
    $conn = @mysqli_connect($host, $user, $pass, $dbname);
    
    if (!$conn) {
        error_log("Connection failed: " . mysqli_connect_error());
        die("System Error: Unable to connect to the database.");
    }

    // 1. Enforce UTF-8 (utf8mb4) Schema
    // Crucial for handling Emoji and preventing encoding-based SQLi bypasses.
    if (!mysqli_set_charset($conn, "utf8mb4")) {
        error_log("Error loading character set utf8mb4: " . mysqli_error($conn));
        die("System Error: Charset configuration failed.");
    }

    // 2. Enforce Strict SQL Mode
    // Prevents MySQL from truncated data or automatic type casting that could mask attacks.
    $sql_mode = "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'";
    if (!mysqli_query($conn, $sql_mode)) {
        error_log("Error setting SQL Mode: " . mysqli_error($conn));
        die("System Error: Database configuration failed.");
    }

    return $conn;
}

// Simple setup script to ensure tables exist
$conn = get_db_connection();

// Create Users Table
$sql_users = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

// Create Products Table
$sql_products = "CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

// Create Feedback Table
$sql_feedback = "CREATE TABLE IF NOT EXISTS feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    feedback_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

if (mysqli_query($conn, $sql_users) && mysqli_query($conn, $sql_products) && mysqli_query($conn, $sql_feedback)) {
    // Tables created
} else {
    echo "Error creating tables: " . mysqli_error($conn);
}
?>
