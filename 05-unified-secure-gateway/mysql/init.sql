CREATE DATABASE IF NOT EXISTS unified_security_db;
USE unified_security_db;

-- 🛠️ Main Gateway Audit Table
CREATE TABLE IF NOT EXISTS unified_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    true_mime VARCHAR(100) NOT NULL,
    detected_engine VARCHAR(50) NOT NULL,
    security_status ENUM('passed', 'sanitized', 'rejected', 'error') NOT NULL,
    threat_details TEXT,
    sanitized_path VARCHAR(255),
    file_hash CHAR(64),
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ⏳ Rate Limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    identifier_type ENUM('ip', 'session') NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_time (identifier, created_at)
);

-- 🔍 Reputation Database (PDF Chapter)
CREATE TABLE IF NOT EXISTS file_reputation (
    file_hash CHAR(64) PRIMARY KEY,
    status ENUM('safe', 'suspicious', 'malicious') DEFAULT 'safe',
    findings JSON,
    detection_count INT DEFAULT 1,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rep_status (status)
);

-- 📊 CSV Staging & Imports (CSV Chapter)
CREATE TABLE IF NOT EXISTS csv_staging (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id CHAR(16) NOT NULL,
    row_number INT NOT NULL,
    original_data JSON NOT NULL,
    sanitized_data JSON NOT NULL,
    validation_status ENUM('valid', 'invalid') NOT NULL,
    INDEX idx_batch (batch_id)
);

CREATE TABLE IF NOT EXISTS csv_imports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id CHAR(16) NOT NULL,
    row_number INT NOT NULL,
    original_data JSON NOT NULL,
    sanitized_data JSON NOT NULL,
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 📔 Legacy Chapter Audit Tables (To keep code exactly as-is)
CREATE TABLE IF NOT EXISTS upload_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id CHAR(16) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    filename VARCHAR(255),
    file_hash CHAR(64),
    file_size INT,
    status VARCHAR(50),
    row_count INT DEFAULT 0,
    neutralized_cells INT DEFAULT 0,
    validation_errors JSON,
    completed_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS pdf_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    user_agent TEXT,
    filename VARCHAR(255),
    status VARCHAR(50),
    security_findings JSON,
    file_size INT,
    file_hash CHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_file_hash ON unified_audit(file_hash);
