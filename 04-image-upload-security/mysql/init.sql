-- Database schema for Image Security Chapter
CREATE DATABASE IF NOT EXISTS image_security;
USE image_security;

-- Audit trail for all upload attempts
CREATE TABLE IF NOT EXISTS image_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    filename VARCHAR(255) NOT NULL,
    status ENUM('safe', 'sanitized', 'rejected', 'blocked') NOT NULL,
    security_findings JSON,
    file_size INT,
    file_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    identifier_type ENUM('ip', 'session') NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (identifier, created_at)
) ENGINE=InnoDB;

-- Known malicious hash database
CREATE TABLE IF NOT EXISTS file_reputation (
    file_hash VARCHAR(64) PRIMARY KEY,
    status ENUM('safe', 'malicious', 'suspicious') NOT NULL,
    findings JSON,
    detection_count INT DEFAULT 1,
    last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Secure image metadata storage
CREATE TABLE IF NOT EXISTS uploaded_images (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uuid VARCHAR(36) UNIQUE NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    width INT,
    height INT,
    file_size INT,
    file_hash VARCHAR(64),
    storage_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
