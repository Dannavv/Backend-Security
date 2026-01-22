CREATE DATABASE IF NOT EXISTS pdf_security;
USE pdf_security;

-- Audit table for PDF uploads
CREATE TABLE IF NOT EXISTS pdf_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id VARCHAR(64),
    ip_address VARCHAR(45),
    user_agent TEXT,
    filename VARCHAR(255),
    file_hash VARCHAR(64),
    file_size INT,
    status ENUM('pending', 'accepted', 'rejected', 'quarantined') DEFAULT 'pending',
    security_findings JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255),
    identifier_type ENUM('ip', 'session'),
    action VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (identifier, created_at)
);

-- Store for accepted files (metadata)
CREATE TABLE IF NOT EXISTS accepted_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    storage_name VARCHAR(255),
    original_name VARCHAR(255),
    mime_type VARCHAR(100),
    file_size INT,
    uploaded_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Reputation cache for file hashes
CREATE TABLE IF NOT EXISTS file_reputation (
    file_hash VARCHAR(64) PRIMARY KEY,
    status ENUM('safe', 'malicious', 'suspicious'),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    detection_count INT DEFAULT 1,
    findings JSON
);

CREATE INDEX idx_audit_hash ON pdf_audit(file_hash);
