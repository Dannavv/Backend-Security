-- CSV Upload Security - Database Schema
-- ======================================

-- Set strict mode and charset
SET NAMES utf8mb4;
SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';

-- Use the database
USE csv_security;

-- ======================
-- Audit Logging Table
-- ======================
CREATE TABLE IF NOT EXISTS upload_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id VARCHAR(36) NOT NULL,
    user_id INT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    filename VARCHAR(255) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    file_size INT NOT NULL,
    row_count INT DEFAULT 0,
    column_count INT DEFAULT 0,
    validation_errors JSON,
    neutralized_cells INT DEFAULT 0,
    status ENUM('pending', 'processing', 'completed', 'failed', 'rejected') NOT NULL DEFAULT 'pending',
    rejection_reason TEXT,
    processing_time_ms INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    
    INDEX idx_batch (batch_id),
    INDEX idx_user (user_id),
    INDEX idx_status (status),
    INDEX idx_hash (file_hash),
    INDEX idx_created (created_at),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Staging Table
-- ======================
CREATE TABLE IF NOT EXISTS csv_staging (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id VARCHAR(36) NOT NULL,
    `row_number` INT NOT NULL,
    original_data JSON NOT NULL,
    sanitized_data JSON NOT NULL,
    validation_status ENUM('pending', 'valid', 'invalid') DEFAULT 'pending',
    validation_errors JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_batch_status (batch_id, validation_status),
    INDEX idx_batch_row (batch_id, `row_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Production Data Table
-- ======================
CREATE TABLE IF NOT EXISTS csv_imports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id VARCHAR(36) NOT NULL,
    `row_number` INT NOT NULL,
    original_data JSON NOT NULL,
    sanitized_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_batch (batch_id),
    INDEX idx_batch_row (batch_id, `row_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Rate Limiting Table
-- ======================
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(64) NOT NULL,
    identifier_type ENUM('ip', 'user', 'session') NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_identifier_action (identifier, action, created_at),
    INDEX idx_cleanup (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Known Bad Hashes Table
-- ======================
CREATE TABLE IF NOT EXISTS blocked_hashes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_hash VARCHAR(64) NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    blocked_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_hash (file_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Import Templates Table
-- ======================
CREATE TABLE IF NOT EXISTS import_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    expected_columns JSON NOT NULL,
    column_rules JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ======================
-- Insert Default Template
-- ======================
INSERT INTO import_templates (name, description, expected_columns, column_rules) VALUES
(
    'employees',
    'Employee data import template',
    '["name", "email", "department", "salary", "hire_date"]',
    '{
        "name": {"type": "string", "required": true, "max_length": 100},
        "email": {"type": "email", "required": true, "max_length": 255},
        "department": {"type": "string", "required": true, "allowed": ["Engineering", "Sales", "Marketing", "HR", "Finance"]},
        "salary": {"type": "number", "required": true, "min": 0, "max": 10000000},
        "hire_date": {"type": "date", "required": true, "format": "Y-m-d"}
    }'
);

-- ======================
-- Cleanup Event (Auto-purge old data)
-- ======================
DELIMITER //

CREATE EVENT IF NOT EXISTS cleanup_old_data
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    -- Delete rate limit entries older than 24 hours
    DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);
    
    -- Delete staging data older than 1 hour (should be empty anyway)
    DELETE FROM csv_staging WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
    
    -- Note: Audit logs are retained for compliance (manual purge required)
END//

DELIMITER ;

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- ======================
-- Summary View
-- ======================
CREATE OR REPLACE VIEW upload_statistics AS
SELECT 
    DATE(created_at) as upload_date,
    COUNT(*) as total_uploads,
    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
    AVG(row_count) as avg_rows,
    AVG(processing_time_ms) as avg_processing_ms,
    SUM(neutralized_cells) as total_neutralized
FROM upload_audit
GROUP BY DATE(created_at)
ORDER BY upload_date DESC;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON csv_security.* TO 'csv_user'@'%';
FLUSH PRIVILEGES;
