-- Chapter 7: Database initialization
-- Rate limiting and audit tables

CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(64) NOT NULL,
    identifier_type ENUM('ip', 'session') DEFAULT 'ip',
    action VARCHAR(32) DEFAULT 'query',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_time (identifier, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(32) NOT NULL,
    severity ENUM('INFO', 'WARNING', 'CRITICAL') DEFAULT 'INFO',
    ip_address VARCHAR(45),
    user_id VARCHAR(64),
    message TEXT,
    context JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_time (event_type, created_at),
    INDEX idx_severity (severity)
) ENGINE=InnoDB;

-- Demo table for testing
CREATE TABLE IF NOT EXISTS demo_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT INTO demo_users (name, email, role) VALUES
('Alice Admin', 'alice@example.com', 'admin'),
('Bob User', 'bob@example.com', 'user'),
('Charlie Test', 'charlie@example.com', 'user');

-- Auto-cleanup for rate limits (keep 1 hour)
CREATE EVENT IF NOT EXISTS cleanup_rate_limits
ON SCHEDULE EVERY 1 HOUR
DO DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
