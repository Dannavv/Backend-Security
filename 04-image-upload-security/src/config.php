<?php
/**
 * 🛠️ Configuration Constants for Image Security
 */

define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('MIN_FILE_SIZE', 100);
define('RATE_LIMIT_PER_MINUTE', 10);

// Path Configuration
define('UPLOAD_BASE_DIR', '/var/www/html/uploads');
define('QUARANTINE_DIR', '/var/www/quarantine');
define('LOG_DIR', '/var/log/app');

// Image Constraints
define('MAX_IMAGE_WIDTH', 4000);
define('MAX_IMAGE_HEIGHT', 4000);
define('MAX_TOTAL_PIXELS', 10000000); // 10 Megapixels cap
define('EXEC_TIMEOUT', 'timeout 10s '); // CPU/Time limit for processing
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('ALLOWED_MIME_TYPES', [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp'
]);

// Security Weights
define('REJECTION_THRESHOLD', 10);
define('WEIGHT_MAGIC_MISMATCH', 10);
define('WEIGHT_POLYGLOT_DETECTED', 10);
define('WEIGHT_METADATA_FOUND', 2);
define('WEIGHT_DIMENSION_ANOMALY', 5);

// Database Config
define('DB_HOST', getenv('DB_HOST') ?: 'mysql');
define('DB_NAME', getenv('DB_NAME') ?: 'image_security');
define('DB_USER', getenv('DB_USER') ?: 'image_user');
define('DB_PASS', getenv('DB_PASS') ?: 'image_secure_pass_2024');
