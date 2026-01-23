<?php
/**
 * 🛠️ Unified Configuration - Merges constants from Chapters 2, 3, 4
 * Uses prefixes to avoid conflicts: CSV_, PDF_, IMG_
 */

declare(strict_types=1);

// =========================================================================
// CSV SECURITY CONSTANTS (From Chapter 2)
// =========================================================================
define('CSV_MAX_FILE_SIZE', 5 * 1024 * 1024);
define('CSV_MIN_FILE_SIZE', 10);
define('CSV_MAX_ROWS', 10000);
define('CSV_MAX_COLUMNS', 50);
define('CSV_MAX_LINE_LENGTH', 50000);
define('CSV_RATE_LIMIT_PER_MINUTE', 10);
define('CSV_FORMULA_TRIGGERS', ['=', '+', '-', '@', "\t", "\r", "\n"]);
define('CSV_QUARANTINE_PATH', '/var/quarantine/uploads');
define('CSV_LOG_PATH', '/var/log/csv-security');
define('CSV_ALLOWED_EXTENSIONS', ['csv', 'txt']);
define('CSV_ALLOWED_MIME_TYPES', ['text/csv', 'text/plain', 'application/csv']);
define('CSV_MAX_ERROR_COUNT', 50);
define('CSV_BINARY_SIGNATURES', [
    "\x7fELF" => 'ELF', "MZ" => 'Windows EXE', "<?php" => 'PHP', "<?" => 'PHP/XML', "#!/" => 'Shebang', "\x00" => 'Null Byte Injection'
]);

// =========================================================================
// PDF SECURITY CONSTANTS (From Chapter 3)
// =========================================================================
define('PDF_MAX_FILE_SIZE', 10 * 1024 * 1024);
define('PDF_MIN_FILE_SIZE', 100);
define('PDF_RATE_LIMIT_PER_MINUTE', 5);
define('PDF_QUARANTINE_PATH', '/var/quarantine/uploads');
define('PDF_LOG_PATH', '/var/log/pdf-security');
define('PDF_ALLOWED_EXTENSIONS', ['pdf']);
define('PDF_ALLOWED_MIME_TYPES', ['application/pdf']);

define('PDF_MALICIOUS_KEYWORDS', [
    '/JS'           => ['desc' => 'Embedded JavaScript', 'level' => 'critical'],
    '/JavaScript'   => ['desc' => 'Embedded JavaScript', 'level' => 'critical'],
    '/Action'       => ['desc' => 'Generic Action Dictionary', 'level' => 'critical'],
    '/A'            => ['desc' => 'Short Action Dictionary', 'level' => 'critical'],
    '/OpenAction'   => ['desc' => 'Automatic Action on Open', 'level' => 'critical'],
    '/AA'           => ['desc' => 'Additional Action Trigger', 'level' => 'critical'],
    '/Launch'       => ['desc' => 'External Application Launch', 'level' => 'critical'],
    '/SubmitForm'   => ['desc' => 'Form Data Submission (SSRF)', 'level' => 'critical'],
    '/ImportData'   => ['desc' => 'External Data Import', 'level' => 'critical'],
    '/GoToR'        => ['desc' => 'Remote GoTo Action', 'level' => 'critical'],
    '/GoToE'        => ['desc' => 'Embedded File GoTo Action', 'level' => 'critical'],
    '/URI'          => ['desc' => 'External Hyperlink Action', 'level' => 'critical'],
    '/AcroForm'     => ['desc' => 'Interactive Form Actions', 'level' => 'critical'],
    '/EmbeddedFile' => ['desc' => 'Embedded File Attachment', 'level' => 'critical'],
    '/RichMedia'    => ['desc' => 'Embedded Flash/Media', 'level' => 'critical'],
    '/Sound'        => ['desc' => 'Embedded Audio Object', 'level' => 'critical'],
    '/Movie'        => ['desc' => 'Embedded Video Object', 'level' => 'critical'],
    '/XFA'          => ['desc' => 'XML Forms Architecture (Legacy Exploit Vector)', 'level' => 'critical'],
    '/S'            => ['desc' => 'Action Subtype Identifier', 'level' => 'critical'],
    '/Metadata'     => ['desc' => 'Embedded XMP Metadata (Info Leakage)', 'level' => 'suspicious'],
]);

define('PDF_MAX_OBJECT_COUNT', 50000);
define('PDF_MAX_STREAM_COUNT', 10000);
define('PDF_MAX_PAGE_COUNT', 5000);
define('PDF_WEIGHT_SEMANTIC_HIT', 10);
define('PDF_WEIGHT_REGEX_HIT', 3);
define('PDF_WEIGHT_STRUCTURAL_ANOMALY', 5);
define('PDF_MAX_RECURSION_DEPTH', 50);
define('PDF_EXEC_TIMEOUT', 'timeout 5s ');
define('PDF_REJECTION_SCORE_THRESHOLD', 10);

// =========================================================================
// IMAGE SECURITY CONSTANTS (From Chapter 4)
// =========================================================================
define('IMG_MAX_FILE_SIZE', 5 * 1024 * 1024);
define('IMG_MIN_FILE_SIZE', 100);
define('IMG_RATE_LIMIT_PER_MINUTE', 10);
define('IMG_UPLOAD_BASE_DIR', '/var/www/html/uploads');
define('IMG_QUARANTINE_DIR', '/var/www/quarantine');
define('IMG_LOG_DIR', '/var/log/app');
define('IMG_MAX_IMAGE_WIDTH', 4000);
define('IMG_MAX_IMAGE_HEIGHT', 4000);
define('IMG_MAX_TOTAL_PIXELS', 10000000);
define('IMG_EXEC_TIMEOUT', 'timeout 10s ');
define('IMG_ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('IMG_ALLOWED_MIME_TYPES', [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp'
]);
define('IMG_REJECTION_THRESHOLD', 10);
define('IMG_WEIGHT_MAGIC_MISMATCH', 10);
define('IMG_WEIGHT_POLYGLOT_DETECTED', 10);
define('IMG_WEIGHT_METADATA_FOUND', 2);
define('IMG_WEIGHT_DIMENSION_ANOMALY', 5);
