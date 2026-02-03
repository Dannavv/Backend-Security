<?php
/**
 * Chapter 7: Validation Rules Configuration
 * Centralized rules for input validation (adapted from Ch01 pattern)
 */

declare(strict_types=1);

// ============================================
// TYPE VALIDATION DEFAULTS
// ============================================

$typeMaxLengths = [
    's' => 65535,   // String
    'i' => 11,      // Integer digits
    'd' => 20,      // Double digits
    'b' => 1048576, // Blob (1MB)
];

// ============================================
// VALIDATION RULES BY TYPE
// ============================================

$validationRules = [
    // String validation
    's' => [
        'name' => 'String',
        'checks' => [
            'null_bytes' => 'Strip null bytes (chr(0))',
            'trim' => 'Trim whitespace',
            'utf8' => 'Validate UTF-8 encoding',
            'utf7_bypass' => 'Detect UTF-7 encoding bypass',
            'max_length' => 'Check maximum length (default: 65535)',
            'normalize' => 'NFC Unicode normalization'
        ]
    ],
    // Integer validation  
    'i' => [
        'name' => 'Integer',
        'checks' => [
            'numeric' => 'Must be numeric',
            'whole_number' => 'Must be whole number (no decimals)',
            'range' => 'Must be within PHP_INT_MIN to PHP_INT_MAX'
        ]
    ],
    // Double validation
    'd' => [
        'name' => 'Double/Float',
        'checks' => [
            'numeric' => 'Must be valid number',
            'finite' => 'Must be finite (no INF/NAN)'
        ]
    ],
    // Binary validation
    'b' => [
        'name' => 'Binary/Blob',
        'checks' => [
            'max_length' => 'Check maximum size (default: 1MB)'
        ]
    ]
];

// ============================================
// QUERY BLACKLIST PATTERNS
// Dangerous SQL patterns to block (adapted from Ch02 FORMULA_TRIGGERS)
// ============================================

$queryBlacklistPatterns = [
    '/SLEEP\s*\(/i'           => 'Time-based SQLi attempt',
    '/BENCHMARK\s*\(/i'       => 'Benchmark SQLi attempt',
    '/WAITFOR\s+DELAY/i'      => 'MSSQL delay attack',
    '/;\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE)\s/i' => 'Destructive statement',
    '/LOAD_FILE\s*\(/i'       => 'File read attempt',
    '/INTO\s+(OUT|DUMP)FILE/i' => 'File write attempt',
    '/@@\w+/i'                => 'System variable probe',
    '/INFORMATION_SCHEMA/i'   => 'Schema enumeration',
];

// ============================================
// RATE LIMITING CONFIGURATION
// ============================================

$rateLimitConfig = [
    'enabled' => true,
    'max_requests' => 100,      // Requests per window
    'window_seconds' => 60,     // Time window (1 minute)
    'block_duration' => 300,    // Block for 5 minutes after exceeded
];

// ============================================
// SECURITY HEADERS CONFIGURATION
// ============================================

$securityHeaders = [
    'X-Frame-Options' => 'DENY',
    'X-Content-Type-Options' => 'nosniff',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
];
