<?php
/**
 * Chapter 7: Input Validator
 * Validates parameters based on type rules (adapted from Ch01 validator.php)
 */

declare(strict_types=1);

require_once __DIR__ . '/rules.php';

/**
 * Get validation rules for display
 */
function get_validation_rules(): array {
    global $validationRules;
    return $validationRules;
}

/**
 * Get type max lengths
 */
function get_type_max_lengths(): array {
    global $typeMaxLengths;
    return $typeMaxLengths;
}

/**
 * Validate a single parameter based on its type
 * 
 * @param mixed $value The value to validate
 * @param string $type Type indicator (s/i/d/b)
 * @param array $options Optional settings like max_length
 * @return array ['valid' => bool, 'errors' => [], 'value' => mixed, 'rules_applied' => []]
 */
function validate_param($value, string $type, array $options = []): array {
    global $typeMaxLengths;
    
    $errors = [];
    $appliedRules = [];
    $maxLength = $options['max_length'] ?? $typeMaxLengths[$type] ?? 65535;
    
    try {
        // Handle null values
        if ($value === null) {
            if ($type !== 'b') {
                $errors[] = 'Value cannot be null';
                return ['valid' => false, 'errors' => $errors, 'value' => $value, 'rules_applied' => []];
            }
        }
        
        // Null-byte stripping (Ch01 validator.php:18-21)
        if (is_string($value)) {
            $value = str_replace(chr(0), '', $value);
            $value = trim($value);
            $appliedRules[] = 'null_bytes_stripped';
            $appliedRules[] = 'trimmed';
        }
        
        // UTF-8 validation (Ch02 validateAndNormalize)
        if (is_string($value) && $value !== '') {
            if (!mb_check_encoding($value, 'UTF-8')) {
                $errors[] = 'Invalid UTF-8 encoding';
                return ['valid' => false, 'errors' => $errors, 'value' => $value, 'rules_applied' => $appliedRules];
            }
            $appliedRules[] = 'utf8_validated';
        }
        
        // UTF-7 bypass detection (Ch02)
        if (is_string($value) && $value !== '' && preg_match('/\+[A-Za-z0-9+\/]+-/', $value)) {
            $errors[] = 'Potential UTF-7 encoding bypass detected';
            return ['valid' => false, 'errors' => $errors, 'value' => $value, 'rules_applied' => $appliedRules];
        }
        
        // Length check (Ch01 validator.php:38-40)
        if (is_string($value) && strlen($value) > $maxLength) {
            $errors[] = "Value exceeds maximum length of $maxLength (got " . strlen($value) . ")";
            return ['valid' => false, 'errors' => $errors, 'value' => $value, 'rules_applied' => $appliedRules];
        }
        $appliedRules[] = 'length_checked';
        
        // Type-specific validation
        switch ($type) {
            case 'i':
                if (is_string($value)) {
                    $value = trim($value);
                    if (!preg_match('/^-?\d+$/', $value)) {
                        $errors[] = 'Value must be an integer (got: ' . substr($value, 0, 20) . ')';
                        break;
                    }
                    $value = (int)$value;
                }
                if (!is_int($value) && !is_numeric($value)) {
                    $errors[] = 'Value must be an integer';
                } elseif ($value < PHP_INT_MIN || $value > PHP_INT_MAX) {
                    $errors[] = 'Integer out of range';
                }
                $appliedRules[] = 'integer_validated';
                break;
                
            case 'd':
                if (is_string($value)) {
                    $value = trim($value);
                    if (!is_numeric($value)) {
                        $errors[] = 'Value must be a number (got: ' . substr($value, 0, 20) . ')';
                        break;
                    }
                    $value = (float)$value;
                }
                if (!is_numeric($value)) {
                    $errors[] = 'Value must be a number';
                } elseif (!is_finite((float)$value)) {
                    $errors[] = 'Value must be finite (no INF/NAN)';
                }
                $appliedRules[] = 'double_validated';
                break;
                
            case 's':
                $appliedRules[] = 'string_validated';
                break;
                
            case 'b':
                if (is_string($value) && strlen($value) > $maxLength) {
                    $errors[] = "Binary data exceeds maximum size of $maxLength bytes";
                }
                $appliedRules[] = 'binary_validated';
                break;
                
            default:
                $errors[] = "Unknown type: $type (must be s/i/d/b)";
        }
        
        // Normalize (Ch02 - NFC normalization)
        if (empty($errors) && is_string($value) && $value !== '' && class_exists('Normalizer')) {
            $normalized = \Normalizer::normalize($value, \Normalizer::FORM_C);
            if ($normalized !== false) {
                $value = $normalized;
                $appliedRules[] = 'nfc_normalized';
            }
        }
        
    } catch (\Throwable $e) {
        $errors[] = 'Validation error: ' . $e->getMessage();
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'value' => $value,
        'rules_applied' => $appliedRules
    ];
}

/**
 * Check query against blacklist patterns
 */
function check_query_blacklist(string $sql): ?string {
    global $queryBlacklistPatterns;
    
    foreach ($queryBlacklistPatterns as $pattern => $description) {
        if (preg_match($pattern, $sql)) {
            return $description;
        }
    }
    return null;
}
