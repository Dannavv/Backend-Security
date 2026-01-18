<?php
require_once 'rules.php';

function validate_input($data, $rules) {
    $errors = [];

    foreach ($data as $field => $value) {
        if (!isset($rules[$field])) {
            continue; // Skip fields without rules
        }

        $fieldRules = $rules[$field];
        $label = $fieldRules['label'] ?? $field;
        
        // --- 1. Sanitization Phase ---
        // Strip NULL bytes to prevent truncation attacks
        // Trim whitespace
        if (is_string($value)) {
            $value = str_replace(chr(0), '', $value);
            $value = trim($value);
        }

        // --- 2. Validation Phase ---

        // Check required
        if (isset($fieldRules['required']) && $fieldRules['required'] && $value === '') {
            $errors[$field][] = "$label is required.";
            continue; 
        }

        if ($value !== '') {
            // Min Length
            if (isset($fieldRules['min_length']) && strlen($value) < $fieldRules['min_length']) {
                $errors[$field][] = "$label must be at least {$fieldRules['min_length']} characters.";
            }

            // Max Length
            if (isset($fieldRules['max_length']) && strlen($value) > $fieldRules['max_length']) {
               $errors[$field][] = "$label must not exceed {$fieldRules['max_length']} characters.";
            }

            // Pattern (Regex)
            if (isset($fieldRules['pattern']) && !preg_match($fieldRules['pattern'], $value)) {
                $errors[$field][] = "$label contains invalid characters.";
            }

            // Email Type
            if (isset($fieldRules['type']) && $fieldRules['type'] === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                $errors[$field][] = "Invalid email format for $label.";
            }

            // Numeric Type (Strictness Improvement)
            if (isset($fieldRules['type']) && $fieldRules['type'] === 'numeric') {
                // strict numeric check: allow only decimal numbers, no hex/scientific if unwanted.
                // For prices, filter_var with FILTER_VALIDATE_FLOAT is robust.
                if (!filter_var($value, FILTER_VALIDATE_FLOAT) && $value != '0') {
                     $errors[$field][] = "$label must be a valid number.";
                } else if (isset($fieldRules['min_value']) && floatval($value) < $fieldRules['min_value']) {
                     $errors[$field][] = "$label must be at least {$fieldRules['min_value']}.";
                }
            }

            // Allowed Values (Enum)
            if (isset($fieldRules['allowed_values']) && !in_array($value, $fieldRules['allowed_values'], true)) { // Added true for strict type check
                $errors[$field][] = "Invalid selection for $label.";
            }
        }
    }

    return $errors;
}
?>
