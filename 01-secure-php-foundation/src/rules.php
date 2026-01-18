<?php
// Centralized validation rules configuration

$rules = [
    'username' => [
        'required' => true,
        'min_length' => 3,
        'max_length' => 20,
        'pattern' => '/^[a-zA-Z0-9_]+$/', // Alphanumeric and underscore
        'label' => 'Username'
    ],
    'email' => [
        'required' => true,
        'type' => 'email',
        'label' => 'Email Address'
    ],
    'password' => [
        'required' => true,
        'min_length' => 8,
        // Enforce complexity: at least one letter and one number
        'pattern' => '/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/', 
        'label' => 'Password'
    ],
    'product_name' => [
        'required' => true,
        'min_length' => 2,
        'max_length' => 100,
        'label' => 'Product Name'
    ],
    'category' => [
        'required' => true,
        'allowed_values' => ['software', 'hardware', 'service', 'consulting'],
        'label' => 'Category'
    ],
    'price' => [
        'required' => true,
        'type' => 'numeric',
        'min_value' => 0,
        'label' => 'Price'
    ],
    'feedback_type' => [
        'required' => true,
        'allowed_values' => ['bug', 'feature', 'security', 'other'],
        'label' => 'Feedback Type'
    ],
    'severity' => [
        'required' => true,
        'allowed_values' => ['low', 'medium', 'high'],
        'label' => 'Severity'
    ],
    'message' => [
        'required' => true,
        'min_length' => 10,
        'max_length' => 1000,
        'label' => 'Message'
    ]
];
?>
