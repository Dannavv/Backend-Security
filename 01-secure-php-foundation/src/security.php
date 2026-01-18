<?php
// Prevent Clickjacking
header("X-Frame-Options: DENY");

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Enforce Content Security Policy (Basic)
// Allows self, Google Fonts, and inline styles (needed for your current setup)
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");

// Referrer Policy
header("Referrer-Policy: no-referrer-when-downgrade");

// Hide PHP version (best effort, though usually done in php.ini)
header_remove("X-Powered-By");
?>
