# 🛡️ Military-Grade Logging: The Forensic Masterclass Guide

## Part 1: The "Black Box" Landscape

Chapter 6 shifts from preventative security to **Forensic Readiness**. In a high-threat environment, we assume the system *will* be attacked. The logging infrastructure is the "Flight Recorder" (Black Box) that survives the crash to tell us what happened.

### Why Forensic Logging is Required
*   **The attribution gap**: 90% of breaches are never attributed to a specific actor because logs are either missing or tampered with.
*   **The "Silent Failure"**: Attackers often probe silently (SQLi attempts, IDORs). Without granular security logs, you have no warning signs.
*   **Log Tampering**: Sophisticated attackers `rm -rf /var/log` or edit files to hide their tracks. Standard logging is insecure by default.
*   **Compliance**: GDPR, PCI-DSS, and HIPAA Traceability requirements cannot be met with `error_log()`.

---

## Part 2: The 4-Layer Forensic Pipeline

Every event in the ERP system is captured across four synchronization layers:

### Layer 1: Infrastructure (Apache)
**Concept**: Capturing the raw "Wire Data" before it hits the application.
**Role**: Provides the `Timestamp`, `Client IP`, and `TLS Cipher` strength.
**Linkage**: Passes a unique `X-Request-ID` to PHP.

### Layer 2: Application (PHP)
**Concept**: The Logic Engine. Captures business context.
**Role**: Logs `User Identity`, `Logic Path`, `Exceptions`, and `Data Mutations`.
**Linkage**: Inherits `Request-ID` and appends `Context JSON`.

### Layer 3: Data (MySQL)
**Concept**: The State Engine. Captures persistence performance.
**Role**: Logs `Slow Queries` (>2s) and `SQL Errors` (potential SQLi attempts).

### Layer 4: Verification (Hash Chain)
**Concept**: The Integrity Engine.
**Role**: Cryptographically signs logs to prevent post-facto modification.

---

## Part 3: Specialized Engine Defenses

### 1. 🛡️ Structured Logging Engine (`erp_log`)

#### Layer 1: Contextual Intelligence
**Concept**: Logs must be machine-parseable and context-aware. A log without a User ID or Request ID is useless noise.
**Code Reference** (`include/config.php`):
```php
$logContent = sprintf(
    "[%s] [%s] [%s] [%s] [%s] [%s] [%06d] [%s] %s",
    $timestamp,
    str_pad(strtoupper($level), 8),
    basename($caller['file']) . ':' . $caller['line'],
    $user,          // Who?
    "$client_ip|$peer_ip", // From Where?
    $rid_str,       // Tracing functions
    $sequence,      // 1, 2, 3...
    LOG_KEY_ID,     // Key Rotation ID
    $cleanMessage
);
```

#### Layer 2: ID Poisoning Defense
**Concept**: Attackers inject malicious `X-Request-ID` headers to pollute logs or frame other users. We validate trust boundaries.
**Code Reference** (`include/config.php`):
```php
if (!empty($inboundID) && !preg_match('/^[a-f0-9]{16,32}$/i', $inboundID)) {
    // REJECT tainted ID and GENERATE fresh one
    define('REQUEST_ID', bin2hex(random_bytes(8)));
    define('REQUEST_ID_SOURCE', 'GENERATED_FALLBACK');
    // Log the attempt
    $isInvalidPropagated = true;
}
```

---

### 2. 🛡️ Integrity & Anti-Tamper Engine

#### Layer 3: Hash Chaining (Blockchain-Lite)
**Concept**: Prevent log deletion/modification by making every line dependent on the previous line's hash.
**Code Reference** (`include/config.php`):
```php
// Sign( Secret + PrevHash + Content )
$signaturePayload = LOG_SECRET_KEY . $prev_hash . $logContent;
$signature = hash_hmac('sha256', $signaturePayload, LOG_SECRET_KEY);

// Update session chain memory
$_SESSION['last_log_hash'] = $signature;

// Append to log
$finalEntry = $logContent . " | [SIG:$signature]";
```

#### Layer 4: PII Redaction with Luhn
**Concept**: Prevent accidental logging of Credit Cards by verifying the algorithm, not just regex (reduces false positives).
**Code Reference** (`include/config.php`):
```php
foreach ($matches[0] as $match) {
    $cleanNum = preg_replace('/\D/', '', $match);
    // Only redact if it passes Luhn Sum (Real Card)
    if (is_luhn_valid($cleanNum)) {
        $value = str_replace($match, '***REDACTED_CC***', $value);
    }
}
```

---

### 3. 🛡️ Availability & Reliability

#### Layer 5: DoS Protection (Size Capping)
**Concept**: Prevent "Log Flooding" DoS where an attacker generates massive error logs to fill the disk.
**Code Reference** (`include/config.php`):
```php
// Cap message at 2KB
$cleanMessage = sanitize_entry(substr($message, 0, 2048)); 

// Cap Context JSON at 8KB
if (strlen($jsonContext) > 8192) {
     $jsonContext = substr($jsonContext, 0, 8192) . "... [TRUNCATED]";
}
```

#### Layer 6: Global Exception Trap
**Concept**: Hijack the PHP runtime to catch crashes that would otherwise result in a white screen or leaked stack trace.
**Code Reference** (`include/config.php`):
```php
set_exception_handler(function (Throwable $e) {
    log_critical("Uncaught Exception: " . $e->getMessage(), [
        'trace' => $e->getTraceAsString()
    ]);
    // Show generic error to user, log details
    die('An internal error occurred. Ref: ' . REQUEST_ID);
});
```

---

## Part 4: Operational Principles

1.  **Identity is Mandatory**: No log line exists without an attached User ID and Correlation ID.
2.  **Verify the Chain**: The chain is only useful if you verify it. Run `php test_forensic.php` hourly.
3.  **Forward Integrity**: If the server is compromised, local logs are suspect. Ship logs to a remote syslog in real-time.
4.  **Quiet by Default**: We filter noise to ensure `SECURITY` events stand out.

---
*Authorized Security Audit - Military-Grade Logging Masterclass v6.0*
*Document Classification: High-Assurance Technical Architecture*

