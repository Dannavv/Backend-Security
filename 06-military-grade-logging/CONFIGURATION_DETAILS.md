# 🛡️ Chapter 6: Military-Grade Logging Configuration Manifest

This document serves as the **Single Source of Truth** for every configuration deployed in this chapter. It details the `Apache`, `MySQL`, `PHP`, and `System` configurations designed to create a forensic-ready, anti-tamper logging infrastructure.

---

## 1. Apache Configuration (Layer 1: The Wire)
**File:** `config/apache-logging.conf`
**Target Location:** `/etc/apache2/conf-available/erp-logging.conf`

We replace standard logging with a **Forensic Log Format** that captures security context often missed by default configurations.

### A. The Forensic Log Format
Standard Common Log Format (CLF) is insufficient for security forensics. We use a custom format `erp_forensic`.

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %{X-Request-ID}o %{SSL_PROTOCOL}x %{SSL_CIPHER}x" erp_forensic
```

**Field Breakdown:**
| Token | Meaning | Forensic Utility |
| :--- | :--- | :--- |
| `%D` | Duration (microseconds) | Detects **Slowloris DoS** attacks or Performance degradation. |
| `%{X-Request-ID}o` | Correlation ID | **Crucial:** Links this Apache Request to the specific PHP Execution trace. |
| `%{SSL_PROTOCOL}x` | TLS Protocol | Audits legacy clients (e.g., finding who is still using TLS 1.0). |
| `%{SSL_CIPHER}x` | TLS Cipher | Verifies encryption strength. |

### B. Smart Noise Filtering
Security logs lose value if they are flooded with noise. We explicitly **exclude** low-risk static assets from the access log to save IOPS and focus on actual logic requests.

```apache
SetEnvIf Request_URI "^/health$" dontlog
SetEnvIf Request_URI "^/favicon.ico$" dontlog
SetEnvIf Request_URI "\.(?i:gif|jpe?g|png|ico|css|js)$" dontlog
SetEnvIf Request_URI "stream_logs\.php" dontlog

# Apply the filter (env=!dontlog)
CustomLog ${APACHE_LOG_DIR}/erp_access.log erp_forensic env=!dontlog
```

---

## 2. MySQL Configuration (Layer 3: The State)
**File:** `config/mysql-logging.cnf`
**Target Location:** `/etc/mysql/conf.d/custom.cnf`

Database logging focuses on **Performance Security** (DoS prevention) rather than general query logging (which leaks PII).

### A. Disable General Query Log
```ini
[mysqld]
general_log = 0
```
*   **Why:** Logging every query (`general_log = 1`) destroys IO performance and writes sensitive data (passwords, PII) to disk in cleartext.

### B. Enable Slow Query Log (DoS Defense)
```ini
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
```
*   **Why:** Queries taking > 2 seconds are often indicators of:
    1.  **SQL Injection probing** (`SLEEP(5)`).
    2.  **DoS attempts** (Complex JOINS).
    3.  **Inefficient code** needing optimization.

### C. Index Monitoring
```ini
log_queries_not_using_indexes = 1
```
*   **Why:** Queries scanning full tables are CPU killers. Attackers abuse these to exhaust database resources.

---

## 3. PHP Forensic Engine (Layer 2 & 4: Application & Integrity)
**File:** `include/config.php`

This is a custom-built, cryptographically signed logging engine acting as a wrapper around the application.

### A. ID Poisoning Defense (Correlation Rule)
Attackers may inject a malicious `X-Request-ID` to corrupt your logs or frame a different request.
```php
$inboundID = $_SERVER['HTTP_X_REQUEST_ID'] ?? '';

// Regex Strict Allow-list: Hex Only, 16-32 chars
if (!empty($inboundID) && !preg_match('/^[a-f0-9]{16,32}$/i', $inboundID)) {
    // REJECT tainted ID and GENERATE fresh one
    define('REQUEST_ID', bin2hex(random_bytes(8)));
    define('REQUEST_ID_SOURCE', 'GENERATED_FALLBACK');
    // We flag this event to log a Security Warning later
}
```

### B. Contextual Intelligence & PII Redaction
We categorize "Context" (variables passed to logs) and sanitize them using the **Luhn Algorithm** for Credit Cards, not just Regex.

```php
function sanitize_context_data(array $context): array {
    // ...
    // Check for Credit Card Pattern
    if (preg_match_all('/\b(?:\d[ -]*?){13,19}\b/', $value, $matches)) {
         foreach ($matches[0] as $match) {
             $cleanNum = preg_replace('/\D/', '', $match);
             // VERIFY with Luhn before redacting (Prevent False Positives)
             if (is_luhn_valid($cleanNum)) {
                 $value = str_replace($match, '***REDACTED_CC***', $value);
             }
         }
    }
    // ...
}
```

### C. Hash Chaining (Integrity)
To prevent admin-level attackers from editing logs, we link every log entry to the previous one using a cryptographic hash (Blockchain-lite).

```php
// 1. Get Previous Hash (Session or Storage)
$prev_hash = $_SESSION['last_log_hash'];

// 2. Sign( Secret + PrevHash + Content )
$signaturePayload = LOG_SECRET_KEY . $prev_hash . $logContent;
$signature = hash_hmac('sha256', $signaturePayload, LOG_SECRET_KEY);

// 3. Update Memory State
$_SESSION['last_log_hash'] = $signature;

// 4. Append Signature to Log Line
$finalEntry = $logContent . " | [SIG:$signature]";
```

### D. Global Exception Trap
Catches crashes (500 Errors) that usually result in silent failures, logging the full stack trace while showing a safe user message.
```php
set_exception_handler(function (Throwable $e) {
    log_critical("Uncaught Exception: " . $e->getMessage(), [
        'trace' => $e->getTraceAsString()
    ]);
    die('An internal error occurred. Ref: ' . REQUEST_ID);
});
```

---

## 4. System & Docker Configuration
**File:** `Dockerfile`, `docker-compose.yml`, `config/logrotate.conf`

### A. Apache Module Enablement
We explicitly enable the necessary Apache modules in the `Dockerfile`.
```dockerfile
RUN a2enmod rewrite log_forensic headers ssl
```

### B. Log Rotation (Prevents Disk Exhaustion)
**File:** `config/logrotate.conf`
We configure aggressive rotation policies.

*   **PHP Logs**: Daily, Keep 30 days (`rotate 30`).
*   **Apache Logs**: Daily, Keep 14 days, Reload Apache after rotate.
*   **MySQL Logs**: Daily, Keep 7 days, Flush logs after rotate.

### C. Volume Persistence
**File:** `docker-compose.yml`
We ensure logs survive container destruction by mounting them to the host.
```yaml
volumes:
  - ./logs:/var/www/html/logs
  - ./logs/apache:/var/log/apache2
  - ./logs/mysql:/var/log/mysql
```

---

## 5. Security Principles Applied

1.  **Defense in Depth**: We log at the Network (Apache), Application (PHP), and Data (MySQL) layers.
2.  **Confidentiality**: PII is redacted *before* writing to disk.
3.  **Integrity**: Hash chaining prevents undetected modification.
4.  **Availability**: Log rotation and "Smart Filtering" prevent disk exhaustion (DoS).
