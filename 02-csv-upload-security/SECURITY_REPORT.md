# CSV Upload Security: Complete Knowledge Guide

## Part 1: The Fundamental Problem

File uploads are the highest-risk feature in any web application. CSV is particularly dangerous because:

1.  **No reliable fingerprint** — Unlike images or PDFs, CSV has no magic bytes.
2.  **Trusted by spreadsheets** — Excel/LibreOffice auto-execute certain patterns.
3.  **Processed server-side** — Imported into databases, triggering further vulnerabilities.
4.  **"Admin-only" is false comfort** — Attackers specifically target admin accounts.

---

## Part 2: The 10-Layer Defense Architecture

### Layer 1: Request Forgery (CSRF)
**Concept**: Browser automatically attaches cookies to requests. Malicious page tricks admin's browser into uploading attacker's file.
**Defense Implementation** (`src/app.php`):
```php
public static function validateCSRF(string $token): bool {
    return !empty($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
}
```
**Principle**: Unpredictable token in every form.

### Layer 2: Rate Limiting
**Concept**: Prevents Denial of Service (DoS) and brute-force attempts.
**Defense Implementation** (`src/app.php`):
```php
public static function checkRateLimit(string $ip): bool {
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    // ...
}
```
**Principle**: Per-IP limits to protect server resources.

### Layer 3: Deep Inspection (Content Disguise)
**Concept**: Filename is attacker-controlled metadata. `backdoor.php` renamed to `data.csv` is still PHP.
**Defense Implementation** (`src/app.php`):
```php
foreach (BINARY_SIGNATURES as $sig => $name) {
    if (strpos($header, $sig) !== false) return ["Violation Detected"];
}
```
**Principle**: Examine actual bytes. Executables have distinctive signatures (ELF, MZ, Shebang).

### Layer 4: Formula Guard (Injection)
**The Attack**: Cell starting with `=`, `+`, `-`, `@` executes when opened in spreadsheet.
**Defense Implementation** (`src/app.php`):
```php
if (is_string($cell) && !empty($cell) && in_array($cell[0], FORMULA_TRIGGERS, true)) {
    $cell = "'" . $cell;
}
```
**Principle**: Neutralize with apostrophe prefix. Never strip data.

### Layer 5: Encoding Shield
**Vectors**: UTF-7 bypass (`+ADw-script...`), Overlong UTF-8.
**Defense Implementation** (`src/app.php`):
```php
if (!mb_check_encoding($input, 'UTF-8')) return false;
if (mb_convert_encoding($input, 'UTF-8', 'UTF-8') !== $input) return false;
```
**Principle**: Enforce single encoding (UTF-8). Reject invalid sequences.

### Layer 6: Business Logic Validation
**Concept**: Data poisoning or privilege escalation via import (e.g., uploading negative salaries).
**Defense Implementation** (`src/app.php`):
```php
public static function validateBusinessLogic(array $row): array {
    if (isset($row['salary']) && (float)$row['salary'] < 0) $errors[] = "Negative salary";
}
```
**Principle**: Domain-specific validation. Each field has business meaning.

### Layer 7: Atomic Commit (Transaction Integrity)
**Problems without transactions**: Error at row 500 leaves 499 orphaned rows.
**Defense Implementation** (`src/app.php`):
```php
$db->beginTransaction();
// ... execute staging inserts ...
$db->commit();
```
**Principle**: Atomic operations. Staging tables prevent partial data corruption.

### Layer 8: Isolated Quarantine
**Architecture**: Processes uploads outside the public web root (`/var/quarantine/uploads`).
**Principle**: No direct URL access to uploaded files.

### Layer 9: Forensic Audit Trail
**Requirements**: Who uploaded what, when, and exact original status.
**Defense Implementation** (`src/app.php`):
```php
public static function start($batchId, $filename, $size): void {
    getDB()->prepare("INSERT INTO upload_audit (batch_id, ip_address, ...)")->execute([...]);
}
```
**Principle**: Log IP, user agent, timing, and hashes for accountability.

### Layer 10: Hardened Security Headers
**Defense Implementation** (`src/app.php`):
```php
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self' ...;");
```
**Principle**: Browser-level instructions to mitigate XSS and Clickjacking.

---

## Part 3: Operational Security & Principles

1.  **Never trust the client** — Extension, MIME type, filename are attacker-controlled.
2.  **Parse to validate** — If parser struggles, reject.
3.  **Neutralize, don't strip** — Preserve integrity while removing danger.
4.  **Fail closed** — When uncertain, reject.
5.  **Log aggressively** — Can't investigate what wasn't recorded.
6.  **Defense in depth** — Every layer can fail; overlap them.

---
