# CSV Upload Security: Complete Knowledge Guide

## Part 1: The Fundamental Problem

Because **CSV is not a format — it’s a *convention***. This is where most security vulnerabilities begin.

### Why CSV is Tricky
Unlike PDFs or images, CSV suffers from a "Parser + Application" gap:

*   **No Real Spec**: RFC 4180 is widely ignored or treated as optional.
*   **No Magic Bytes**: There is no unique binary signature to verify file integrity.
*   **Parser Disagreement**: Different parsers handle quotes, escapes, and newlines in conflicting ways.
*   **Application Ambiguity**: CSVs are often opened by **Excel**, not just programmatic parsers.
*   **Data as Code**: Excel treats certain cell prefixes (`=`, `+`, `-`, `@`) as **formulas**, meaning data becomes executable code at open time.

### The SQL Connection
CSV is dangerous when it becomes **untrusted input for SQL**:

*   **Bypassing Validation**: Direct CSV → SQL imports often skip standard application-level validation.
*   **Breaking Parsers**: Advanced formula or quote tricks can "break" the parser, leading to malformed queries.
*   **Encoding Shifts**: Subtle encoding issues can change the meaning of a query between the parser and the database.
*   **Impact Amplification**: Bulk inserts allow a single file to poison thousands of records instantly.

CSV isn’t dangerous by itself—it’s dangerous **when blindly mapped to SQL fields**.

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

### Layer 2: Rate Limiting (Multi-Dimensional)
**Concept**: Prevents Denial of Service (DoS) and brute-force attempts.
**Defense Implementation** (`src/app.php`):
```php
public static function checkRateLimit(string $ip): bool {
    // 1. IP-based tracking
    // 2. Session-based tracking (prevents IP rotation bypass)
}
```
**Principle**: Per-IP and Per-Session limits to protect server resources.

### Layer 3: Content-First Deep Inspection
**Concept**: Filename and extension are attacker-controlled. `backdoor.php` renamed to `data.csv` is still PHP.
**Defense Implementation** (`src/app.php`):
```php
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($file); // Real MIME detection
// Full Content Scan
foreach (BINARY_SIGNATURES as $sig => $name) {
    if (strpos($content, $sig) !== false) return ["Violation Detected"];
}
```
**Principle**: Trust content, not metadata. Full-file scanning catches polyglots hidden beyond the header.

### Layer 4: Formula Guard (Injection)
**The Attack**: Cell starting with `=`, `+`, `-`, `@` executes when opened in spreadsheet.
**Defense Implementation** (`src/app.php`):
```php
public static function validateFormulas(array $row): ?string {
    foreach ($row as $cell) {
        if (is_string($cell) && in_array($cell[0], FORMULA_TRIGGERS, true)) {
            return "Formula Injection Detected";
        }
    }
}
```
**Principle**: Reject/Block malicious rows. Never allow executable patterns into the database.

### Layer 5: Encoding & Normalization Shield
**Vectors**: UTF-7 bypass (`+ADw-script...`), Overlong UTF-8, and malformed character sequences.
**Defense Implementation** (`src/app.php`):
```php
if (!mb_check_encoding($input, 'UTF-8')) return false;
// Normalization (NFC) prevents bypasses via alternative byte sequences
$normalized = Normalizer::normalize($input, Normalizer::FORM_C);
```
**Principle**: Enforce single encoding (UTF-8) and normalize characters to prevent visual spoofing or filter bypasses.

### Layer 6: Business Logic Validation
**Concept**: Data poisoning or privilege escalation via import (e.g., uploading negative salaries).
**Defense Implementation** (`src/app.php`):
```php
public static function validateBusinessLogic(array $row): array {
    if (isset($row['salary']) && (float)$row['salary'] < 0) $errors[] = "Negative salary";
}
```
**Principle**: Domain-specific validation. Each field has business meaning.

### Layer 7: Atomic Commit & DoS Protection
**Problems**: Partial data corruption or Database DoS via millions of validation errors.
**Defense Implementation** (`src/app.php`):
```php
$db->beginTransaction();
if (count($errors) < MAX_ERROR_COUNT) { // Error Capping
    $errors[] = "...";
}
// Fail-Closed: Only commit if errors == 0
$db->commit();
```
**Principle**: Atomic operations. Staging tables prevent corruption; error capping prevents resource exhaustion.

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
