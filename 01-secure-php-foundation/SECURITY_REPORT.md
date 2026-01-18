# Security Analysis: Secure PHP Foundation
**Project:** Chapter 01: Secure PHP Foundation
**Classification:** Internal Technical Report

## 1. Input Validation Strategy ("Defense at the Edge")

The project implements a strict, centralized validation logic relying on Allow-listing (Whitelisting) rather than Blacklisting, which is the gold standard for secure input handling.

### 1.1 Centralized Rules (`src/rules.php`)
Every input field has a strict definition. This ensures that malformed data never reaches the business logic or database layer.
- **Example**: `feedback_type` uses an `allowed_values` array. If a user tries to send `feedback_type=admin_hack`, the validator rejects it before any SQL is constructed.
- **Example**: `username` enforces `/^[a-zA-Z0-9_]+$/`. This effectively neutralizes potential SQL injection payloads like `admin' --` because the `'` and `-` characters are not in the allowed regex.
- **Example**: `password` enforces complexity (`/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/`) ensuring at least one letter, one number, and 8+ characters.

### 1.2 Procedural Validator (`src/validator.php`)
A pure function `validate_input($data, $rules)` iterates through inputs.
- **Security Check**: It automatically fails if a required field is missing.
- **Type Safety**: It enforces `is_numeric` for prices and strict `filter_var` for emails.

### 1.3 Input Sanitization
Before validation rules are applied, all input data undergoes a sanitization pass:
- **Null Byte Stripping**: `str_replace(chr(0), '', $value)` removes null bytes which can be used in poisoning attacks to truncate strings in backend systems.
- **Whitespace Trimming**: Ensures data consistency.

## 2. SQL Injection Prevention

The project adheres to the "Separation of Data and Code" principle to prevent SQL Injection (SQLi), even without using PDO/ORM.

### 2.1 The Vulnerability
In standard procedural PHP, a common vulnerability looks like this:
```php
// VULNERABLE CODE
$sql = "INSERT INTO users (name) VALUES ('" . $_POST['name'] . "')";
$result = mysqli_query($conn, $sql);
```
If `$_POST['name']` is `Robert'); DROP TABLE users;--`, the database executes the malicious command.

### 2.2 The Solution: Prepared Statements (`mysqli`)
This project enforces the use of `mysqli_prepare` and `mysqli_stmt_bind_param`.

**Implementation Pattern:**
1.  **Prepare**: The SQL template is sent to the database *without* user data.
    ```php
    $stmt = mysqli_prepare($conn, "INSERT INTO users (username, email) VALUES (?, ?)");
    ```
    The `?` placeholders tell the DB "data will go here, treat it strictly as data."

2.  **Bind**: The user data is attached to the placeholders.
    ```php
    mysqli_stmt_bind_param($stmt, "ss", $username, $email);
    ```
    The DB ensures that even if `$username` contains `' OR '1'='1`, it is treated strictly as a string literal, not executable SQL.

3.  **Execute**: The query runs safely.

### 2.3 Layered Defense
Even if the Prepared Statement failed (highly unlikely), the **Input Validator** (Layer 1) would have likely rejected the SQLi payload (e.g., restricted characters in username) before it even reached the database query. This "Defense in Depth" approach provides robust security.

### 2.4 Database Hardening
- **Charset Enforcement**: The connection explicitly sets `utf8mb4` to prevent encoding-based SQL injections (like the GBK exploit).
- **Strict SQL Mode**: `STRICT_ALL_TABLES` is enforced to prevent MySQL from automatically truncating data or converting invalid values, which can obscure malicious inputs.

## 3. Information Leakage Prevention

**Vulnerability:** Default PHP/MySQL configurations often print raw database errors (e.g., "Table 'testdb.users' doesn't exist") to the screen. This allows attackers to map the internal schema.

**Remediation Implemented:**
- **Directive:** `mysqli_report(MYSQLI_REPORT_OFF)` ensures no exceptions are leaked violently.
- **Handling:** All database connections and queries are wrapped in logic that captures errors, logs them to the server-side `error_log`, and presents a sanitized "System Error" message to the end-user.

## 4. HTTP Security Hardening

**Vulnerability:** Missing headers can expose the application to Client-Side attacks.

**Measurements Taken (`src/security.php`):**
- **Anti-Clickjacking**: `X-Frame-Options: DENY` ensures the site cannot be embedded in an iframe.
- **MIME Sniffing**: `X-Content-Type-Options: nosniff` forces the browser to respect declared content types.
- **Content Security Policy (CSP)**: A strict policy restricts script and style sources to 'self' and trusted CDNs (Google Fonts), mitigating Cross-Site Scripting (XSS).
