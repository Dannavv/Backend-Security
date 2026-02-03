# 🎓 Chapter 7: Security Concepts & Foundations

Understanding the **why** behind `execute_query_d1()` - how all previous chapters build up to creating a military-grade secure database query function.

---

## 🎯 The Reality: Scattered Security

Your ERP **already has most security layers** - they're just scattered across multiple files! The problem isn't missing security, it's **inconsistent application**.

### What Already Exists in ERP:

| Layer | Location | Problem |
|-------|----------|---------|
| CSRF Verification | `csrf_verify_or_die()` in 17+ files | Called manually, easy to forget |
| POST Enforcement | `require_post_method()` in security_utils.php | Rarely used |
| Input Sanitization | `sanitize_input()` - 274+ usages | Applied inconsistently |
| Rate Limiting | `rate_limit_check()` in archive/security_claude.php | Not integrated |
| Role-Based DB | `get_db_connection($role)` in config.php | ✅ Already in execute_query_d() |
| Prepared Statements | `execute_query_d()` in functions.php | ✅ Core is solid |

### The Real Problem: Pipeline is Fragmented

```
❌ Current State (Scattered)              ✅ Target State (Consolidated)
                                          
┌──────────────────────────────┐          ┌──────────────────────────────┐
│ Page: student_search.php     │          │ ANY PAGE                     │
│  ├─ csrf_verify_or_die()     │ ← Manual │       ↓                      │
│  ├─ sanitize_input()         │ ← Manual │ execute_query_d1($sql, [...],│
│  └─ execute_query_d()        │          │   ['require_csrf' => true])  │
├──────────────────────────────┤          │       ↓                      │
│ Page: form_handler.php       │          │ ┌────────────────────────┐   │
│  ├─ sanitize_input() x20     │ ← Manual │ │ Automatic Security:    │   │
│  └─ execute_query_d()        │          │ │  ✓ CSRF check          │   │
├──────────────────────────────┤          │ │  ✓ POST enforcement    │   │
│ Page: admin_complaints.php   │          │ │  ✓ Rate limiting       │   │
│  ├─ csrf_verify_or_die()     │ ← Manual │ │  ✓ Input validation    │   │
│  └─ execute_query_d()        │          │ │  ✓ Length checks       │   │
├──────────────────────────────┤          │ │  ✓ Query blacklist     │   │
│ Page: faculty_register.php   │          │ │  ✓ Error masking       │   │
│  ├─ (forgot CSRF check!)     │ ← OOPS!  │ │  ✓ Audit logging       │   │
│  └─ execute_query_d()        │          │ └────────────────────────┘   │
└──────────────────────────────┘          └──────────────────────────────┘

Problem: Developer must remember        Solution: Security is automatic
         to call each security layer             and consistent
```

### What execute_query_d1() Actually Does:

**Consolidates scattered security into ONE enforced gateway:**

```php
// BEFORE: Developer must remember each step
csrf_verify_or_die();                    // Easy to forget
$name = sanitize_input($_POST['name']);  // Inconsistent
execute_query_d($sql, ['s', $name]);     // Just the query

// AFTER: One function, automatic security
execute_query_d1($sql, ['s', $name], [
    'require_csrf' => true,   // Enforced automatically
    'require_post' => true,   // Enforced automatically
    'max_lengths' => ['name' => 100]  // Enforced automatically
]);
```


---

## 🧩 Reusable Components from Chapters 1-6

These are the **actual functions and systems** from each chapter that we can directly use or adapt for `execute_query_d1()`.

---

### From Chapter 01: `01-secure-php-foundation/src/`

| File | Function/System | Use in Chapter 7 |
|------|-----------------|------------------|
| `validator.php` | `validate_input($data, $rules)` | **Adapt for parameter validation** |
| `rules.php` | Rule array schema pattern | **Define param schemas** |
| `security.php` | HTTP security headers | Already covers web layer |

**Key code to reuse:**

```php
// From validator.php - Lines 18-21: Null-byte stripping
$value = str_replace(chr(0), '', $value);
$value = trim($value);

// From validator.php - Lines 33-39: Length validation
if (strlen($value) > $fieldRules['max_length']) {
   $errors[$field][] = "$label must not exceed {$fieldRules['max_length']} characters.";
}
```

---

### From Chapter 02: `02-csv-upload-security/src/app.php`

| Class | Method | Use in Chapter 7 |
|-------|--------|------------------|
| `CSVSecurity` | `checkRateLimit($ip)` | **Direct reuse for rate limiting** |
| `CSVSecurity` | `validateCSRF($token)` | **CSRF validation pattern** |
| `CSVSecurity` | `validateAndNormalize($input)` | **UTF-8 encoding enforcement** |

**Key code to reuse:**

```php
// Rate Limiting (Lines 92-113)
public static function checkRateLimit(string $ip): bool {
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
    $stmt->execute([$ip]);
    if ((int)$stmt->fetchColumn() >= RATE_LIMIT_PER_MINUTE) return true;
    return false;
}

// UTF-8 Validation (Lines 148-159)
public static function validateAndNormalize(string $input): ?string {
    if (!mb_check_encoding($input, 'UTF-8')) return null;
    if (preg_match('/\+[A-Za-z0-9+\/]+-/', $input)) return null; // UTF-7 bypass
    return Normalizer::normalize($input, Normalizer::FORM_C);
}
```

---

### From Chapter 05: `05-unified-secure-gateway/src/`

| File | Pattern | Use in Chapter 7 |
|------|---------|------------------|
| `Gateway.php` | Unified dispatcher pattern | **Single entry point design** |
| `config.php` | Prefixed constants | **Security configuration pattern** |

**Key pattern to adopt:**

```php
// Gateway pattern - Single entry point (Lines 22-84)
class Gateway {
    public static function handle(array $file): array {
        // 1. Extension check
        // 2. MIME validation  
        // 3. Route to specialized engine
        // 4. Return unified result
    }
}

// This becomes: execute_query_d1() as single entry for ALL queries
```

---

### From Chapter 06: `06-military-grade-logging/include/config.php`

| Function | Purpose | Use in Chapter 7 |
|----------|---------|------------------|
| `erp_log($level, $msg, $ctx)` | Structured logging | **Direct reuse for audit logging** |
| `log_security($msg, $ctx)` | Security event logging | **Log injection attempts** |
| `sanitize_context_data($ctx)` | PII redaction | **Safe logging of parameters** |
| `get_ip_details()` | Client IP detection | **Rate limiting & logging** |

**Key code to reuse:**

```php
// Structured logging (Lines 178-275)
erp_log('SECURITY', 'SQL injection attempt blocked', [
    'input' => $sanitized_input,
    'pattern' => $matched_blacklist,
    'ip' => $client_ip
]);

// PII Redaction (Lines 87-144)
// Automatically redacts: passwords, tokens, credit cards
sanitize_context_data($context);

// IP Detection with proxy support (Lines 146-176)
[$client_ip, $peer_ip] = get_ip_details();
```

---

## 🔧 Integration Map

```
execute_query_d1()
       │
       ├── POST/CSRF Check ─────────► ERP: csrf_verify_or_die() + Ch02: validateCSRF()
       │
       ├── Rate Limiting ───────────► Ch02: CSVSecurity::checkRateLimit()
       │
       ├── Input Validation ────────► Ch01: validate_input() pattern
       │                               Ch02: validateAndNormalize() for UTF-8
       │
       ├── Length Check ────────────► Ch01: max_length rule
       │
       ├── Query Blacklist ─────────► Ch02: FORMULA_TRIGGERS pattern
       │                               (adapted for SQL: SLEEP, BENCHMARK, etc.)
       │
       ├── Prepared Statement ──────► ERP: execute_query_d() [EXISTING]
       │
       ├── Error Masking ───────────► Ch01: error suppression pattern
       │
       └── Audit Logging ───────────► Ch06: erp_log(), log_security()
```

---



```php
// Blacklist catches obvious attacks before they hit the DB
if (preg_match('/;\s*(DROP|DELETE|TRUNCATE)/i', $sql)) {
    return ['success' => false, 'error' => 'Forbidden query pattern'];
}
```

---

### 2. Time-Based Blind SQLi
**Attack**: `' OR SLEEP(10) --`  
**Defense Layers**: Query blacklist (SLEEP, BENCHMARK, WAITFOR)

```php
$blacklist = [
    '/SLEEP\s*\(/i',
    '/BENCHMARK\s*\(/i',
    '/WAITFOR\s+DELAY/i',
];
```

---

### 3. Cross-Site Request Forgery (CSRF)
**Attack**: Trick user into executing query via malicious link  
**Defense Layers**: POST enforcement + CSRF token

```php
if ($options['require_post'] && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    return ['success' => false, 'error' => 'POST required'];
}
```

---

### 4. Denial of Service (DoS)
**Attack**: Flood server with queries  
**Defense Layers**: Rate limiting (per-IP)

```php
$key = 'rate_limit_' . getClientIP();
if ($this->getRequestCount($key) > SECURE_QUERY_RATE_LIMIT) {
    return ['success' => false, 'error' => 'Rate limit exceeded'];
}
```

---

### 5. Buffer Overflow / Data Truncation
**Attack**: Submit 1MB string to varchar(50) field  
**Defense Layers**: Length validation

```php
$maxLengths = ['s' => 65535, 'i' => 11, 'd' => 20];
if (strlen($value) > $maxLengths[$type]) {
    return ['success' => false, 'error' => 'Input too long'];
}
```

---

### 6. Information Disclosure
**Attack**: Trigger error to see database structure  
**Defense Layers**: Error masking

```php
// Production: generic message
// Debug: full error
return [
    'success' => false,
    'error' => SECURE_QUERY_DEBUG_MODE 
        ? $e->getMessage() 
        : 'A database error occurred'
];
```

---

## 🛡️ The Defense-in-Depth Principle

```
┌────────────────────────────────────────────────────────────────┐
│                        ATTACKER                                │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 1: WAF / Network (not in scope)                  │   │
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 2: Request Method Check                          │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 3: CSRF Token Validation                         │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 4: Rate Limiting                                 │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 5: Input Validation                              │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 6: Query Blacklist                               │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 7: Prepared Statement                            │ ← EXISTING
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Layer 8: Error Masking + Logging                       │ ← You are here
│  └────────────────────────────────────────────────────────┘   │
│                           ↓                                    │
│                       DATABASE                                 │
└────────────────────────────────────────────────────────────────┘
```

**Philosophy**: Each layer assumes ALL previous layers have failed. This way, even if an attacker bypasses one defense, the next one catches them.

---

## 📋 Security Checklist for execute_query_d1()

| Layer | Defense | Status |
|-------|---------|--------|
| 1 | POST enforcement for mutations | ⬜ To implement |
| 2 | CSRF token validation | ⬜ To implement |
| 3 | Rate limiting (100 req/min/IP) | ⬜ To implement |
| 4 | Input type validation | ⬜ To implement |
| 5 | UTF-8 encoding check | ⬜ To implement |
| 6 | Null byte removal | ⬜ To implement |
| 7 | Length enforcement | ⬜ To implement |
| 8 | Query blacklist | ⬜ To implement |
| 9 | Prepared statements | ✅ Already exists |
| 10 | Error masking | ⬜ To implement |
| 11 | Audit logging | ⬜ To implement |

---

## 🔗 Quick Reference: Attack → Defense Mapping

| Attack | Defense | Chapter Source |
|--------|---------|----------------|
| SQL Injection | Prepared statements + Blacklist | Ch 01 |
| Formula Injection | Character blocking | Ch 02 |
| Nested Payloads | Structural analysis | Ch 03 |
| Type Confusion | Strict type enforcement | Ch 04 |
| Scattered Checks | Centralized gateway | Ch 05 |
| Log Tampering | Hash-chained logging | Ch 06 |

---

*"Security is not a product, but a process." — Bruce Schneier*
