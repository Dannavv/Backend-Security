# Chapter 7: Military-Grade Secure Query Function

This chapter demonstrates `execute_query_d1()` - a consolidated security gateway that combines scattered security layers into **one enforced entry point** for all database queries.

## 🚀 Quick Start

```bash
chmod +x start.sh
./start.sh
```

**Dashboard**: http://localhost:8087

## 🔒 Security Layers (8-Layer Pipeline)

| # | Layer | What It Does | Blocks | Source |
|---|-------|--------------|--------|--------|
| 1 | **POST Method Enforcement** | Requires POST for INSERT/UPDATE/DELETE queries | CSRF via URL, browser prefetch | ERP pattern |
| 2 | **CSRF Token Validation** | Verifies cryptographic token with `hash_equals()` | Cross-site request forgery | Ch02 `validateCSRF()` |
| 3 | **Rate Limiting** | 100 queries/min/IP, tracked in database | Brute force, DoS, credential stuffing | Ch02 `checkRateLimit()` |
| 4 | **Parameter Count Check** | Maximum 50 parameters per query | Parameter pollution, memory exhaustion | New |
| 5 | **Input Validation + UTF-8** | Type check, length limit, null-byte strip, NFC normalize | SQLi, buffer overflow, encoding attacks | Ch01 + Ch02 |
| 6 | **Query Blacklist** | Blocks SLEEP, BENCHMARK, INFORMATION_SCHEMA | Time-based SQLi, schema enumeration | Ch02 adapted |
| 7 | **Prepared Statement** | Parameterized queries via `mysqli` | Classic SQL injection | ERP `execute_query_d()` |
| 8 | **Error Masking + Audit** | Safe user messages, full log with RID/IP/PII redaction | Information disclosure | Ch06 `erp_log()` |

### Layer 5 Sub-checks:
- `5a` Null byte stripping (`chr(0)` removal)
- `5b` UTF-8 encoding validation
- `5c` UTF-7 bypass detection (`+ADw-` patterns)
- `5d` Length check (default: 65,535 bytes)
- `5e` Type validation (integer, double, string, binary)
- `5f` NFC Unicode normalization

## 📁 Structure

```
07-military-grade-query/
├── include/
│   ├── security.php    ← Consolidated security functions
│   └── functions.php   ← execute_query_d1()
├── public/
│   └── index.php       ← Interactive demo dashboard
├── test_secure_query.php ← Automated test suite
└── config/
    └── init.sql        ← Database schema
```

## 🧪 Run Tests

```bash
docker exec -it ch7-secure-query php test_secure_query.php
```

## 📖 Usage

```php
// Basic usage
$result = execute_query_d1(
    "SELECT * FROM users WHERE id = ?",
    ['i', $userId],
    ['require_csrf' => true]
);

if ($result['success']) {
    $users = $result['data'];
} else {
    echo $result['error'];
}
```

## 📚 See Also

- [CONCEPTS.md](./CONCEPTS.md) - Security theory and architecture
- [Chapter 1](../01-secure-php-foundation/) - Input validation
- [Chapter 2](../02-csv-upload-security/) - Rate limiting & CSRF
- [Chapter 6](../06-military-grade-logging/) - Audit logging
