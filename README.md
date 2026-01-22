# Practical Backend Security

A comprehensive repository for mastering backend security through hands-on labs. Features improvements from the ground up, starting with secure PHP foundations. Demonstrates defense-in-depth, input sanitization, and architectural hardening for building resilient systems.

## Modules

### [01. Secure PHP Foundation](./01-secure-php-foundation/)
A secure, Dockerized procedural PHP foundation. Implementing defense-in-depth with centralized validation, sanitization, and prepared statements. Features database hardening (utf8mb4, strict mode) and secure HTTP headers to robustly block SQLi, XSS, and data leakage.

Key concepts covered:
- **Defense in Depth** architecture
- **SQL Injection Prevention** (Prepared Statements + Database Hardening)
- **Zero-Trust Validation** (Whitelisting, Type Safety, Input Hygiene)
- **HTTP Security Headers** (CSP, X-Frame-Options)
- **Information Leakage Prevention**

### [02. Secure CSV Import](./02-csv-upload-security/)
A high-security CSV processing engine designed to neutralize advanced file-based attacks. Features a 10-layer defense architecture including deep binary inspection, isolated quarantine, and formula neutralization.

Key concepts covered:
- **Formula Injection Protection** (CSV Injection Defense)
- **Binary Content Inspection** (Polyglot & Content Disguise Detection)
- **Isolated Quarantine Storage** (Outside Web Root Processing)
- **Atomic Database Transactions** (Staging-to-Production Workflow)
- **Rate Limiting & CSRF** (DoS and Request Forgery Defense)
- **Forensic Audit Trails** (IP-Targeted Action Logging)

---
*More chapters coming soon...*
