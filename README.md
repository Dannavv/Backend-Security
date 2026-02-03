# Practical Backend Security 🛡️

A comprehensive repository for mastering backend security through hands-on labs. Features improvements from the ground up, starting with secure PHP foundations. Demonstrates defense-in-depth, input sanitization, and architectural hardening for building resilient systems.

---

## 🛰️ Module Roadmap

### [01. Secure PHP Foundation](./01-secure-php-foundation/)
A secure, Dockerized procedural PHP foundation. Implementing defense-in-depth with centralized validation, sanitization, and prepared statements. Features database hardening (utf8mb4, strict mode) and secure HTTP headers to robustly block SQLi, XSS, and data leakage.

*   **Logic**: Centralized `validator.php` and `rules.php` for uniform security application.
*   **Defense**: Prepared SQL statements and HSTS/CSP security headers.

### [02. Secure CSV Import](./02-csv-upload-security/)
A high-security CSV processing engine designed to neutralize advanced file-based attacks. Features a 10-layer defense architecture including deep binary inspection, isolated quarantine, and formula neutralization.

*   **Logic**: Row-by-row validation with atomic database transactions.
*   **Defense**: Formula injection blocking (`=`, `@`, `+`) and binary signature scanning.

### [03. PDF Upload Security](./03-pdf-upload-security/)
Advanced structural analysis and sanitization for PDF documents. Moving beyond simple detection to authoritative reconstruction of complex document trees.

*   **Logic**: QPDF-based structural analysis and JSON tree inspection.
*   **Defense**: JavaScript dictionary destruction and cross-reference table linearization.

### [04. Professional Image Security](./04-image-upload-security/)
A "Decode-or-Die" image processing pipeline. Uses high-performance libraries to rebuild images from raw pixel data, destroying steganographic and polyglot payloads.

*   **Logic**: libvips distillation and pixel-flood Dos protection.
*   **Defense**: Metadata stripping (EXIF/GPS), animation flattening, and re-encoding.

### [05. Unified Secure Gateway](./05-unified-secure-gateway/)
The pinnacle of the series: A centralized, multi-engine security perimeter. Combines the specialized logic of all previous modules into a single dispatcher with randomized identity and high-fidelity forensic audit trails.

*   **Logic**: Functional gateway routing with isolated engine isolation.
*   **Defense**: Multi-layer Ingress Protection and high-assurance sanitization authority.

### [06. Military-Grade Logging](./06-military-grade-logging/)
Enterprise-grade audit logging system with forensic capabilities. Implements structured logging with request IDs, IP detection, PII redaction, and tamper-evident log files.

*   **Logic**: Centralized `erp_log()` function with contextual metadata.
*   **Defense**: Automatic PII masking, Luhn validation for credit cards, structured JSON output.

### [07. Military-Grade Secure Query](./07-military-grade-query/)
The ultimate secure database gateway: An 8-layer security pipeline consolidated into a single `execute_query_d1()` function. Replaces 237 scattered security implementations with one enforced entry point.

*   **Logic**: Sequential validation pipeline with early rejection and full audit trail.
*   **Defense**: POST enforcement, CSRF, rate limiting, input validation, query blacklist, prepared statements, error masking.
*   **Layers**:
    | # | Layer | Blocks |
    |---|-------|--------|
    | 1 | POST Method | CSRF via URL |
    | 2 | CSRF Token | Cross-site forgery |
    | 3 | Rate Limiting | Brute force, DoS |
    | 4 | Param Count | Memory exhaustion |
    | 5 | Input Validation | Encoding attacks |
    | 6 | Query Blacklist | SLEEP, BENCHMARK |
    | 7 | Prepared Stmt | SQL injection |
    | 8 | Error Masking | Info disclosure |

---

## 🛠️ Global Technology Stack
Each module is isolated and containerized for zero-friction deployment:
- **Runtime**: PHP 8.2 (Hardened configuration)
- **Database**: MariaDB 10.6 (Atomic staging tables)
- **Orchestration**: Docker & Docker Compose
- **Security Tools**: QPDF, Libvips, Poppler-Utils, PHP-Intl

---
*Built for the Advanced Backend Security Framework*
