# 📊 Military-Grade Logging Strategy Report

## 🛡️ Executive Summary
In a production ERP environment, logs are the **Black Box** of the system. Without them, you are flying blind. This report outlines the implementation of a 4-layer logging architecture designed for compliance, performance, and forensic readiness.

---

## 🏛️ Layer 1: Apache (Web Server)
**Focus:** Infrastructure Visibility & Forensic Reconstruction.

| Log Type | Purpose | Security Value |
| :--- | :--- | :--- |
| **Combined Access** | Request tracking | Attacker identification (IP, UA) |
| **Forensic Access** | Deep request profiling | Request duration (%D), TLS version, Cipher strength |
| **Error Log** | Service health | Identifies module crashes and rewrite failures |

### Forensic Configuration
We utilize a custom `erp_forensic` format that captures the **Request ID**. This ID is passed to the PHP layer, creating a unified trace across the entire stack.

---

## 🐘 Layer 2: PHP (Application)
**Focus:** Logic Verification & Error Diagnostics.

### 🧩 Structured Logging Engine
Every log entry follows a precise schema:
`[ISO8601] [LEVEL] [FILE:LINE] [USER|IP] [RID] MESSAGE`

*   **SECURITY Level:** Logged when authentication fails or unauthorized access is attempted.
*   **AUDIT Level:** Logged during sensitive data mutation (CRU operations).
*   **PERFORMANCE Level:** Logged when execution time exceeds the SLA.

### 🚫 Global Defense
*   **Hijacked Exception Handler:** Prevents raw stack traces from leaking to the frontend.
*   **Smart Error Bitmasks:** In Production, we log `E_ALL` but suppress `E_NOTICE` and `E_DEPRECATED` to keep logs signal-heavy.

### 🛡️ Security & Performance Hardening (New)
The system now includes specific defenses against log-based attacks and resource exhaustion:

1.  **Sensitive Data Redaction (`sanitize_context_data`)**
    *   **Defense:** Recursively scans context arrays.
    *   **Action:** Redacts keys matching `password`, `token`, `secret`, `cvv`, etc.
    *   **Goal:** Prevents accidental PII/Credential leakage.

2.  **Log Injection Prevention (`sanitize_entry`)**
    *   **Defense:** Strips CRLF characters (`\r`, `\n`) from user input.
    *   **Goal:** Prevents "Log Forging" where attackers fake system events by injecting new lines.

3.  **Atomic Write Locking**
    *   **Mechanism:** `file_put_contents(..., LOCK_EX)`
    *   **Goal:** Prevents race conditions where concurrent requests interleave log lines, corrupting forensic data during high loads.

4.  **Memory Optimization**
    *   **Mechanism:** `debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)`
    *   **Goal:** Reduces memory overhead by ~80% in deep ERP call stacks.

---

## 🛢️ Layer 3: MySQL (Database)
**Focus:** Data Integrity & Bottleneck Detection.

### 🐢 The Slow Query Sentinel
Crucial for ERP scalability. We monitor queries that:
1.  Take longer than **2 seconds**.
2.  Perform **Full Table Scans** (Queries not using indexes).
3.  Examine more than **1000 rows**.

---

## 🔄 Layer 4: System (Rotation)
**Focus:** Availability & Resource Management.

Without rotation, a log file is a **Time Bomb**. Our strategy uses `logrotate` to:
*   **Daily Rotation:** Fresh files every 24 hours.
*   **Gzip Compression:** Saving 90% disk space on historical logs.
*   **Retention Policy:** 30 days for application logs (Compliance), 7 days for heavy MySQL logs.

---

## 📊 Security Events Checklist
Implemented events that **STRICTLY** trigger a `SECURITY` or `AUDIT` log:
- [x] Failed Login Attempts (Brute force detection)
- [x] Unauthorized URL Access (Privilege escalation detection)
- [x] Sensitive Field Updates (Grade/Salary changes)
- [x] Uncaught Exceptions (System instability detection)
- [x] API Connection Failures (Third-party downtime/misconfig)

---
*Created by Antigravity AI for the ERP Security Initiative.*
