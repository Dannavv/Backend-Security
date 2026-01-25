# 🛡️ 06. Military-Grade Logging Architecture

A production-hardened, multi-layer logging infrastructure representing the **forensic backbone** of the series. This module implements a "Black Box" flight recorder for ERP systems, ensuring total traceability, performance monitoring, and tamper-evident audit trails.

> **The Traceability Doctrine**: Logs are not just text files; they are **legal evidence**. This system treats logging as a first-class security citizen, ensuring that *WHO* did *WHAT*, *WHEN*, and *WHY* is irrefutably recorded, cryptographically chained, and structurally strictly formatted.

---

## 💎 Integrated Module Features

### 1. 🛡️ Forensic Application Engine (PHP)
The PHP engine implements **defense-in-depth logging** with structured data and integrity checks.

#### 🛡️ Logging Defense Layers
| Layer | Defense | Description |
| :---: | :--- | :--- |
| **1** | **Structured Data** | Logs as `[TIMESTAMP] [LEVEL] [RID] MESSAGE | JSON_CONTEXT` for machine parsing. |
| **2** | **Correlation IDs** | Unique `Request-ID` tracing across Apache, PHP, and Database layers. |
| **3** | **Hash Chaining** | **Blockchain-Lite**: Each log line is cryptographically signed using the previous line's hash. |
| **4** | **Tamper Evidence** | Detection of deletion, reordering, or modification of log entries. |
| **5** | **Context Awareness** | Auto-captures User ID, Role, Client IP, and Peer IP for every event. |
| **6** | **Global Traps** | Hijacked Exception/Error handlers to catch *everything*, preventing silent failures. |
| **7** | **DoS Protection** | Caps log message size (2KB) and Context JSON (8KB) to prevent disk exhaustion. |
| **8** | **PII Redaction** | Automatic scrubbing of Credit Cards (Luhn check) and Bearer Tokens. |

---

### 2. 🏗️ Infrastructure & Data Engine (Apache & MySQL)
The base layers provide raw access data and performance metrics.

#### 🛡️ Infrastructure Defense Layers
| Layer | Defense | Security Goal |
| :---: | :--- | :--- |
| **1** | **Forensic Access** | Apache logs include Duration (`%D`), TLS Cipher, and Request IDs. |
| **2** | **Slow Query Sentinel** | MySQL captures queries >2s or strictly strictly unindexed scans. |
| **3** | **Noise Filtering** | Configured to ignore internal loops and keep signals high-fidelity. |
| **4** | **Log Rotation** | Daily rotation with GZIP compression to prevent "Suicide by Log Volume". |
| **5** | **Strict Permissions** | Log directories locked down to prevent unauthorized read/write. |

---

## 📂 System Architecture

```text
06-military-grade-logging/
├── include/
│   ├── config.php              # ⚙️ LOGGING CORE: Configuration & format definitions
│   └── functions.php           # 🧠 HELPER: Timezones & Utilities
├── public/
│   ├── index.php               # 🖥️ DASHBOARD: Trigger events & View logs
│   ├── css/                    # 🎨 Styles for the dashboard
│   └── js/                     # ✨ Interactive elements
├── config/
│   ├── apache-logging.conf     # 🌐 APACHE: Custom LogFormat directives
│   └── mysql-logging.cnf       # 🛢️ MYSQL: Slow query & Error settings
├── logs/                       # 📂 LIVE STREAMS (In production, ship these out)
│   ├── app.log                 # 📝 General Application Flow
│   ├── security.log            # 🚨 Auth Failures & Attacks (High Priority)
│   ├── audit.log               # ⚖️ Data mutations (Grade changes, etc)
│   └── performance.log         # 🐢 Slow operations & Latency
├── test_logging.php            # 🧪 UNIT TEST: Validation of logging functions
├── test_forensic.php           # 🕵️ FORENSIC TEST: Chain verification
└── start.sh                    # 🚀 LAUNCHER: Environment setup
```

---

## 🛡️ Operational Security Principles

1.  **Observability is Security**: You cannot secure what you cannot see. We log successful *and* failed security events.
2.  **Logs are Targets**: We assume attackers will try to delete or modify logs cover their tracks. Hash chaining makes this mathematically detectable.
3.  **Fail-Silent Frontend**: Users see "An error occurred", while admins see the full stack trace in the logs.
4.  **Assumed Breach**: We log assuming the network is hostile, capturing Peer IPs and X-Forwarded-For chains.

---

## 🚀 Deployment Command Center

### 1. Launch the Stack
```bash
./start.sh
```

### 2. Live Forensic Monitoring
```bash
# Watch the Security Stream in real-time
tail -f logs/security.log
```

### 3. Verify Integrity
```bash
# Run the tamper-evidence check
php test_forensic.php
```

---
*Built for the Advanced Backend Security Framework. Verified High-Assurance Code.*
*Version 6.0 - The Forensic Series*
