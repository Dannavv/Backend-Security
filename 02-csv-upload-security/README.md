# 02. Secure CSV Import Module

A defense-in-depth secure CSV import system designed to prevent common and advanced attacks including Formula Injection, Binary Disguise, Resource Exhaustion, and Race Conditions.

> **Security First Architecture**: Every file is treated as hostile until proven otherwise.

## ❓ Why CSV Security is Hard

CSV is not a format — it’s a **convention**. This ambiguity makes it one of the most dangerous file types to handle:

*   **The Parser + Application Gap**: Unlike PDFs, CSV has no "magic bytes" or strict spec. A file that looks like harmless text to your backend might be interpreted as **executable formulas** when opened in Excel.
*   **Data as Code**: Cell prefixes like `=`, `+`, `-`, and `@` trigger automatic execution in spreadsheet software, turning data into code at open time.
*   **Blind SQL Mapping**: Problems arise when CSVs are mapped directly to SQL fields, bypassing validation and allowing "parser breaking" tricks to poison database integrity.

## 🎯 Features

*   **Isolated Quarantine System**: Uploads are processed in a separate directory outside the web root.
*   **Strict Formula Guard**: Identifies and blocks malicious spreadsheet prefixes (`=`, `+`, `-`, `@`) to prevent CSV injection.
*   **Content-First Inspection**: Relies on real MIME detection (`finfo`) and full-file signature scanning, bypassing weak extension checks.
*   **Atomic Transactions**: Multi-stage imports ensure database integrity (all-or-nothing commit).
*   **Normalization Shield**: Detects UTF-7, Overlong UTF-8, and normalizes characters (NFC) to prevent bypasses.
*   **Forensic Audit Trail**: Detailed logging of IP, Session, User Agent, and action results for accountability.
*   **DoS Protection**: Capped error collection (max 50) prevents database and memory exhaustion from junk files.
*   **Multi-Dimensional Rate Limiting**: Tracking per IP and per Session to block sophisticated attackers.
*   **Hardened Security Headers**: CSP, HSTS, and X-Frame-Options configured by default.

## 📁 System Architecture

The application logic has been consolidated into a focused, highly auditable core:

```
02-csv-upload-security/
├── docker-compose.yml          # Container orchestration
├── src/
│   ├── app.php                # 🔥 CORE SECURITY ENGINE (All logic)
│   ├── index.php              # Dashboard UI
│   ├── upload.php             # Secure Upload Portal
│   ├── process.php            # Request Handler
│   ├── history.php            # Audit Log Viewer
│   └── assets/                # Styles
├── quarantine/                # 🔒 Isolated Storage (Outside web root)
├── logs/                      # Secure Logs
└── test/                      # Attack Vectors & Samples
```

## 🛡️ Defense Layers (Implemented in `src/app.php`)

| Layer | Defense | Description |
| :--- | :--- | :--- |
| **1** | **CSRF Protection** | Validates `hash_equals` token for every POST request. |
| **2** | **Multi-Dim Rate Limiting** | Limits uploads per IP + Session (10/min) to prevent DoS. |
| **3** | **Content-First Scan** | Uses MIME detection & full-file binary scan (ELF, EXE, PHP). |
| **4** | **Strict Formula Guard** | Rejects rows starting with dangerous triggers (`=`, `+`, `-`, `@`). |
| **5** | **Normalization Shield** | NFC Normalization + UTF-7/Overlong detection. |
| **6** | **Business Logic** | Validates data integrity (e.g. negative salaries, email formats). |
| **7** | **Atomic Commit & Cap** | Transactions for consistency + Error Capping to prevent DB DoS. |
| **8** | **Quarantine** | Processes uploads outside the public web root. |
| **9** | **Audit Trail** | Detailed forensic logs of every action, including session IDs. |
| **10** | **Hardened Headers** | Blocks XSS and Clickjacking via CSP and X-Frame-Options. |

## 🚀 Usage

### 1. Start the Environment
```bash
./start.sh
```
> This script sets up permissions, builds Docker containers, and waits for MySQL.

### 2. Access the Portal
*   **Dashboard**: [http://localhost:8082](http://localhost:8082)
*   **Database (phpMyAdmin)**: [http://localhost:8082](http://localhost:8083)

### 3. Test Attack Vectors
Try uploading files from `test/malicious_samples/`:
*   `formula_injection.csv`: Tests if the view sanitizes dangerous spreadsheet formulas.
*   `binary_disguise.csv`: Tests if the deep inspector catches executables renamed as .csv.

## 📊 Database Schema

### `csv_staging` vs `csv_imports`
*   **Staging**: Temporary holding area. If *any* row fails validation, the entire batch is rolled back.
*   **Imports**: The final destination for clean, sanitized data.

### `upload_audit`
Tracks every single upload attempt, including IP, User Agent, File Hash, and Result.

---
*Built for the Backend Security Learning Series*
