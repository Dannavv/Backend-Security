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
*   **Formula Neutralization**: Prevents Excel/Spreadsheet RCE via CSV Injection prefixes.
*   **Deep Content Inspection**: Scans binary signatures to detect polyglot attacks and disguised executables.
*   **Atomic Transactions**: Multi-stage imports ensure database integrity (all-or-nothing).
*   **Encoding Shield**: Detects UTF-7 and Overlong UTF-8 bypass attempts.
*   **Forensic Audit Trail**: Detailed logging of IP, User Agent, and action results for accountability.
*   **Business Logic Validation**: Domain-specific data integrity checks (e.g., non-negative values).
*   **Rate Limiting & CSRF**: Built-in protection against DoS and request forgery.
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
| **2** | **Rate Limiting** | Limits uploads to 10/min per IP to prevent DoS. |
| **3** | **Deep Inspection** | Scans file headers for binary signatures (ELF, EXE, PHP). |
| **4** | **Formula Guard** | Prefixes cells starting with `=`, `+`, `-`, `@` with `'`. |
| **5** | **Encoding Shield** | Detects UTF-7/Overlong encoding bypass attempts. |
| **6** | **Business Logic** | Validates data integrity (e.g. negative salaries, email formats). |
| **7** | **Atomic Commit** | Uses DB transactions to ensure data consistency. |
| **8** | **Quarantine** | Processes uploads outside the public web root. |
| **9** | **Audit Trail** | Detailed forensic logs of every action. |
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
