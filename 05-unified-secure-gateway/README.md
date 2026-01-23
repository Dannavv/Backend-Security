# 🛡️ 05. Unified Secure Gateway Infrastructure

A production-hardened, multi-engine file processing infrastructure representing the **apex** of the series. This final module integrates the defensive stratagems from **Chapter 2 (CSV)**, **Chapter 3 (PDF)**, and **Chapter 4 (Images)** into a single, high-performance **Security Perimeter** with unified orchestration and forensic intelligence.

> **The Unified Sanitization Doctrine**: Traditional detection is reactive. This gateway adopts a **"Reconstruction-First"** policy. We discard the original file container entirely, extracting only the verified data and re-authoring every document from scratch. If it doesn't survive the deconstruction, it doesn't enter the system.

---

## 💎 Integrated Module Features

### 1. 📊 CSV Guard Engine (Chapter 2 Integration)
The CSV engine protects against both **Spreadsheet Client Exploits** and **SQL Data Poisoning**.

#### 🛡️ CSV Defense Layers
| Layer | Defense | Description |
| :---: | :--- | :--- |
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

---

### 2. 📄 PDF Bastion Engine (Chapter 3 Integration)
The PDF engine is built for **Structural Deconstruction** and **Semantic Understanding**.

#### 🛡️ PDF Professional Defense Layers
| Layer | Defense | Security Goal |
| :---: | :--- | :--- |
| **1** | **Identity Audit** | SHA-256 Reputation check against the malicious signature database. |
| **2** | **Boundary Guard** | Verification of `%PDF` Magic Bytes and Truncated Trailer detection. |
| **3** | **Resource Guard** | Immediate rejection of "PDF Bombs" via object/stream count analysis. |
| **4** | **Semantic Scan** | Walking the `qpdf --json` tree to find functional `/JS`, `/Launch`, or `/Action` objects. |
| **5** | **Regex Fallback** | Deep binary scanning for secondary indicators and obfuscated anomalies. |
| **6** | **Confidence Score** | Decision engine combining hard Evidence (Semantic) and weak Signals (Regex). |
| **7** | **Authoritative Scrub** | Mandatory structural linearization and metadata destruction. |
| **8** | **Forensic Verify** | Post-sanitization re-scan to ensure 100% "Perfect-Safe" output. |

---

### 3. 🖼️ Image Sentinel Engine (Chapter 4 Integration)
The image engine follows the **"Distillation"** approach via the **Decode-or-Die** philosophy.

#### 🛡️ Image Professional Defense Layers
| Layer | Defense | Security Goal |
| :---: | :--- | :--- |
| **1** | **Traffic Guard** | Rate limiting and CSRF protection to block automation. |
| **2** | **Boundary Check** | Strict verification of file extensions and MIME types. |
| **3** | **Structure Check** | Verification of Magic Bytes signatures against the claimed MIME type. |
| **4** | **Resource Guard** | Pre-computation of `WxH` to block Pixel Flood DoS attacks. |
| **5** | **Signal Scan** | Searching raw bytes for text payloads (`<?php`, `<script`) to flag polyglots. |
| **6** | **Authoritative Scrub** | **"Decode-or-Die"** via `libvips`: Strip metadata, flatten frames, normalize. |
| **7** | **Integrity Verify** | Post-sanitization confirmation of valid image structure. |
| **8** | **Secure Delivery** | Serving via `Content-Security-Policy` and forced-download headers. |

---

## 🏗️ The 8-Layer Unified Pipeline
The Gateway orchestrates every file through a centralized high-assurance pipeline as detailed in the technical report.

---

## 📁 System Architecture

```text
05-unified-secure-gateway/
├── src/
│   ├── lib/                    # 🔥 INTEGRATED ENGINES
│   │   ├── CSVSecurity.php     # 📊 Formula Guard & Normalization
│   │   ├── PDFSecurity.php     # 📄 QPDF Semantic Sanitization
│   │   └── ImageSecurity.php   # 🖼️ Libvips Distillation Logic
│   ├── Gateway.php             # 🛰️ THE BRAIN: Air Traffic Control & Routing
│   ├── upload.php              # Orchestrator: Multi-stage pipeline execution
│   ├── index.php               # Forensic Command Center (Modern UI)
│   ├── download.php            # Secure Proxy: CSP-Hardened Sandbox
│   ├── db.php                  # Data Layer: Staging & Forensic Logs
│   ├── config.php              # Policy Center: Safety Thresholds
│   └── uploads/                # 🔒 Isolation Vault: Sanitized files only
├── test/
│   └── malicious_samples/      # ☣️ Malware Laboratory (Bombs & Polyglots)
├── logs/                       # Forensic streams
└── quarantine/               # 🔒 Isolated workbench directory
```

---

## 🛡️ Operational Security Principles

1. **Reconstruction is Law**: We never move an uploaded file to storage. We create a *new* file based on its contents.
2. **Metadata is Hostile**: All metadata is discarded by default to protect both security and user privacy.
3. **Fail-Secure Defaults**: Any parsing error or timeout results in immediate file destruction and rejection.
4. **Forensic Visibility**: Every byte removed during sanitization is measured and logged for audit purposes.

---

## 🚀 Deployment Command Center

### 1. Launch the Stack
```bash
./start.sh
```

### 2. Live Forensic Monitoring
```bash
docker-compose logs -f
```

---
*Built for the Advanced Backend Security Framework. Verified High-Assurance Code.*
*Version 5.0 - The Apex Series*
