# 🛡️ 05. Unified Secure Gateway Infrastructure

A production-hardened, multi-engine file processing infrastructure representing the **apex** of the series. This final module integrates the defensive stratagems from **Chapter 2 (CSV)**, **Chapter 3 (PDF)**, and **Chapter 4 (Images)** into a high-performance **Security Perimeter** with unified orchestration and forensic intelligence.

> **The Unified Sanitization Doctrine**: Traditional detection is reactive. This gateway adopts a **"Reconstruction-First"** policy. We discard the original file container entirely, extracting only the verified data and re-authoring every document from scratch. If it doesn't survive the deconstruction, it doesn't enter the system.

---

## 💎 Integrated Module Features

### 1. 📊 CSV Guard Engine (The Data-Integrity Core)
- **Formula Guard Authority**: A non-bypassable validator for spreadsheet command triggers (`=`, `@`, `+`, `-`).
- **NFC Normalization Shield**: Enforces UTF-8 (NFC) encoding to kill UTF-7 and overlong-encoding bypasses.
- **Atomic Staging Workflow**: Implements a "Staging-to-Production" commit model. Files are validated row-by-row in an isolated table before commitment.

### 2. 📄 PDF Bastion Engine (The Structural Guardian)
- **Semantic Tree Inspection**: Uses `qpdf` engines to walk the actual logical object tree, neutralizing `/JS`, `/Launch`, and `/OpenAction` directives.
- **Linearized Re-Authoring**: Physically rewrites the PDF to flatten XRef tables, destroying "Chameleon" polyglots hidden in document streams.
- **Structural DoS Guard**: Enforces hard complexity caps (Object count <50,000) to block "PDF Bombs."

### 3. 🖼️ Image Sentinel Engine (The Pixel Sentinel)
- **"Distillation" Reconstruction**: Uses `libvips` to decode images into raw pixel buffers and re-encode them, stripping all metadata (EXIF/GPS) automatically.
- **Pixel-Flood Defense**: Pre-computes the uncompressed bitmap size to prevent memory-exhaustion attacks from "Image Bombs."
- **Animation Flattening**: Forcefully reduces complex animated formats to a single static frame to minimize attack surface.

---

## 🏗️ The 8-Layer Professional Defense Pipeline

The Gateway orchestrates every file through a centralized high-assurance pipeline:

| Layer | Component | Deep Security Detail |
| :---: | :--- | :--- |
| **1** | **Ingress Perimeter** | `finfo` byte-matching + Strict Extension Allow-list. Blocks extension spoofing. |
| **2** | **Identity Sanitization** | Cryptographically secure UUID renaming + Zero-Trust path isolation. |
| **3** | **Structural Sentinel** | Pre-parsing for resource caps: Pixel count (Images), Object count (PDF), and Row caps (CSV). |
| **4** | **Signal Intelligence** | Multi-pattern signature scanning for `<?php`, `system()`, and shellcode markers. |
| **5** | **Semantic Authority** | Parser-level tree analysis. Understanding the *meaning* of the data, not just the bytes. |
| **6** | **Authoritative Scrub** | **RECONSTRUCTION**: QPDF Linearization, Vips Distillation, and NFC Normalization. |
| **7** | **Post-Sanitize Audit** | Mandatory secondary scan of the "cleaned" file to ensure structural safety. |
| **8** | **Forensic Commitment** | SHA-256 integrity hashing and detailed "Threat Delta" logging in the Database. |

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
└── quarantine/                 # 🔒 Isolated workbench directory
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
