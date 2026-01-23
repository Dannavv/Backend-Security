# 🛡️ 05. Unified Secure Gateway Infrastructure

A production-hardened, multi-engine file processing infrastructure. This final module integrates the defense strategies from Chapters 2 (CSV), 3 (PDF), and 4 (Images) into a single, high-assurance **Security Perimeter** that treats every byte as hostile.

> **Multi-Engine Philosophy**: We do not rely on a single defensive layer. Instead, we route every file to a specialized **Sanitization Authority**. Every file is structurally analyzed, physically reconstructed (Decode-or-Die), and stripped of all hidden payloads. If a file cannot be fully verified and scrubbed, it is rejected.

---

## 💎 Premium Features

*   **🛰️ Unified Dispatch Engine**: A central gateway that performs strict ingress filtering and routes files to specialized isolated security cores based on true MIME identity.
*   **📄 PDF Reconstruction Bastion**: Uses `qpdf` for authoritative structural reconstruction. It flattens xref tables, destroys incremental updates, and strips all interactive dictionaries.
*   **📊 CSV Semantic Guard**: Implements row-by-row data sanitization with strict UTF-8 (NFC) normalization and formula injection blocking triggers.
*   **🖼️ Image Distillation Citadel**: Employs `libvips` for pixel-level reconstruction. It flattens frames, strips steganographic metadata, and re-encodes from raw buffers.
*   **🧪 Active Polyglot Defense**: A deep-inspection layer that identifies hybrid files (e.g., PDF+ZIP or JPEG+PHP) by scanning for discordant signatures across the entire file body.
*   **📔 Centralized Forensic Audit**: A unified logging system that captures the "Threat Delta" (what was stripped), SHA-256 integrity hashes, and engine-specific forensic details.
*   **🌊 Global Resource Sentinel**: Enforces hard structural limits (Object counts, Pixel floods, Row caps) before any complex parsing begins to block DoS vectors.

---

## 📁 System Architecture

```text
05-unified-secure-gateway/
├── docker-compose.yml          # Global container orchestration
├── Dockerfile                  # Unified Stack (Vips, QPDF, GD, Intl)
├── src/
│   ├── lib/
│   │   ├── CSVSecurity.php     # 📊 CSV Guard Engine
│   │   ├── PDFSecurity.php     # 📄 PDF Shield Engine
│   │   └── ImageSecurity.php   # 🖼️ Image Sentinel Engine
│   ├── Gateway.php             # 🛰️ THE DISPATCHER: Ingress & Routing Logic
│   ├── index.php               # Modern Security Dashboard
│   ├── upload.php              # Multi-Engine Orchestrator
│   ├── download.php            # Secure Sandboxed Proxy
│   ├── db.php                  # Forensic Database & Headers
│   ├── config.php              # Global Security Constants
│   └── uploads/                # 🔒 Hardened Sanitized Storage
├── test/
│   └── malicious_samples/      # ☣️ Universal Exploit Vault
├── quarantine/                 # 🔒 Multi-Stage Processing Vault
└── logs/                       # Encrypted Transaction Streams
```

---

## 🛡️ Professional Defense Layers

| Layer | Defense | Security Goal |
| :--- | :--- | :--- |
| **1** | **Ingress Perimeter** | Strict extension and `finfo` MIME verification to block spoofing. |
| **2** | **Identity Randomization** | Renaming to 128-bit hex UUIDs to prevent traversal and discovery. |
| **3** | **Structural Logic** | Parsing the logical tree (PDF Objects, CSV Rows, Image Pixels) to ignore junk. |
| **4** | **Resource Guard** | Enforcing Object, Page, Pixel, and Row limits before processing. |
| **5** | **Deep Signal Scan** | Content-wide signature matching for EXE, PHP, and Shellcode markers. |
| **6** | **Authoritative Scrub** | **"Decode-or-Die"** reconstruction via specialized tools (QPDF, Vips, Normalizer). |
| **7** | **Integrity Check** | Post-process verification of the sanitized asset's structural health. |
| **8** | **Caged Delivery** | Safe serving via `Content-Security-Policy: sandbox` and forced downloads. |

---

## 🚀 Getting Started

### 1. Launch the Gateway
```bash
./start.sh
```

### 2. Access the Portal
*   **Security Command Center**: [http://localhost:8085](http://localhost:8085)
*   **Audit Trail**: Real-time forensic integrity logs available on the main dashboard.

### 3. Verification Testing
Upload the cross-format samples in `test/malicious_samples` to see the gateway in action:
*   **Polyglot Bomb**: A file that is both a valid PDF and a valid ZIP.
*   **CSV Formula**: A CSV file containing Excel command injection strings.
*   **Image Steno**: A JPEG containing hidden Javascript in an ICC profile.

---
*Built for the Advanced Backend Security Framework*
