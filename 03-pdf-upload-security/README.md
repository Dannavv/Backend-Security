# 🛡️ 03. Professional PDF Security Module

A state-of-the-art, defense-in-depth PDF upload and sanitization system. This module demonstrates professional-grade strategies to handle one of the most complex and dangerous file formats: PDF.

> **Zero-Trust Semantic Architecture**: This system moves beyond naive regex scanning. It uses a hybrid model of **Semantic Tree Inspection** and **Confidence Scoring** to neutralize threats while ensuring maximum usability for legitimate documents.

---

## 💎 Premium Features

*   **🧠 Semantic JSON Analysis**: Uses `qpdf` to parse the actual logical object tree of the PDF, bypassing all known stream-based obfuscation and hex-encoding tricks.
*   **⚖️ Smart Confidence Scoring**: A weighted engine that differentiates between "Byte Noise" (false positives from regex) and "Functional Threats" (confirmed logical objects).
*   **🛡️ Structural DoS Guard**: Enforces strict resource caps on internal PDF complexity to prevent "PDF Bombs":
    *   **Objects**: Max 50,000
    *   **Pages**: Max 5,000
    *   **Streams**: Max 10,000
*   **🧼 Mandatory Sanitization**: Every accepted file is linearized and stripped of non-essential metadata using the `qpdf` re-authoring engine.
*   **🔍 Post-Sanitization Forensic Re-Scan**: A mandatory re-verification of the "cleaned" file to ensure no critical threats survived the scrub.
*   **📑 Hash-Based Reputation Sync**: Maps original file hashes to their sanitized forensic profiles for instant blocking of known malicious payloads.
*   **🔒 Secure Proxy Delivery**: Strict `Content-Security-Policy: sandbox` and `attachment` forced-download.

---

## 📁 System Architecture

```text
03-pdf-upload-security/
├── docker-compose.yml          # Container orchestration
├── Dockerfile                  # PHP 8.2 + QPDF + Poppler Security Stack
├── src/
│   ├── app.php                # 🔥 THE ENGINE: Semantic, Structural, and Regex Logic
│   ├── index.php              # Modern Security Dashboard
│   ├── upload.php             # Unified Pipeline Orchestrator
│   ├── download.php           # Secure Sandboxed Proxy
│   ├── history.php            # Forensic Audit Log & Reputation Viewer
│   └── assets/                # Premium Design System
├── test/
│   └── malicious_samples/     # ☣️ Curated Exploit Vectors (JS, Launch, Polyglot)
├── quarantine/                # 🔒 Non-Executable Storage Vault
└── logs/                      # Encrypted Transaction Logs
```

---

## 🛡️ Professional Defense Layers

| Layer | Defense | Security Goal |
| :--- | :--- | :--- |
| **1** | **Identity Audit** | SHA-256 Reputation check against the malicious signature database. |
| **2** | **Boundary Guard** | Verification of `%PDF` Magic Bytes and Truncated Trailer detection. |
| **3** | **Resource Guard** | Immediate rejection of "PDF Bombs" via object/stream count analysis. |
| **4** | **Semantic Scan** | Walking the `qpdf --json` tree to find functional `/JS`, `/Launch`, or `/Action` objects. |
| **5** | **Regex Fallback** | Deep binary scanning for secondary indicators and obfuscated anomalies. |
| **6** | **Confidence Score** | Decision engine combining hard Evidence (Semantic) and weak Signals (Regex). |
| **7** | **Authoritative Scrub** | Mandatory structural linearization and metadata destruction. |
| **8** | **Forensic Verify** | Post-sanitization re-scan to ensure 100% "Perfect-Safe" output. |

---

## 🚀 Getting Started

### 1. Launch the Stack
```bash
./start.sh
```

### 2. Access the Portal
*   **Security Dashboard**: [http://localhost:8084](http://localhost:8084)
*   **Audit History**: View detailed forensic logs via the dashboard.

### 3. Verification Testing
Upload the samples in `test/malicious_samples`:
*   `exploit_js.pdf`: Triggers Semantic JS detection.
*   `polyglot_zip.pdf`: Triggers Structural anomaly detection.
*   `pdf_bomb.pdf`: Triggers Resource Guard.

---
*Built for the Advanced Backend Security Framework*
