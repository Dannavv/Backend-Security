# 🛡️ 04. Professional Image Upload Security

A state-of-the-art, defense-in-depth image upload and sanitization system. This module demonstrates professional-grade strategies to handle the most ubiquitous yet dangerous file type on the web: The Image.

> **Decode-or-Die Philosophy**: We do not trust "detection". Scanners can be fooled. Instead, we rely on **Authoritative Reconstruction**. Every image is physically decoded, stripped of all metadata, flattened (if animated), and re-encoded using `libvips`. If an image cannot survive this process, it dies.

---

## 💎 Premium Features

*   **🧱 "Decode-or-Die" Engine**: Uses `libvips` to force a full decode-and-re-encode cycle. This neutralizes structural exploits and parser vulnerabilities by discarding the original file entirely.
*   **🌊 Pixel Flood Sentinel**: Calculates total pixel count (Width × Height) before processing to block "Image Bombs" (decompression bombs) that exhaust server memory.
*   **🧹 Deep Metadata Scrubbing**: Automatically strips EXIF, XMP, IPTC, and ICC profiles where payloads, private GPS data, and copyright malware often hide.
*   **🎞️ Animation Flattening**: Forcefully converts animated formats (GIF, APNG, WebP) to a single static frame, eliminating complex attack vectors hidden in subsequent frames.
*   **🕵️ Signal-Based Detection**: A non-blocking inspection layer that flags "Suspicious Signals" (e.g., PHP tags, mismatched magic bytes) for forensic logging without interrupting the sanitization flow.
*   **🔬 Post-Sanitization Audit**: A mandatory re-verification of the "cleaned" output to ensure the sanitization process yielded a valid, safe image.
*   **📊 Forensic Delta Logging**: precise tracking of bytes removed during sanitization to quantify the "malicious" or "junk" data stripped.

---

## 📁 System Architecture

```text
04-image-upload-security/
├── docker-compose.yml          # Container orchestration
├── Dockerfile                  # PHP 8.2 + Libvips + ExifTool Stack
├── src/
│   ├── app.php                # 🔐 Global Security & Audit Logger
│   ├── ImageSecurity.php      # 🔥 THE ENGINE: Libvips, Signal Logic, Pixel Guard
│   ├── index.php              # Modern Security Dashboard
│   ├── upload.php             # Unified Pipeline Orchestrator
│   ├── download.php           # Secure Sandboxed Proxy
│   ├── history.php            # Forensic Audit Log
│   ├── config.php             # Security Constants & Limits
│   └── uploads/               # 🔒 Sanitized Storage
├── test/
│   └── malicious_samples/     # ☣️ Curated Exploit Vectors (Polyglots, Bombs)
├── quarantine/                # 🔒 Temporary Processing Vault
└── logs/                      # Encrypted Transaction Logs
```

---

## 🛡️ Professional Defense Layers

| Layer | Defense | Security Goal |
| :--- | :--- | :--- |
| **1** | **Traffic Guard** | Rate limiting and CSRF protection to block automation. |
| **2** | **Boundary Check** | Strict verification of file extensions and MIME types. |
| **3** | **Structure Check** | Verification of Magic Bytes signatures against the claimed MIME type. |
| **4** | **Resource Guard** | Pre-computation of `WxH` to block Pixel Flood DoS attacks. |
| **5** | **Signal Scan** | Searching raw bytes for text payloads (`<?php`, `<script`) to flag polyglots. |
| **6** | **Authoritative Scrub** | **"Decode-or-Die"** via `libvips`: Strip metadata, flatten frames, normalize. |
| **7** | **Integrity Verify** | Post-sanitization confirmation of valid image structure. |
| **8** | **Secure Delivery** | Serving via `Content-Security-Policy` and forced-download headers. |

---

## 🚀 Getting Started

### 1. Launch the Stack
```bash
./start.sh
```

### 2. Access the Portal
*   **Security Dashboard**: [http://localhost:8085](http://localhost:8085)
*   **Audit History**: View detailed forensic logs via the dashboard.

### 3. Verification Testing
Upload the samples in `test/malicious_samples` (if available) or create your own:
*   **Polyglot**: An image containing `<?php system($_GET['c']); ?>`.
*   **Image Bomb**: A 10000x10000 pixel image compressed to <1MB.
*   **Fake Extension**: A text file renamed to `.png`.

---
*Built for the Advanced Backend Security Framework*
