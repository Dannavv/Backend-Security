# PDF Upload Security: Complete Knowledge Guide

## Part 1: The Fundamental Problem

The PDF format is not merely a document format — it is a **dynamic execution environment**. This makes it one of the most dangerous vectors in modern web security.

### Why PDF is a Security Nightmare
Unlike static formats, PDF is a "Swiss Army Knife" of capabilities that bridge the gap between documents and executable code:

*   **Active Scripting**: The PDF specification allows for embedded **JavaScript** (`/JS`, `/JavaScript`) that can execute within many PDF viewers.
*   **Automatic Triggers**: Commands like `/OpenAction` or `/AA` (Additional Actions) can trigger tasks immediately upon opening.
*   **External Execution**: The `/Launch` command can attempt to execute external binaries or open malicious links.
*   **The Polyglot Haven**: PDF's flexible structure (allowing content before the header or after the trailer) makes it perfect for **Polyglot Attacks**—hiding a ZIP, JAR, or HTML file inside a valid PDF.
*   **Dynamic Parsing**: PDF uses a complex cross-reference (`xref`) system. Attackers can provide malformed or "Chameleon" structures that bypass security scanners but execute in the victim's viewer.
*   **Resource Bombs**: A "PDF Bomb" uses deeply nested objects or massive object counts (500,000+) to crash the parser or service (Denial of Service).

---

## Part 2: The 8-Layer Professional Defense Pipeline

### Layer 1: Identity & Reputation (Audit & Hash)
**Concept**: Re-scanning the same malicious payload is expensive and slow.
**Defense Implementation** (`src/app.php`):
```php
$fileHash = hash_file('sha256', $tmpName);
$reputation = ReputationEngine::check($fileHash);
if ($reputation['status'] === 'malicious') return ["Known malicious file"];
```
**Principle**: Use SHA-256 signatures to build a "Known Bad" blocklist for instant rejection.

### Layer 2: Boundary & Integrity Guard
**Concept**: Verifying the PDF is not a polyglot hiding malicious payloads at the file edges.
**Defense Implementation** (`src/app.php`):
```php
if (strpos($header, '%PDF-') !== 0) return ["Invalid header"];
if (strpos($trailer, '%%EOF') === false) $findings[] = "Malformed trailer";
```
**Principle**: Enforce strict absolute boundaries. A file must start with `%PDF` and end with `%%EOF`.

### Layer 3: Resource Guard (DoS Prevention)
**Concept**: Preventing "PDF Bombs" from exhausting CPU/Memory.
**Defense Implementation** (`src/app.php`):
```php
if ($results['object_count'] > 50000) return ["Object limit exceeded"];
if ($results['page_count'] > 5000) return ["Page limit exceeded"];
```
**Principle**: Enforce hard structural limits before deep parsing.

### Layer 4: Semantic JSON Tree Inspection (The Authority)
**The Attack**: Regex can be bypassed with hex-encoding (e.g., `/#4a#53` for `JS`). 
**The Solution** (`src/app.php`):
```php
// Walk the actual logical tree parsed into JSON
if (self::arraySearchRecursive($json_objects, 'JS')) {
    $findings[] = "Semantic JS Detected";
}
```
**Principle**: Use a parser to understand the *meaning* of the file, not just the bytes. Regex is a fallback, but the Semantic Tree is the Authority.

### Layer 5: Smart Confidence Scoring
**Concept**: Don't reject legitimate files based on "noisy" regex hits (like metadata signatures).
**Principle**: Differentiate between **Semantic Hits** (10 points - Reject/Sanitize) and **Regex Noise** (3 points - Sanitize). Only confirmed structural threats trigger rejection.

### Layer 6: Authoritative Sanitization (The "Scrub")
**Concept**: Neutralizing hidden threats by re-authoring the file.
**Defense Implementation** (`src/app.php`):
```bash
qpdf --linearize --remove-metadata input.pdf output.pdf
```
**Principle**: Physically rewrite the PDF. Linearization flattens incremental updates and destroys non-referenced objects where payloads hide.

### Layer 7: Forensic Post-Sanitization Re-Scan
**Concept**: Trust but verify. Did the "Scrub" actually work?
**Defense Implementation** (`src/upload.php`):
```php
$postFindings = PDFSecurity::validateFile(['tmp_name' => $sanitized_path]);
// Compare pre-scan vs post-scan findings
```
**Principle**: A sanitized file is only cleared if the post-scan confirms critical threats were successfully neutralized.

### Layer 8: Delivery Hardening (Locked Proxy)
**Concept**: Isolate the PDF if it ever reaches the browser.
**Defense Implementation** (`src/download.php`):
```php
header('Content-Disposition: attachment'); // Force Download
header('Content-Security-Policy: sandbox'); // Disable Scripts
```
**Principle**: Prevent in-browser rendering and disable script execution at the network layer.

---

## Part 3: Operational Principles

1.  **Parser Authority** — Bytes can lie; the logical object tree does not.
2.  **Zero Trust for Metadata** — Metadata is for machines; assume it contains payloads and strip it.
3.  **Linearize by Default** — Rebuilding the file is the most effective neutralization strategy.
4.  **Resource Caps** — A secure system must first be a stable system.
5.  **Fail-Closed** — If the QPDF parser crashes or throws integrity warnings, the file is malicious until proven otherwise.

---
*Technical Security Audit - Professional Backend Security Framework*
