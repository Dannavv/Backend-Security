# Security Integrity Report: Unified Gateway Infrastructure 🛰️

## Part 1: The Fundamental Problem

The modern web application faces a **"Convergence of Threats"**. Attackers no longer rely on single-file exploits; they use **Hybrid Attacks (Polyglots)** and **Parser Disagreement** across multiple file formats (CSV, PDF, Images) to bypass standard security filters.

### Why a Unified Gateway is Necessary
Generic upload handlers suffer from several fatal flaws that this gateway resolves:

*   **The Identity Crisis**: Relying on extensions (`.jpg`) or client-side MIME types is a security failure. An attacker can rename a PHP shell to `.pdf` to bypass simple filters.
*   **The Parser Gap**: A scanner might see a file as safe, but the final application (Excel, Acrobat, Browser) might interpret hidden bytes as executable code.
*   **Payload Obfuscation**: Malicious code can be hidden in "Dark Data" regions (Metadata, Deleted XRef objects, ICC profiles) that standard validators never touch.
*   **Resource Exhaustion**: Without a global resource sentinel, a single file (PDF Bomb or Pixel Flood) can crash the entire processing service.

---

## Part 2: The Multi-Layer Defense Architecture

### Layer 1: Ingress Isolation & Identity Lockdown
**Concept**: Stop the attack at the perimeter. Filename and extension are treated as hostile untrusted inputs.
**Defense Implementation** (`src/Gateway.php`):
```php
$mime = $finfo->file($file['tmp_name']); // True Identity
if ($mime !== $expectedMime) {
    return ['status' => 'rejected', 'error' => "Mismatched MIME type"];
}
$sanitizedName = bin2hex(random_bytes(16)) . '.' . $ext; // Identity Neutralization
```
**Principle**: Trust Magic Bytes, not extensions. Randomize naming to prevent directory traversal.

### Layer 2: PDF Structural Reconstruction
**Concept**: Treat documents as executable environments.
**Defense Implementation** (`src/lib/PDFSecurity.php`):
```bash
qpdf --linearize --remove-metadata input.pdf output.pdf
```
**Principle**: **Authoritative Reconstruction**. Use QPDF to rebuild the object tree, flattening incremental updates and destroying interactive dictionaries where payloads hide.

### Layer 3: CSV Semantic Integrity
**The Attack**: Command execution via spreadsheet formula injection (`=DDE()`).
**Defense Implementation** (`src/lib/CSVSecurity.php`):
```php
if (in_array($cell[0], ['=', '+', '-', '@'], true)) {
    return "Formula Injection Detected";
}
// Normalize to NFC to prevent encoding bypasses
$normalized = Normalizer::normalize($input, Normalizer::FORM_C);
```
**Principle**: Data interpretation is security. Block leading triggers and enforce a single normalized encoding (UTF-8) across the entire dataset.

### Layer 4: Image Pixel Distillation (Decode-or-Die)
**Concept**: Re-authoring images from raw pixels.
**Defense Implementation** (`src/lib/ImageSecurity.php`):
```bash
vips copy "input.jpg[n=1]" "output.jpg[strip]"
```
**Principle**: **Decode-or-Die**. Force a full decode cycle. Metadata is not "stripped"—it is **discarded** as the engine creates a brand-new file from raw pixel data.

### Layer 5: Global Resource Sentinel
**Concept**: Resilience against DoS (Denial of Service).
**Defense Implementation**:
- **PDF**: Object count (<50,000) and Page count (<5,000) caps.
- **Image**: Pixel count (<10MP) pre-check.
- **CSV**: Row count (<10,000) cap.
**Principle**: A secure system must remain a stable system. Pre-calculate structural complexity before allocation.

### Layer 6: Centralized Forensic Audit
**Requirements**: High-fidelity records of every neutralized threat.
**Defense Implementation** (`src/upload.php`):
```php
$stmt->execute([
    $file['name'],
    $result['mime'],
    $result['engine'],
    $status,
    $threat_details,
    $sanitized_hash
]);
```
**Principle**: Can't mitigate what you can't measure. Record the **Threat Delta** (what was changed) for every transaction.

### Layer 7: Hardened Delivery Proxy
**Concept**: Sandbox the download to protect the end-user.
**Defense Implementation** (`src/download.php`):
```php
header('Content-Security-Policy: sandbox');
header('X-Content-Type-Options: nosniff');
```
**Principle**: Network-layer isolation. Even if a file remains "malicious" to a target application, we block it from hurting the browser.

---

## Part 3: Operational Principles

1.  **Reconstruction is Authority**: Detection is just a signal. Rewriting the file is the ultimate security verdict.
2.  **Specialized Isolation**: Use the right tool for the right format (QPDF for PDF, Vips for Images, Normalizer for CSV).
3.  **Zero Trust for Metadata**: Metadata exists for machines; assume it contains payloads and discard it by default.
4.  **Fail-Closed**: If a security engine crashes, times out, or throws an integrity warning, the file is rejected.
5.  **Forensic Continuity**: A unified trail across all engines ensures accountability and incident response speed.

---
*Technical Security Audit - Professional Backend Security Framework v5.0*
