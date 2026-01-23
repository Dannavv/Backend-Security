# 🛡️ Unified Secure Gateway: The Professional Masterclass Guide

## Part 1: The "Converged Threat" Landscape

Chapter 5 represents the **apex** of the series. It moves beyond format-specific validation to solve the **"Converged Threat"** problem: the reality that modern exploits are multi-stage, multi-format, and designed to bypass single-layer filters.

### Why a Unified Gateway is Required
*   **The Polyglot Problem**: A file can be a valid JPEG image and a valid PHP script simultaneously.
*   **The Interpretation Gap**: What a security scanner sees is often different from what the final application (Excel, Acrobat, Browser) renders.
*   **The Metadata Shadow**: Attackers hide code in non-rendered regions (ICC profiles, deleted PDF objects, formula triggers) that standard validators ignore.
*   **Resource Exhaustion**: Single files (PDF Bombs, Image Bombs, CSV Row Floods) can crash entire services.

---

## Part 2: The 8-Layer Unified Defense Pipeline

Every file entering the gateway passes through this strictly sequenced, high-assurance pipeline.

### Layer 1: MIME-Force Ingress (The Perimeter)
**Concept**: Discard client-provided headers and verify the absolute binary truth.
**Defense Implementation** (`src/Gateway.php`):
```php
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($file['tmp_name']);
// Strict Allow-list check
$expectedMime = self::ALLOWED_MAP[$ext]['mime'];
if ($mime !== $expectedMime) {
    return ['status' => 'rejected', 'error' => "Security Rejection: Content type ($mime) mismatch"];
}
```
**Principle**: Never trust the `Content-Type` header. Verify the magic bytes against an allow-list before routing.

### Layer 2: Identity Sanitization (The Isolation)
**Concept**: Eliminate Path Traversal and Command Injection by destroying the original metadata.
**Defense Implementation** (`src/Gateway.php`):
```php
$sanitizedName = bin2hex(random_bytes(16)) . '.' . $ext;
$targetPath = __DIR__ . '/../uploads/' . $sanitizedName;
```
**Principle**: Treat the original filename as a hostile payload. Renaming to a UUID restores "File Identity" to a clean state.

---

## Part 3: Specialized Engine Defenses

### 1. 📊 CSV Guard Engine (10 Layers)

#### Layer 4: Strict Formula Guard
**Concept**: Prevent SpreadSheet Formula Injection (CSV Injection) where cells starting with `=`, `+`, `-`, `@` execute code in Excel.
**Code Reference** (`src/lib/CSVSecurity.php`):
```php
function csv_validate_formulas(array $row): ?string {
    foreach ($row as $cell) {
        if (is_string($cell) && !empty($cell) && in_array($cell[0], CSV_FORMULA_TRIGGERS, true)) {
            return "Formula Injection Detected: Cell starts with '" . $cell[0] . "'";
        }
    }
    return null;
}
```

#### Layer 5: Normalization Shield
**Concept**: Prevent homoglyph attacks and encoding bypasses by forcing NFC normalization.
**Code Reference** (`src/lib/CSVSecurity.php`):
```php
function csv_validate_and_normalize(string $input): ?string {
    if (!mb_check_encoding($input, 'UTF-8')) return null;
    
    if (class_exists('Normalizer')) {
        $normalized = Normalizer::normalize($input, Normalizer::FORM_C);
        return $normalized !== false ? $normalized : $input;
    }
    return $input;
}
```

#### Layer 7: Atomic Transaction Cap
**Concept**: Prevent DB DoS by limiting the transaction size and ensuring all-or-nothing integrity.
**Code Reference** (`src/lib/CSVSecurity.php`):
```php
$db->beginTransaction();
while (($row = fgetcsv($handle)) !== false) {
    if (++$results['rows'] > CSV_MAX_ROWS) break;
    // ... validation ...
}
// Fail Closed
if (empty($results['errors'])) {
    $db->commit();
} else {
    $db->rollBack();
}
```

---

### 2. 📄 PDF Bastion Engine (8 Layers)

#### Layer 3: Semantic Resource Guard
**Concept**: Detect "PDF Bombs" and resource exhaustion attacks before they crash the parser.
**Code Reference** (`src/lib/PDFSecurity.php`):
```php
if ($structuralResults['object_count'] > PDF_MAX_OBJECT_COUNT) 
    $findings[] = ['tag' => 'dos', 'desc' => 'Object count exceeds safety threshold'];
if ($structuralResults['stream_count'] > PDF_MAX_STREAM_COUNT) 
    $findings[] = ['tag' => 'dos', 'desc' => 'Stream count exceeds safety threshold'];
```

#### Layer 4: Deep Semantic Scan
**Concept**: Use `qpdf --json` to walk the logical tree and find hidden Javascript or Actions.
**Code Reference** (`src/lib/PDFSecurity.php`):
```php
$json = json_decode(implode("\n", $output), true);
// Recursive inspector looks for /JS, /Launch, /Annot keys
$semanticFindings = pdf_inspect_semantics($structuralResults['json']);
```

#### Layer 7: Authoritative Scrub
**Concept**: Re-author the PDF to strip hidden metadata and ensure a clean structure.
**Code Reference** (`src/lib/PDFSecurity.php`):
```php
$cmd = "qpdf --linearize --remove-metadata " . escapeshellarg($inputPath) . " " . escapeshellarg($outputPath);
exec($cmd, $output, $returnCode);
```

---

### 3. 🖼️ Image Sentinel Engine (8 Layers)

#### Layer 4: Pixel Flood Guard
**Concept**: Calculate total pixels (`W x H`) to stop "Image Bombs" (Small file size, massive RAM usage).
**Code Reference** (`src/lib/ImageSecurity.php`):
```php
$dimensions = @getimagesize($tmpPath);
$totalPixels = $dimensions[0] * $dimensions[1];

if ($totalPixels > IMG_MAX_TOTAL_PIXELS) {
    return ["Security Violation: Total pixel count ($totalPixels) exceeds safety limit"];
}
```

#### Layer 6: Decode-or-Die (Libvips)
**Concept**: Use Libvips to decode the image to raw pixels and re-encode it, destroying any non-pixel payloads (Polyglots).
**Code Reference** (`src/lib/ImageSecurity.php`):
```php
// Libvips Reconstruction with [strip] to remove metadata
$cmd = "vips copy " . escapeshellarg($inputPath) . "[strip] " . escapeshellarg($outputPath);
exec($cmd, $output, $returnCode);
```

#### Layer 5: Signal Intelligence
**Concept**: Scan raw bytes for PHP/Script signatures hidden in image comments or metadata.
**Code Reference** (`src/lib/ImageSecurity.php`):
```php
$malicious = ['<?php', '<script', 'javascript:', 'eval('];
foreach ($malicious as $trigger => $desc) {
    if (stripos($content, $trigger) !== false) {
        $findings[] = ['trigger' => $trigger, 'desc' => $desc];
    }
}
```

---

## Part 4: Operational Principles

1.  **Sanitization is Authority**: We don't "clean" files; we extract data and create **new** files.
2.  **Metadata is Hostile**: Metadata is for machines, not humans. Discard it by default.
3.  **Fail-Secure Infrastructure**: If any engine crashes or a timeout occurs, the file is destroyed.
4.  **Specialized Tooling**: Use industry-hardened tools (QPDF, Libvips) over fragile regex.
5.  **Zero-Trust Identity**: Filenames, extensions, and user-provided types are treated as lies.

---
*Authorized Security Audit - Unified Secure Gateway Masterclass v5.0*
*Document Classification: High-Assurance Technical Architecture*
