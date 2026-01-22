# Image Upload Security: Complete Knowledge Guide

## Part 1: The Fundamental Problem

Images are not just static grids of pixels—they are complex data containers. Modern image formats (JPEG, PNG, GIF, WebP) support extensive metadata, color profiles, and compression algorithms. This complexity makes them a prime vector for cyberattacks.

### Why Images are a Security Nightmare
*   **Polyglot Attacks**: A file can validly be interpreted as *two different formats* depending on the parser. A file can be a valid JPEG to an image viewer, but valid PHP code to a server.
*   **Image Bombs (Pixel Floods)**: Attackers exploit compression algorithms to create tiny files (e.g., 5KB) that decode into massive bitmaps (e.g., 10GB RAM), causing Denial of Service (DoS).
*   **Metadata Leakage**: Images often contain EXIF data (GPS coordinates, camera model, timestamp) which violates privacy.
*   **Payload Hiding**: Attackers can hide malicious code (JavaScript, Shellcode) in "Comment" fields, ICC profiles, or appended to the end of the file.
*   **Parser Vulnerabilities**: Image parsing libraries (like ImageMagick or GD) historically have had buffer overflow vulnerabilities.

---

## Part 2: The 8-Layer Professional Defense Pipeline

### Layer 1: Traffic & Identity Control
**Concept**: Stop the attack before it even hits the image parser.
**Defense Implementation**:
```php
if (ImageSecurity::checkRateLimit($ip)) die("Too fast");
if (!ImageSecurity::validateCSRF($token)) die("Invalid Request");
```
**Principle**: Rate limiting prevents automated DoS attempts and flooding.

### Layer 2: Structural Integrity & Magic Bytes
**Concept**: Don't trust the file extension.
**Defense Implementation** (`src/ImageSecurity.php`):
```php
$hex = bin2hex(fread($handle, 12));
if ($mime === 'image/jpeg' && !str_starts_with($hex, 'ffd8ff')) {
    return ["Fake JPEG Detected"];
}
```
**Principle**: Every file type has a unique "Magic Byte" signature. If the header doesn't match the MIME type, it's a spoofed file.

### Layer 3: Resource Guard (Pixel Flood Defense)
**Concept**: Protect server memory from decompression bombs.
**Defense Implementation**:
```php
$dimensions = getimagesize($tmpPath);
$totalPixels = $dimensions[0] * $dimensions[1]; // Width * Height
if ($totalPixels > 30000000) return ["Image Bomb Detected"];
```
**Principle**: Check dimensions *before* fully loading the image into a processing library. Reject anything that exceeds a safe pixel budget.

### Layer 4: Signal Detection (The Informant)
**Concept**: Detect polyglots that contain readable code.
**Defense Implementation**:
```php
// Scan for PHP tags, Script tags, or Shell commands
if (strpos($content, '<?php') !== false) {
    $findings[] = "Potential PHP Payload Found";
}
```
**Principle**: This layer **does not** necessarily block the file (smart attackers can obfuscate). It acts as a "Signal" to the logging system to flag the upload as suspicious.

### Layer 5: Authoritative Sanitization (Decode-or-Die)
**Concept**: The core defense. Rebuild the image from scratch.
**Defense Implementation** (`src/ImageSecurity.php`):
```bash
# Libvips command
vips copy "input.jpg[n=1]" "output.jpg[strip]"
```
**Principle**:
1.  **Fully Decode**: Forces the library to interpret every pixel. Malformed exploit files often fail here.
2.  **Strip Metadata (`[strip]`)**: Removes EXIF, XMP, IPTC, and Comments.
3.  **Flatten (`[n=1]`)**: If it's a GIF/APNG, only keep the first frame. This kills animation-based exploits.
4.  **Re-Encode**: Write a brand new file. The bytes of the user's file are *never* copied.

### Layer 6: Post-Sanitization Forensic Verify
**Concept**: Trust but verify.
**Defense Implementation**:
```php
$sanitizedHash = hash_file('sha256', $finalPath);
$delta = $originalSize - $sanitizedSize; // Log how much junk was removed
```
**Principle**: We confirm the new file is valid and calculate the "Delta" to see how much data (potential payload) was stripped.

### Layer 7: Zero-Trust Storage
**Concept**: Never keep the original filename or directory.
**Defense Implementation**:
```php
$uuid = bin2hex(random_bytes(16));
$path = UPLOAD_DIR . '/' . $uuid . '.jpg';
```
**Principle**: Renaming prevents directory traversal attacks and makes guessing file URLs impossible.

### Layer 8: Delivery Hardening
**Concept**: Sandbox the download.
**Defense Implementation** (`src/download.php`):
```php
header("Content-Security-Policy: default-src 'none'");
header("X-Content-Type-Options: nosniff");
```
**Principle**: Even if a file is malicious, we prevent the browser from executing it as a script.

---

## Part 3: Operational Principles

1.  **Decode-or-Die**: If we can't completely rebuild it, we don't want it.
2.  **Sanitization is Authority**: Detection is just a hint. Sanitization is the judge, jury, and executioner.
3.  **No Animation**: Animations are complex state machines. We flatten them to simple static bitmaps to reduce attack surface.
4.  **Privacy by Default**: We enable metadata stripping on *every* file to protect user privacy (GPS data).
5.  **Fail-Secure**: If the Libvips process crashes or times out, the default action is **REJECT**.

---
*Technical Security Audit - Professional Backend Security Framework*
