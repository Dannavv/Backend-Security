<?php
/**
 * 🛰️ Unified Secure Upload Gateway
 * Acts as the central dispatcher for all file uploads.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib/CSVSecurity.php';
require_once __DIR__ . '/lib/PDFSecurity.php';
require_once __DIR__ . '/lib/ImageSecurity.php';

class Gateway {
    private const ALLOWED_MAP = [
        'pdf'  => ['mime' => 'application/pdf', 'engine' => 'PDF'],
        'csv'  => ['mime' => 'text/csv', 'engine' => 'CSV'],
        'jpg'  => ['mime' => 'image/jpeg', 'engine' => 'IMAGE'],
        'jpeg' => ['mime' => 'image/jpeg', 'engine' => 'IMAGE'],
        'png'  => ['mime' => 'image/png', 'engine' => 'IMAGE']
    ];

    public static function handle(array $file): array {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['status' => 'error', 'message' => 'Upload error'];
        }

        // 1. Strict Extension Check
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!isset(self::ALLOWED_MAP[$ext])) {
            return [
                'status' => 'rejected',
                'error' => "Policy Violation: Unsupported file extension (.$ext)"
            ];
        }

        // 2. Identify True Type (Magic Bytes)
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($file['tmp_name']);

        // 3. Extension-MIME Lockdown
        $expectedMime = self::ALLOWED_MAP[$ext]['mime'];
        if ($mime !== $expectedMime) {
            // Special case for CSV which can sometimes be application/csv
            if ($ext === 'csv' && $mime === 'application/csv') {
                // Allowed
            } else {
                return [
                    'status' => 'rejected',
                    'error' => "Security Rejection: Content type ($mime) does not match extension (.$ext)."
                ];
            }
        }

        $engineType = self::ALLOWED_MAP[$ext]['engine'];
        $sanitizedName = bin2hex(random_bytes(16)) . '.' . $ext;
        $targetPath = __DIR__ . '/../uploads/' . $sanitizedName;

        // 2. Route to specialized engine
        $result = [];
        try {
            switch ($engineType) {
                case 'CSV':
                    $result = csv_process($file, $targetPath);
                    break;
                case 'PDF':
                    $result = pdf_process($file, $targetPath);
                    break;
                case 'IMAGE':
                    $result = img_process($file, $targetPath, $mime);
                    break;
            }
        } catch (Throwable $e) {
            $result = [
                'status' => 'error',
                'error' => 'Security Engine Failure: ' . $e->getMessage()
            ];
        }

        $result['mime'] = $mime;
        $result['engine'] = $engineType;
        $result['filename'] = $file['name'];
        
        return $result;
    }

    public static function getFeatures(): array {
        return [
            'CSV' => csv_get_features(),
            'PDF' => pdf_get_features(),
            'IMAGE' => img_get_features()
        ];
    }
}
