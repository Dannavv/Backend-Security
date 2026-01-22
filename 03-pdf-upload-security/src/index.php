<?php
require_once __DIR__ . '/app.php';
initSecurity();
$features = PDFSecurity::getFeatures();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Security Portal | Chapter 03</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #8b5cf6;
            --secondary: #6366f1;
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
            --danger: #ef4444;
            --success: #22c55e;
            --glass: rgba(30, 41, 59, 0.7);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
            background-image: radial-gradient(circle at top right, rgba(139, 92, 246, 0.1), transparent),
                              radial-gradient(circle at bottom left, rgba(99, 102, 241, 0.1), transparent);
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        header {
            text-align: center;
            margin-bottom: 4rem;
            animation: fadeInDown 0.8s ease-out;
        }

        header h1 {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
        }

        header p { color: var(--text-dim); font-size: 1.2rem; }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 4rem;
        }

        .upload-section {
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 24px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .drop-zone {
            border: 2px dashed rgba(139, 92, 246, 0.3);
            border-radius: 16px;
            padding: 3rem;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
            background: rgba(139, 92, 246, 0.05);
        }

        .drop-zone:hover {
            border-color: var(--primary);
            background: rgba(139, 92, 246, 0.1);
            transform: translateY(-2px);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.5rem;
        }

        .feature-card {
            background: var(--glass);
            padding: 1.5rem;
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.05);
            transition: all 0.3s ease;
        }

        .feature-card:hover {
            background: rgba(255,255,255,0.05);
            border-color: var(--primary);
            transform: scale(1.02);
        }

        .feature-icon { font-size: 1.5rem; margin-bottom: 0.75rem; }
        .feature-name { font-weight: 600; margin-bottom: 0.5rem; color: #fff; }
        .feature-desc { font-size: 0.85rem; color: var(--text-dim); }

        .btn {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 1.5rem;
            font-family: inherit;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(139, 92, 246, 0.4);
        }

        .stats-card {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(99, 102, 241, 0.1));
            border-radius: 24px;
            padding: 2rem;
            border: 1px solid rgba(139, 92, 246, 0.2);
        }

        .nav-links {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 3rem;
        }

        .nav-link {
            color: var(--text-dim);
            text-decoration: none;
            transition: color 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .nav-link:hover { color: var(--primary); }

        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 968px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PDF Upload Security</h1>
            <p>Advanced Structural Analysis & Active Content Detection</p>
        </header>

        <div class="dashboard-grid">
            <div class="upload-section">
                <div class="section-title">
                    <span>🛡️</span> Secure Upload Portal
                </div>
                <form action="upload.php" method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?= PDFSecurity::csrfToken() ?>">
                    <div class="drop-zone" id="dropZone">
                        <div style="font-size: 3rem; margin-bottom: 1rem;">📄</div>
                        <p><strong>Click to upload</strong> or drag and drop</p>
                        <p style="font-size: 0.85rem; color: var(--text-dim); margin-top: 0.5rem;">Only PDF files accepted (Max 10MB)</p>
                        <input type="file" id="fileInput" name="pdf_file" style="display: none;" accept=".pdf" required>
                    </div>
                    <button type="submit" class="btn">Initialize Deep Scan</button>
                </form>
            </div>

            <div class="stats-card">
                <div class="section-title">🚀 Security Stats</div>
                <div style="display: flex; flex-direction: column; gap: 1rem;">
                    <div>
                        <div style="font-size: 0.85rem; color: var(--text-dim);">Threat Level</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: var(--success);">SECURE</div>
                    </div>
                    <div>
                        <div style="font-size: 0.85rem; color: var(--text-dim);">Active Engines</div>
                        <div style="font-size: 1.5rem; font-weight: 700;">8 Defense Layers</div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <a href="history.php" class="nav-link" style="color: var(--primary);">View Security Logs →</a>
                    </div>
                </div>
            </div>
        </div>

        <section>
            <div class="section-title" style="justify-content: center; margin-bottom: 3rem;">
                Implemented Defense Layers
            </div>
            <div class="features-grid">
                <?php foreach ($features as $f): ?>
                <div class="feature-card">
                    <div class="feature-icon"><?= $f['icon'] ?></div>
                    <div class="feature-name"><?= $f['name'] ?></div>
                    <div class="feature-desc"><?= $f['desc'] ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>

        <div class="nav-links">
            <a href="history.php" class="nav-link">📜 Audit History</a>
            <a href="https://github.com/Dannavv/Backend-Security" class="nav-link" target="_blank">🐙 Repository</a>
            <a href="SECURITY_REPORT.md" class="nav-link">📖 Security Report</a>
        </div>
    </div>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        // Simple click to trigger file input
        dropZone.addEventListener('click', () => {
            fileInput.click();
        });

        // Simple drag and drop visual feedback
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                dropZone.style.borderColor = 'var(--primary)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                dropZone.style.borderColor = 'rgba(139, 92, 246, 0.3)';
            }, false);
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                dropZone.querySelector('p strong').textContent = fileInput.files[0].name;
                dropZone.querySelector('p:last-of-type').textContent = (fileInput.files[0].size / 1024 / 1024).toFixed(2) + ' MB';
            }
        });
    </script>
</body>
</html>
