<?php
require_once __DIR__ . '/app.php';
initSecurity();
$features = ImageSecurity::getFeatures();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Security Portal | Chapter 04</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #f43f5e;
            --secondary: #ec4899;
            --bg: #0b0f19;
            --card-bg: #161b2a;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
            --glass: rgba(22, 27, 42, 0.7);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(244, 63, 94, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(236, 72, 153, 0.05) 0%, transparent 40%);
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        header {
            text-align: center;
            margin-bottom: 4rem;
            animation: fadeInDown 0.8s ease-out;
        }

        header h1 {
            font-size: 3.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #fff 0%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        header p { color: var(--text-dim); font-size: 1.2rem; }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 2rem;
            margin-bottom: 4rem;
        }

        .section-card {
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 24px;
            border: 1px solid rgba(255,255,255,0.05);
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2);
            backdrop-filter: blur(12px);
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
            border: 2px dashed rgba(244, 63, 94, 0.3);
            border-radius: 20px;
            padding: 4rem 2rem;
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            background: rgba(244, 63, 94, 0.02);
            position: relative;
            overflow: hidden;
        }

        .drop-zone:hover {
            border-color: var(--primary);
            background: rgba(244, 63, 94, 0.05);
            transform: translateY(-4px);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }

        .feature-card {
            background: var(--glass);
            padding: 1.5rem;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.03);
            transition: all 0.3s ease;
        }

        .feature-card:hover {
            background: rgba(255,255,255,0.05);
            border-color: var(--primary);
            transform: scale(1.03);
        }

        .feature-icon { font-size: 1.8rem; margin-bottom: 1rem; }
        .feature-name { font-weight: 600; margin-bottom: 0.5rem; color: #fff; }
        .feature-desc { font-size: 0.9rem; color: var(--text-dim); }

        .btn {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            padding: 1.2rem 2rem;
            border-radius: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 2rem;
            font-size: 1rem;
            font-family: inherit;
            letter-spacing: 0.5px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 20px -5px rgba(244, 63, 94, 0.4);
        }

        .stat-item {
            padding: 1.2rem;
            background: rgba(255,255,255,0.02);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.05);
            margin-bottom: 1rem;
        }

        .stat-label { font-size: 0.85rem; color: var(--text-dim); margin-bottom: 0.25rem; }
        .stat-value { font-size: 1.2rem; font-weight: 700; }

        .nav-links {
            display: flex;
            justify-content: center;
            gap: 2.5rem;
            margin-top: 4rem;
            padding-bottom: 2rem;
        }

        .nav-link {
            color: var(--text-dim);
            text-decoration: none;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-weight: 500;
        }

        .nav-link:hover { color: var(--primary); transform: translateY(-2px); }

        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .alert {
            padding: 1rem 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #6ee7b7; }

        @media (max-width: 968px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Image Shield</h1>
            <p>High-Fidelity Re-encoding & Metadata Sanitation Pipeline</p>
        </header>

        <?php if (isset($_GET['status'])): ?>
            <?php if ($_GET['status'] === 'success'): ?>
                <div class="alert alert-success">
                    <span>✅</span> Image uploaded and sanitized successfully!
                </div>
            <?php elseif ($_GET['status'] === 'error'): ?>
                <div class="alert alert-error">
                    <span>❌</span> Security rejection: <?= htmlspecialchars($_GET['msg'] ?? 'Unknown error') ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <div class="dashboard-grid">
            <div class="section-card">
                <div class="section-title">
                    <span>📸</span> Secure Upload Terminal
                </div>
                <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
                    <input type="hidden" name="csrf_token" value="<?= ImageSecurity::csrfToken() ?>">
                    <div class="drop-zone" id="dropZone">
                        <div style="font-size: 4rem; margin-bottom: 1.5rem; filter: drop-shadow(0 0 15px rgba(244, 63, 94, 0.3));">🖼️</div>
                        <p style="font-size: 1.2rem; font-weight: 600;">Drag & Drop Image</p>
                        <p style="color: var(--text-dim); margin-top: 0.5rem;">Accepted: JPG, PNG, WEBP, GIF (Max 5MB)</p>
                        <input type="file" id="fileInput" name="image_file" style="display: none;" accept="image/*" required>
                    </div>
                    <button type="submit" class="btn">Deploy Sanitation Pipeline</button>
                </form>
            </div>

            <div class="section-card">
                <div class="section-title">📊 System Integrity</div>
                
                <div class="stat-item">
                    <div class="stat-label">Real-time Defense</div>
                    <div class="stat-value" style="color: var(--success);">ACTIVE</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-label">Re-encoding Engine</div>
                    <div class="stat-value">GD Library v2.3+</div>
                </div>

                <div class="stat-item">
                    <div class="stat-label">Security Policy</div>
                    <div class="stat-value" style="font-size: 0.9rem; font-family: 'JetBrains Mono';">Strict-Sanitize-All</div>
                </div>

                <div style="margin-top: 1.5rem;">
                    <a href="history.php" class="nav-link" style="color: var(--primary);">View Security Audit Trail →</a>
                </div>
            </div>
        </div>

        <section style="margin-bottom: 4rem;">
            <div class="section-title" style="justify-content: center; margin-bottom: 3rem;">
                Advanced Defense Matrix
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
            <a href="history.php" class="nav-link">📜 Audit Logs</a>
            <a href="SECURITY_REPORT.md" class="nav-link">📖 Security Report</a>
            <a href="https://github.com/Dannavv/Backend-Security" class="nav-link" target="_blank">🐙 GitHub</a>
        </div>
    </div>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        dropZone.addEventListener('click', () => fileInput.click());

        ['dragenter', 'dragover'].forEach(name => {
            dropZone.addEventListener(name, (e) => {
                e.preventDefault();
                dropZone.style.borderColor = 'var(--primary)';
                dropZone.style.background = 'rgba(244, 63, 94, 0.08)';
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dropZone.addEventListener(name, (e) => {
                e.preventDefault();
                dropZone.style.borderColor = 'rgba(244, 63, 94, 0.3)';
                dropZone.style.background = 'rgba(244, 63, 94, 0.02)';
            });
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                dropZone.querySelector('p:first-of-type').textContent = file.name;
                dropZone.querySelector('p:last-of-type').textContent = (file.size / 1024 / 1024).toFixed(2) + ' MB';
            }
        });
    </script>
</body>
</html>
