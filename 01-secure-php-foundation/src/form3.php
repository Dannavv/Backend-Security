<?php
require_once 'security.php';
require_once 'validator.php';
require_once 'db.php';
$errors = [];
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $errors = validate_input($_POST, $rules);
    
    if (empty($errors)) {
        $type = $_POST['feedback_type'];
        $severity = $_POST['severity'];
        $message = $_POST['message'];

        // Secure INSERT
        $stmt = mysqli_prepare($conn, "INSERT INTO feedback (feedback_type, severity, message) VALUES (?, ?, ?)");
        
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "sss", $type, $severity, $message);
            
            if (mysqli_stmt_execute($stmt)) {
                 $success = "Feedback submitted successfully!";
            } else {
                 error_log("Database error (form3): " . mysqli_error($conn));
                 $errors['db'][] = "An unexpected error occurred. Please try again.";
            }
            mysqli_stmt_close($stmt);
        } else {
             error_log("Statement Prepare failed (form3): " . mysqli_error($conn));
             $errors['db'][] = "An unexpected system error occurred.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Feedback - Form 3</title>
    <link rel="stylesheet" href="style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
</head>
<body>
    <nav>
        <a href="form1.php">Registration</a>
        <a href="form2.php">Product</a>
        <a href="form3.php">Feedback</a>
    </nav>
    <div class="container">
        <h2>System Feedback</h2>
        <p>We value your security insights.</p>

        <?php if ($success): ?>
            <div class="alert" style="border-color: #00ff00; color: #00ff00; background: rgba(0,255,0,0.1);">
                <?= htmlspecialchars($success) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
             <div class="alert" style="border-color: #ff5555; color: #ff5555; background: rgba(255,85,85,0.1);">
                <ul>
                    <?php foreach ($errors as $fieldErrors): ?>
                        <?php foreach ($fieldErrors as $error): ?>
                            <li><?= htmlspecialchars($error) ?></li>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        
        <form action="" method="POST">
            <div class="form-group">
                <label for="feedback_type">Feedback Type</label>
                <select id="feedback_type" name="feedback_type">
                    <option value="bug">Bug Report</option>
                    <option value="feature">Feature Request</option>
                    <option value="security">Security Vulnerability</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <div class="form-group">
                <label for="severity">Severity</label>
                <div style="display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem;">
                    <label style="margin:0; display:flex; align-items:center;"><input type="radio" name="severity" value="low" style="width:auto; margin-right:0.5rem;" checked> Low</label>
                    <label style="margin:0; display:flex; align-items:center;"><input type="radio" name="severity" value="medium" style="width:auto; margin-right:0.5rem;"> Medium</label>
                    <label style="margin:0; display:flex; align-items:center;"><input type="radio" name="severity" value="high" style="width:auto; margin-right:0.5rem;"> High</label>
                </div>
            </div>
            <div class="form-group">
                <label for="message">Description</label>
                <textarea id="message" name="message" rows="5" placeholder="Describe the issue or suggestion..." required></textarea>
            </div>
            <button type="submit">Submit Feedback</button>
        </form>

        <?php require_once 'security_status.php'; render_security_status(); ?>
    </div>
</body>
</html>
