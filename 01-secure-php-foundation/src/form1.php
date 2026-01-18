<?php
require_once 'security.php';
require_once 'validator.php';
require_once 'db.php'; // Includes db connection helper
$errors = [];
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $errors = validate_input($_POST, $rules);
    
    if (empty($errors)) {
        // Validation Passed: Secure Database Insertion
        $username = $_POST['username'];
        $email = $_POST['email'];
        // Note: Password hashing is critical, but focusing on SQLi here.
        // We still hash it to be reasonable.
        $password_hash = password_hash($_POST['password'], PASSWORD_DEFAULT);

        // 1. PREPARE
        $stmt = mysqli_prepare($conn, "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
        
        if ($stmt) {
            // 2. BIND ("sss" means string, string, string)
            mysqli_stmt_bind_param($stmt, "sss", $username, $email, $password_hash);
            
            // 3. EXECUTE
            if (mysqli_stmt_execute($stmt)) {
                $success = "Registration successful and saved securely!";
            } else {
                error_log("Database error (form1): " . mysqli_error($conn));
                $errors['db'][] = "An unexpected error occurred. Please try again.";
            }
            mysqli_stmt_close($stmt);
        } else {
             error_log("Statement Prepare failed (form1): " . mysqli_error($conn));
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
    <title>User Registration - Form 1</title>
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
        <h2>User Registration</h2>
        <p>Create your secured account.</p>

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
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="johndoe" required>
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" placeholder="john@example.com" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit">Register Account</button>
        </form>
        
        <?php require_once 'security_status.php'; render_security_status(); ?>
    </div>
</body>
</html>
