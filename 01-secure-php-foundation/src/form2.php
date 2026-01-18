<?php
require_once 'security.php';
require_once 'validator.php';
require_once 'db.php';
$errors = [];
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $errors = validate_input($_POST, $rules);
    
    if (empty($errors)) {
        $product_name = $_POST['product_name'];
        $category = $_POST['category'];
        $price = $_POST['price'];

        // Secure INSERT
        $stmt = mysqli_prepare($conn, "INSERT INTO products (product_name, category, price) VALUES (?, ?, ?)");
        
        if ($stmt) {
            // "ssd" -> string, string, double
            mysqli_stmt_bind_param($stmt, "ssd", $product_name, $category, $price);
            
            if (mysqli_stmt_execute($stmt)) {
                $success = "Product saved successfully!";
            } else {
                error_log("Database error (form2): " . mysqli_error($conn));
                $errors['db'][] = "An unexpected error occurred. Please try again.";
            }
            mysqli_stmt_close($stmt);
        } else {
             error_log("Statement Prepare failed (form2): " . mysqli_error($conn));
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
    <title>New Product - Form 2</title>
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
        <h2>Add Product</h2>
        <p>Enter new inventory details.</p>

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
                <label for="product_name">Product Name</label>
                <input type="text" id="product_name" name="product_name" placeholder="e.g. ERP License" required>
            </div>
            <div class="form-group">
                <label for="category">Category</label>
                <select id="category" name="category">
                    <option value="software">Software</option>
                    <option value="hardware">Hardware</option>
                    <option value="service">Service</option>
                    <option value="consulting">Consulting</option>
                </select>
            </div>
            <div class="form-group">
                <label for="price">Price (USD)</label>
                <input type="number" id="price" name="price" placeholder="0.00" step="0.01" required>
            </div>
            <button type="submit">Save Product</button>
        </form>

        <?php require_once 'security_status.php'; render_security_status(); ?>
    </div>
</body>
</html>
