<?php
session_start();
header('Content-Type: application/json');

// Database credentials
$host = "localhost";
$db_user = "root";
$db_pass = ""; // Set your actual password
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit();
}

// Get data from request
$email = $_POST['email'] ?? '';
$newPassword = $_POST['newPassword'] ?? '';
$role = $_POST['role'] ?? '';

if (empty($email) || empty($newPassword) || empty($role)) {
    echo json_encode(['success' => false, 'message' => 'All fields are required']);
    exit();
}

if (strlen($newPassword) < 8) {
    echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters']);
    exit();
}

// In a real application, you would:
// 1. Hash the password: $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
// 2. Update the database
// For this demo, we'll store in session

if ($role === 'owner') {
    $_SESSION['owner_reset_password'] = $newPassword;
    $_SESSION['owner_reset_email'] = $email;
} else {
    $_SESSION['secretary_reset_password'] = $newPassword;
    $_SESSION['secretary_reset_email'] = $email;
}

// Also update in database (if you have a users table)
// $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ? AND role = ?");
// $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
// $stmt->bind_param("sss", $hashedPassword, $email, $role);
// $stmt->execute();

echo json_encode(['success' => true, 'message' => 'Password updated successfully']);

$conn->close();
?>
