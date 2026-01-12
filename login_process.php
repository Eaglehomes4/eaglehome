<?php
session_start();
$conn = new mysqli("localhost", "username", "password", "eagles_home");

$user = $_POST['username'];
$pass = $_POST['password'];

// 1. Check if user exists
$sql = "SELECT id, username, password, role FROM users WHERE username = '$user'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    
    // 2. Simple password check (In production, we use password_hash)
    if ($pass === $row['password']) {
        // 3. Success! Save user info in the session
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['role'] = $row['role'];
        $_SESSION['username'] = $row['username'];
        
        // 4. Send them to the dashboard
        header("Location: dashboard.html");
    } else {
        echo "Invalid password.";
    }
} else {
    echo "User not found.";
}
$conn->close();
?>
