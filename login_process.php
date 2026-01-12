<?php
session_start();

// Database credentials - Update these with your real details
$host = "localhost";
$db_user = "root"; 
$db_pass = ""; 
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get the data from the form
$user = $_POST['username'];
$pass = $_POST['password'];
$selected_role = $_POST['role']; // From the hidden input in index.html

// Secure query to check user and role
$sql = "SELECT id, username, password, role FROM users WHERE username = '$user' AND role = '$selected_role'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    
    // Check password
    if ($pass === $row['password']) {
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['role'] = $row['role'];
        $_SESSION['username'] = $row['username'];
        
        // Redirect to dashboard on success
        header("Location: dashboard.html");
        exit();
    } else {
        echo "<script>alert('Wrong password! Please try again.'); window.location='index.html';</script>";
    }
} else {
    echo "<script>alert('User not found for this role.'); window.location='index.html';</script>";
}

$conn->close();
?>
