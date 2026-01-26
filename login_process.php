<?php
session_start();
header('Content-Type: application/json');

// Database credentials - Update these with your real details
$host = "localhost";
$db_user = "root";
$db_pass = ""; // Set your actual password
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit();
}

// Get the data from the form
$user = $_POST['username'] ?? '';
$pass = $_POST['password'] ?? '';
$selected_role = $_POST['role'] ?? '';

if (empty($user) || empty($pass) || empty($selected_role)) {
    echo json_encode(['success' => false, 'message' => 'Please fill all fields']);
    exit();
}

// Check for reset passwords first (stored in session)
if ($selected_role === 'owner' && isset($_SESSION['owner_reset_password'])) {
    if ($pass === $_SESSION['owner_reset_password']) {
        // Check if user exists
        $sql = "SELECT id, username, role FROM users WHERE username = ? AND role = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $user, $selected_role);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['role'] = $row['role'];
            $_SESSION['username'] = $row['username'];
            
            echo json_encode(['success' => true, 'message' => 'Welcome back, Owner!']);
            exit();
        }
    }
}

if ($selected_role === 'secretary' && isset($_SESSION['secretary_reset_password'])) {
    if ($pass === $_SESSION['secretary_reset_password']) {
        // Check if user exists
        $sql = "SELECT id, username, role FROM users WHERE username = ? AND role = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $user, $selected_role);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['role'] = $row['role'];
            $_SESSION['username'] = $row['username'];
            
            echo json_encode(['success' => true, 'message' => 'Welcome back, Secretary!']);
            exit();
        }
    }
}

// Check database credentials
$sql = "SELECT id, username, password, role FROM users WHERE username = ? AND role = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $user, $selected_role);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    
    // Check password - For demo, using plain text comparison
    // In production, use: password_verify($pass, $row['password'])
    if ($pass === $row['password']) {
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['role'] = $row['role'];
        $_SESSION['username'] = $row['username'];
        
        $message = $selected_role === 'owner' ? 'Welcome back, Owner!' : 'Welcome back, Secretary!';
        echo json_encode(['success' => true, 'message' => $message]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid password']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'User not found for this role']);
}

$stmt->close();
$conn->close();
?>
