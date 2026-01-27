<?php
session_start();
header('Content-Type: application/json');

// Database credentials - Update these with your real details
$host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    echo json_encode([
        'success' => false,
        'message' => 'Database connection failed'
    ]);
    exit();
}

// Handle different actions
$action = $_POST['action'] ?? 'login';

if ($action === 'login') {
    handleLogin($conn);
} elseif ($action === 'reset_password') {
    handlePasswordReset($conn);
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid action'
    ]);
}

$conn->close();

function handleLogin($conn) {
    // Get the data from the form
    $user = $conn->real_escape_string($_POST['username']);
    $pass = $_POST['password']; // Don't escape password for hashing comparison
    $selected_role = $conn->real_escape_string($_POST['role']);

    // Secure query to check user and role
    $sql = "SELECT id, username, password, role, email FROM users WHERE username = ? AND role = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $user, $selected_role);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        // Check password (assuming passwords are hashed)
        if (password_verify($pass, $row['password'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['role'] = $row['role'];
            $_SESSION['username'] = $row['username'];
            $_SESSION['email'] = $row['email'];
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'role' => $row['role']
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Wrong password! Please try again.'
            ]);
        }
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'User not found for this role.'
        ]);
    }
    
    $stmt->close();
}

function handlePasswordReset($conn) {
    $email = $conn->real_escape_string($_POST['email']);
    $new_password = $_POST['new_password'];
    $role = $conn->real_escape_string($_POST['role']);
    $reset_code = $_POST['reset_code'];
    
    // Validate reset code (in a real system, you'd check against database)
    // For demo, we'll accept any 6-digit code
    
    if (strlen($reset_code) !== 6 || !is_numeric($reset_code)) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid reset code'
        ]);
        return;
    }
    
    // Check if user exists
    $sql = "SELECT id, email, role FROM users WHERE email = ? AND role = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $email, $role);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        // Hash the new password
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        
        // Update password
        $update_sql = "UPDATE users SET password = ? WHERE email = ? AND role = ?";
        $update_stmt = $conn->prepare($update_sql);
        $update_stmt->bind_param("sss", $hashed_password, $email, $role);
        
        if ($update_stmt->execute()) {
            // Log the password reset
            $log_sql = "INSERT INTO password_reset_logs (user_email, user_role, reset_time, ip_address) 
                       VALUES (?, ?, NOW(), ?)";
            $log_stmt = $conn->prepare($log_sql);
            $ip_address = $_SERVER['REMOTE_ADDR'];
            $log_stmt->bind_param("sss", $email, $role, $ip_address);
            $log_stmt->execute();
            $log_stmt->close();
            
            echo json_encode([
                'success' => true,
                'message' => 'Password updated successfully'
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to update password'
            ]);
        }
        
        $update_stmt->close();
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'User not found'
        ]);
    }
    
    $stmt->close();
}

// Create users table if it doesn't exist (run this once)
function createTables($conn) {
    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL,
        role ENUM('owner', 'secretary') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";
    
    $conn->query($sql);
    
    // Create password reset logs table
    $sql2 = "CREATE TABLE IF NOT EXISTS password_reset_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_email VARCHAR(100) NOT NULL,
        user_role VARCHAR(20) NOT NULL,
        reset_time DATETIME NOT NULL,
        ip_address VARCHAR(45),
        INDEX idx_email (user_email),
        INDEX idx_time (reset_time)
    )";
    
    $conn->query($sql2);
    
    // Insert default users (run once, then remove or secure)
    $check_sql = "SELECT COUNT(*) as count FROM users";
    $result = $conn->query($check_sql);
    $row = $result->fetch_assoc();
    
    if ($row['count'] == 0) {
        // Insert owner user
        $owner_pass = password_hash('Eagles2026!', PASSWORD_DEFAULT);
        $owner_sql = "INSERT INTO users (username, password, email, role) 
                     VALUES ('owner_admin', ?, 'jeremiahmburu76@gmail.com', 'owner')";
        $stmt = $conn->prepare($owner_sql);
        $stmt->bind_param("s", $owner_pass);
        $stmt->execute();
        
        // Insert secretary user
        $secretary_pass = password_hash('Secret2026!', PASSWORD_DEFAULT);
        $secretary_sql = "INSERT INTO users (username, password, email, role) 
                         VALUES ('secretary_entry', ?, 'jeremiahmburu76@gmail.com', 'secretary')";
        $stmt = $conn->prepare($secretary_sql);
        $stmt->bind_param("s", $secretary_pass);
        $stmt->execute();
        
        echo "Default users created successfully!";
    }
}

// Uncomment to create tables and default users (run once)
// createTables($conn);
?>
