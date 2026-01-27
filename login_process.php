<?php
session_start();
header('Content-Type: application/json');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// CORS headers (adjust for production)
$allowed_origins = ['http://localhost', 'http://localhost:3000', 'https://yourdomain.com'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Database configuration
$config = [
    'host' => 'localhost',
    'db_user' => 'eagles_prod_user',
    'db_pass' => 'StrongPassword123!',
    'db_name' => 'eagles_home_db',
    'charset' => 'utf8mb4'
];

// Error handling
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Create logs directory if it doesn't exist
if (!is_dir(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}

try {
    $conn = new mysqli($config['host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    $conn->set_charset($config['charset']);
    $conn->query("SET time_zone = '+03:00'");
    
    // Get request data
    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    
    if (empty($input['action'])) {
        throw new Exception("No action specified");
    }
    
    // Route actions
    switch ($input['action']) {
        case 'login':
            handleLogin($conn, $input);
            break;
            
        case 'request_reset':
            handleRequestReset($conn, $input);
            break;
            
        case 'verify_reset_code':
            handleVerifyResetCode($conn, $input);
            break;
            
        case 'update_password':
            handleUpdatePassword($conn, $input);
            break;
            
        case 'validate_token':
            handleValidateToken($conn, $input);
            break;
            
        case 'logout':
            handleLogout();
            break;
            
        default:
            throw new Exception("Invalid action");
    }
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
        'error_code' => 'SYSTEM_ERROR'
    ]);
    
    error_log("[" . date('Y-m-d H:i:s') . "] " . $e->getMessage() . " - IP: " . getClientIP());
    
} finally {
    if (isset($conn)) {
        $conn->close();
    }
}

// ==================== MAIN FUNCTIONS ====================

function handleLogin($conn, $data) {
    // Validate input
    $required = ['username', 'password', 'role'];
    foreach ($required as $field) {
        if (empty($data[$field])) {
            throw new Exception("Missing required field: $field");
        }
    }
    
    $username = trim($conn->real_escape_string($data['username']));
    $password = $data['password'];
    $role = $conn->real_escape_string($data['role']);
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $ip_address = getClientIP();
    
    // Check rate limiting
    if (isRateLimited('login', $ip_address, $conn)) {
        throw new Exception("Too many login attempts. Please try again in 15 minutes.");
    }
    
    // Prepare and execute query
    $stmt = $conn->prepare("SELECT u.id, u.username, u.password, u.role, u.email, u.is_active 
                           FROM users u 
                           WHERE u.username = ? AND u.role = ? AND u.is_active = 1");
    $stmt->bind_param("ss", $username, $role);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        logLoginAttempt($conn, $username, $ip_address, $user_agent, 'failed', 'User not found');
        incrementRateLimit('login', $ip_address, $conn);
        throw new Exception("Invalid credentials");
    }
    
    $user = $result->fetch_assoc();
    
    // Verify password
    if (!password_verify($password, $user['password'])) {
        logLoginAttempt($conn, $username, $ip_address, $user_agent, 'failed', 'Wrong password');
        incrementRateLimit('login', $ip_address, $conn);
        throw new Exception("Invalid credentials");
    }
    
    // Check if password needs rehashing
    if (password_needs_rehash($user['password'], PASSWORD_ARGON2ID)) {
        $new_hash = password_hash($password, PASSWORD_ARGON2ID);
        $update_stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $update_stmt->bind_param("si", $new_hash, $user['id']);
        $update_stmt->execute();
    }
    
    // Generate session token
    $session_token = bin2hex(random_bytes(32));
    $expires_at = date('Y-m-d H:i:s', strtotime('+8 hours'));
    
    // Store session in database
    $session_stmt = $conn->prepare("INSERT INTO user_sessions 
                                   (user_id, session_token, ip_address, user_agent, expires_at) 
                                   VALUES (?, ?, ?, ?, ?)");
    $session_stmt->bind_param("issss", $user['id'], $session_token, $ip_address, $user_agent, $expires_at);
    $session_stmt->execute();
    
    // Update last login
    $update_stmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
    $update_stmt->bind_param("i", $user['id']);
    $update_stmt->execute();
    
    // Log successful attempt
    logLoginAttempt($conn, $username, $ip_address, $user_agent, 'success', null);
    
    // Set session variables
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['email'] = $user['email'];
    $_SESSION['session_token'] = $session_token;
    
    // Return response
    echo json_encode([
        'success' => true,
        'message' => 'Login successful',
        'data' => [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'email' => $user['email'],
            'session_token' => $session_token,
            'last_login' => $user['last_login'] ?? date('Y-m-d H:i:s')
        ]
    ]);
}

function handleRequestReset($conn, $data) {
    if (empty($data['email']) || empty($data['role'])) {
        throw new Exception("Email and role are required");
    }
    
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $role = $conn->real_escape_string($data['role']);
    $ip_address = getClientIP();
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception("Invalid email format");
    }
    
    // Check rate limiting
    if (isRateLimited('reset_request', $ip_address, $conn)) {
        throw new Exception("Too many reset requests. Please try again later.");
    }
    
    // Check if user exists
    $stmt = $conn->prepare("SELECT id, email, role, username FROM users WHERE email = ? AND role = ? AND is_active = 1");
    $stmt->bind_param("ss", $email, $role);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        // For security, don't reveal if user exists
        sleep(1); // Add delay to prevent timing attacks
        echo json_encode([
            'success' => true,
            'message' => 'If an account exists with this email, a reset link has been sent.'
        ]);
        return;
    }
    
    $user = $result->fetch_assoc();
    
    // Generate reset token
    $reset_token = bin2hex(random_bytes(32));
    $verification_code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires_at = date('Y-m-d H:i:s', strtotime('+15 minutes'));
    
    // Store reset request in database
    $reset_stmt = $conn->prepare("INSERT INTO password_resets 
                                 (user_id, reset_token, verification_code, expires_at, ip_address) 
                                 VALUES (?, ?, ?, ?, ?)");
    $reset_stmt->bind_param("issss", $user['id'], $reset_token, $verification_code, $expires_at, $ip_address);
    
    if (!$reset_stmt->execute()) {
        throw new Exception("Failed to create reset request");
    }
    
    // Generate reset link
    $reset_link = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . 
                  "://" . $_SERVER['HTTP_HOST'] . "/reset-password?token=" . urlencode($reset_token);
    
    // Send email
    $email_sent = sendResetEmail($email, $verification_code, $reset_link, $role, $user['username']);
    
    if (!$email_sent) {
        throw new Exception("Failed to send reset email. Please try again later.");
    }
    
    // Log the reset request
    logPasswordReset($conn, $user['id'], $ip_address, 'requested');
    incrementRateLimit('reset_request', $ip_address, $conn);
    
    echo json_encode([
        'success' => true,
        'message' => 'Password reset instructions have been sent to your email.',
        'data' => [
            'email' => $email,
            'verification_code' => $verification_code,
            'expires_in' => 15 // minutes
        ]
    ]);
}

function handleVerifyResetCode($conn, $data) {
    if (empty($data['code']) || empty($data['email']) || empty($data['role'])) {
        throw new Exception("Code, email, and role are required");
    }
    
    $code = preg_replace('/[^0-9]/', '', $data['code']);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $role = $conn->real_escape_string($data['role']);
    
    if (strlen($code) !== 6) {
        throw new Exception("Invalid verification code format");
    }
    
    // Find user and verify code
    $user_stmt = $conn->prepare("SELECT u.id FROM users u
                                JOIN password_resets pr ON u.id = pr.user_id
                                WHERE u.email = ? AND u.role = ? AND u.is_active = 1
                                AND pr.verification_code = ? AND pr.expires_at > NOW()
                                AND pr.used_at IS NULL");
    $user_stmt->bind_param("sss", $email, $role, $code);
    $user_stmt->execute();
    $user_result = $user_stmt->get_result();
    
    if ($user_result->num_rows === 0) {
        throw new Exception("Invalid or expired verification code");
    }
    
    $user = $user_result->fetch_assoc();
    
    // Generate auth token for password update
    $auth_token = bin2hex(random_bytes(16));
    
    // Store auth token
    $token_stmt = $conn->prepare("UPDATE password_resets SET auth_token = ? WHERE user_id = ? AND verification_code = ?");
    $token_stmt->bind_param("sis", $auth_token, $user['id'], $code);
    
    if (!$token_stmt->execute()) {
        throw new Exception("Failed to generate authentication token");
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Code verified successfully',
        'data' => [
            'auth_token' => $auth_token,
            'email' => $email
        ]
    ]);
}

function handleUpdatePassword($conn, $data) {
    if (empty($data['auth_token']) || empty($data['new_password']) || empty($data['confirm_password'])) {
        throw new Exception("All fields are required");
    }
    
    $auth_token = $conn->real_escape_string($data['auth_token']);
    $new_password = $data['new_password'];
    $confirm_password = $data['confirm_password'];
    $ip_address = getClientIP();
    
    // Validate passwords
    if ($new_password !== $confirm_password) {
        throw new Exception("Passwords do not match");
    }
    
    if (strlen($new_password) < 8) {
        throw new Exception("Password must be at least 8 characters long");
    }
    
    // Check password strength
    if (!preg_match('/[A-Z]/', $new_password) ||
        !preg_match('/[a-z]/', $new_password) ||
        !preg_match('/[0-9]/', $new_password)) {
        throw new Exception("Password must contain uppercase, lowercase, and number");
    }
    
    // Verify auth token
    $reset_stmt = $conn->prepare("SELECT pr.user_id, pr.expires_at, u.email, u.role
                                 FROM password_resets pr
                                 JOIN users u ON pr.user_id = u.id
                                 WHERE pr.auth_token = ? AND pr.expires_at > NOW()
                                 AND pr.used_at IS NULL");
    $reset_stmt->bind_param("s", $auth_token);
    $reset_stmt->execute();
    $reset_result = $reset_stmt->get_result();
    
    if ($reset_result->num_rows === 0) {
        throw new Exception("Invalid or expired reset token");
    }
    
    $reset_data = $reset_result->fetch_assoc();
    
    // Hash new password
    $hashed_password = password_hash($new_password, PASSWORD_ARGON2ID);
    
    // Update password
    $update_stmt = $conn->prepare("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?");
    $update_stmt->bind_param("si", $hashed_password, $reset_data['user_id']);
    
    if (!$update_stmt->execute()) {
        throw new Exception("Failed to update password");
    }
    
    // Mark reset as used
    $used_stmt = $conn->prepare("UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND auth_token = ?");
    $used_stmt->bind_param("is", $reset_data['user_id'], $auth_token);
    $used_stmt->execute();
    
    // Log password reset
    logPasswordReset($conn, $reset_data['user_id'], $ip_address, 'completed');
    
    echo json_encode([
        'success' => true,
        'message' => 'Password updated successfully. You can now login with your new password.'
    ]);
}

function handleValidateToken($conn, $data) {
    if (empty($data['token'])) {
        throw new Exception("Token is required");
    }
    
    $token = $conn->real_escape_string($data['token']);
    
    $stmt = $conn->prepare("SELECT pr.*, u.email, u.role
                           FROM password_resets pr
                           JOIN users u ON pr.user_id = u.id
                           WHERE pr.reset_token = ? AND pr.expires_at > NOW()
                           AND pr.used_at IS NULL");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception("Invalid or expired reset token");
    }
    
    $token_data = $result->fetch_assoc();
    
    echo json_encode([
        'success' => true,
        'message' => 'Token is valid',
        'data' => [
            'email' => $token_data['email'],
            'role' => $token_data['role'],
            'expires_at' => $token_data['expires_at']
        ]
    ]);
}

function handleLogout() {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Logged out successfully'
    ]);
}

// ==================== HELPER FUNCTIONS ====================

function getClientIP() {
    $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function logLoginAttempt($conn, $username, $ip, $user_agent, $status, $reason) {
    $stmt = $conn->prepare("INSERT INTO login_attempts 
                           (username, ip_address, user_agent, status, reason) 
                           VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $username, $ip, $user_agent, $status, $reason);
    $stmt->execute();
}

function logPasswordReset($conn, $user_id, $ip_address, $action) {
    $stmt = $conn->prepare("INSERT INTO password_reset_logs 
                           (user_id, action, ip_address) 
                           VALUES (?, ?, ?)");
    $stmt->bind_param("iss", $user_id, $action, $ip_address);
    $stmt->execute();
}

function sendResetEmail($to_email, $code, $link, $role, $username = 'User') {
    // For production, use PHPMailer, SwiftMailer, or Amazon SES
    
    $subject = "Eagle Homes - Password Reset";
    
    $message = "
    <html>
    <head>
        <title>Password Reset Request</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; background-color: #f8fafc; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .card { background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 30px; }
            .header { text-align: center; margin-bottom: 30px; }
            .code { background: #f1f5f9; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
            .button { background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; 
                     border-radius: 6px; font-weight: bold; display: inline-block; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='card'>
                <div class='header'>
                    <h2 style='color: #1e293b; margin: 0;'>Eagle Homes Property Management</h2>
                    <h3 style='color: #3b82f6; margin: 10px 0 0 0;'>Password Reset Request</h3>
                </div>
                
                <p>Hello " . htmlspecialchars($role) . " (" . htmlspecialchars($username) . "),</p>
                <p>You recently requested to reset your password for your Eagle Homes account.</p>
                
                <div class='code'>
                    <h4 style='margin: 0 0 10px 0; color: #1e293b;'>Your Verification Code:</h4>
                    <div style='font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #3b82f6;'>
                        " . htmlspecialchars($code) . "
                    </div>
                    <p style='color: #64748b; font-size: 14px; margin-top: 10px;'>
                        (This code expires in 15 minutes)
                    </p>
                </div>
                
                <p>Alternatively, you can click the link below to reset your password:</p>
                
                <div style='text-align: center; margin: 25px 0;'>
                    <a href='" . htmlspecialchars($link) . "' class='button'>
                        Reset Password
                    </a>
                </div>
                
                <p style='color: #64748b; font-size: 14px;'>
                    <strong>Important:</strong> If you didn't request this password reset, please ignore this email
                    or contact support if you have concerns about your account security.
                </p>
                
                <div class='footer'>
                    <p>© " . date('Y') . " Eagle Homes Digital Property Management. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Eagle Homes <noreply@eaglehomes.com>" . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    $headers .= "X-Priority: 1" . "\r\n";
    
    // Try to send email
    return mail($to_email, $subject, $message, $headers);
}

function isRateLimited($type, $ip, $conn) {
    $window_minutes = 15;
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count 
                           FROM rate_limits 
                           WHERE ip_address = ? AND action_type = ? 
                           AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $stmt->bind_param("ssi", $ip, $type, $window_minutes);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    $limit = ($type === 'login') ? 5 : 3;
    return $result['count'] >= $limit;
}

function incrementRateLimit($type, $ip, $conn) {
    $stmt = $conn->prepare("INSERT INTO rate_limits (ip_address, action_type) VALUES (?, ?)");
    $stmt->bind_param("ss", $ip, $type);
    $stmt->execute();
}

/*
-- Database Setup SQL --
-- Run these commands in your MySQL database:

-- 1. Create database
CREATE DATABASE IF NOT EXISTS eagles_home_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role ENUM('owner', 'secretary', 'admin') NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email_role (email, role),
    INDEX idx_username_role (username, role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Create password_resets table
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reset_token VARCHAR(64) UNIQUE,
    verification_code VARCHAR(6),
    auth_token VARCHAR(32),
    expires_at DATETIME NOT NULL,
    ip_address VARCHAR(45),
    attempts INT DEFAULT 0,
    used_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_reset_token (reset_token),
    INDEX idx_user_expires (user_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Create login_attempts table
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    status ENUM('success', 'failed') NOT NULL,
    reason VARCHAR(100),
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, attempt_time),
    INDEX idx_username_time (username, attempt_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Create user_sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_valid BOOLEAN DEFAULT TRUE,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token),
    INDEX idx_user_valid (user_id, is_valid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Create password_reset_logs table
CREATE TABLE IF NOT EXISTS password_reset_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action ENUM('requested', 'completed', 'failed') NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Create rate_limits table
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_type_time (ip_address, action_type, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Insert default users (replace with your actual passwords)
INSERT INTO users (username, password, email, role) VALUES
('owner_admin', '$argon2id$v=19$m=65536,t=4,p=1$LzJvR2U0Lk5xM3pNZzVURA$NH1VpJmSDcRUK8Z6hTg8HwnvKx4G3d7T2Qb2Z4Lm5N0', 'jeremiahmburu76@gmail.com', 'owner'),
('secretary_entry', '$argon2id$v=19$m=65536,t=4,p=1$LzJvR2U0Lk5xM3pNZzVURA$NH1VpJmSDcRUK8Z6hTg8HwnvKx4G3d7T2Qb2Z4Lm5N0', 'jeremiahmburu76@gmail.com', 'secretary');

-- To generate password hashes, use this PHP code:
-- echo password_hash('Eagles2026!', PASSWORD_ARGON2ID);
-- echo password_hash('Secret2026!', PASSWORD_ARGON2ID);

*/
?>
