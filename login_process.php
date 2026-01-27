<?php
session_start();
header('Content-Type: application/json');

// Enable CORS for development
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Get input data
$input = json_decode(file_get_contents('php://input'), true);

// If no JSON data, try POST
if (empty($input) && !empty($_POST)) {
    $input = $_POST;
}

// If still no input, return error
if (empty($input)) {
    echo json_encode([
        'success' => false,
        'message' => 'No input data received'
    ]);
    exit();
}

// Get action
$action = $input['action'] ?? '';

// Route actions
switch ($action) {
    case 'login':
        handleLogin($input);
        break;
        
    case 'send_reset_email':
        handleSendResetEmail($input);
        break;
        
    case 'verify_reset_code':
        handleVerifyResetCode($input);
        break;
        
    case 'update_password_with_email':
        handleUpdatePassword($input);
        break;
        
    case 'get_emailjs_config':
        getEmailJSConfig();
        break;
        
    default:
        echo json_encode([
            'success' => false,
            'message' => 'Invalid action'
        ]);
        break;
}

// Functions
function handleLogin($data) {
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $role = $data['role'] ?? '';
    
    // Demo credentials - REPLACE WITH DATABASE IN PRODUCTION
    $validCredentials = [
        'owner' => [
            'username' => 'owner_admin',
            'password' => 'Eagles2026!',
            'email' => 'jeremiahmburu76@gmail.com'
        ],
        'secretary' => [
            'username' => 'secretary_entry',
            'password' => 'Secret2026!',
            'email' => 'jeremiahmburu76@gmail.com'
        ]
    ];
    
    // Check if role exists
    if (!isset($validCredentials[$role])) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid role'
        ]);
        return;
    }
    
    $user = $validCredentials[$role];
    
    // Check credentials
    if ($username === $user['username'] && $password === $user['password']) {
        // Set session
        $_SESSION['user_id'] = $role === 'owner' ? 1 : 2;
        $_SESSION['username'] = $username;
        $_SESSION['role'] = $role;
        $_SESSION['email'] = $user['email'];
        $_SESSION['session_token'] = bin2hex(random_bytes(32));
        
        echo json_encode([
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'user_id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'role' => $_SESSION['role'],
                'email' => $_SESSION['email'],
                'session_token' => $_SESSION['session_token']
            ]
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid username or password'
        ]);
    }
}

function handleSendResetEmail($data) {
    $email = $data['email'] ?? '';
    $role = $data['role'] ?? '';
    $code = $data['code'] ?? '';
    $link = $data['link'] ?? '';
    
    if (empty($email) || empty($role)) {
        echo json_encode([
            'success' => false,
            'message' => 'Missing required fields'
        ]);
        return;
    }
    
    // Store reset request in session
    $_SESSION['reset_request'] = [
        'email' => $email,
        'role' => $role,
        'code' => $code,
        'expiry' => time() + 900, // 15 minutes
        'created' => time()
    ];
    
    // Log the email data (in production, send actual email)
    error_log("Reset email would be sent to: $email with code: $code");
    
    echo json_encode([
        'success' => true,
        'message' => 'Reset email sent successfully'
    ]);
}

function handleVerifyResetCode($data) {
    $email = $data['email'] ?? '';
    $code = $data['code'] ?? '';
    $role = $data['role'] ?? '';
    
    // Check if reset request exists
    if (!isset($_SESSION['reset_request'])) {
        echo json_encode([
            'success' => false,
            'message' => 'No reset request found'
        ]);
        return;
    }
    
    $resetRequest = $_SESSION['reset_request'];
    
    // Check expiry
    if (time() > $resetRequest['expiry']) {
        unset($_SESSION['reset_request']);
        echo json_encode([
            'success' => false,
            'message' => 'Reset code has expired'
        ]);
        return;
    }
    
    // Verify email, role, and code
    if ($resetRequest['email'] === $email && 
        $resetRequest['role'] === $role && 
        $resetRequest['code'] === $code) {
        
        echo json_encode([
            'success' => true,
            'message' => 'Code verified successfully'
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid reset code'
        ]);
    }
}

function handleUpdatePassword($data) {
    $email = $data['email'] ?? '';
    $role = $data['role'] ?? '';
    $newPassword = $data['new_password'] ?? '';
    
    if (empty($email) || empty($role) || empty($newPassword)) {
        echo json_encode([
            'success' => false,
            'message' => 'Missing required fields'
        ]);
        return;
    }
    
    // Check password strength
    if (strlen($newPassword) < 8) {
        echo json_encode([
            'success' => false,
            'message' => 'Password must be at least 8 characters'
        ]);
        return;
    }
    
    // In production, update database here
    // For demo, just log the update
    error_log("Password updated for $email ($role)");
    
    // Clear reset request
    unset($_SESSION['reset_request']);
    
    echo json_encode([
        'success' => true,
        'message' => 'Password updated successfully'
    ]);
}

function getEmailJSConfig() {
    // Return EmailJS configuration
    echo json_encode([
        'serviceId' => 'service_l8mddbx',
        'templateId' => 'template_va2rli4',
        'publicKey' => 'mxImeKQYfA_aBo1hp',
        'success' => true
    ]);
}
?>
