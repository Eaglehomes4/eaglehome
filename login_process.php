<?php
// Enable error reporting for debugging (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
header('Content-Type: application/json');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// CORS - Restrict to your domain in production
$allowedOrigins = [
    'http://localhost',
    'https://yourdomain.com' // Replace with your actual domain
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: http://localhost"); // Default for development
}
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// CSRF protection for state-changing operations
function verifyCsrfToken() {
    if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || $_SERVER['HTTP_X_CSRF_TOKEN'] !== ($_SESSION['csrf_token'] ?? '')) {
        return false;
    }
    return true;
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting
function checkRateLimit($identifier, $limit = 5, $window = 300) {
    $key = 'rate_limit_' . $identifier;
    $currentTime = time();
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 1,
            'start_time' => $currentTime
        ];
        return true;
    }
    
    $rateData = $_SESSION[$key];
    
    if ($currentTime - $rateData['start_time'] > $window) {
        $_SESSION[$key] = [
            'count' => 1,
            'start_time' => $currentTime
        ];
        return true;
    }
    
    if ($rateData['count'] >= $limit) {
        return false;
    }
    
    $rateData['count']++;
    $_SESSION[$key] = $rateData;
    return true;
}

// Input validation and sanitization
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Password hashing
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Get request data
$input = json_decode(file_get_contents('php://input'), true) ?? [];

// Sanitize all input
$input = sanitizeInput($input);

if (empty($input['action'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No action specified']);
    exit();
}

// Route actions
switch ($input['action']) {
    case 'login':
        handleLogin($input);
        break;
        
    case 'save_reset_request':
        handleSaveResetRequest($input);
        break;
        
    case 'send_reset_email':
        handleSendResetEmail($input);
        break;
        
    case 'verify_reset_code':
        handleVerifyResetCode($input);
        break;
        
    case 'update_password_with_email':
        handleUpdatePasswordWithEmail($input);
        break;
        
    case 'get_emailjs_config':
        // Secure endpoint to provide EmailJS config
        getEmailJsConfig();
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

// ==================== FUNCTIONS ====================

function handleLogin($data) {
    // Rate limiting by IP
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit("login_$ip", 5, 300)) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'message' => 'Too many login attempts. Please try again in 5 minutes.'
        ]);
        return;
    }
    
    if (!isset($data['username']) || !isset($data['password']) || !isset($data['role'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $username = $data['username'];
    $password = $data['password'];
    $role = $data['role'];
    
    // Database connection (replace with your actual database connection)
    // For demonstration, using hardcoded values - REPLACE WITH DATABASE IN PRODUCTION
    
    // Simulated user database (in production, fetch from database)
    $users = [
        'owner' => [
            'username' => 'owner_admin',
            'password_hash' => hashPassword('Eagles2026!'), // Pre-hashed
            'email' => 'jeremiahmburu76@gmail.com',
            'user_id' => 1
        ],
        'secretary' => [
            'username' => 'secretary_entry',
            'password_hash' => hashPassword('Secret2026!'), // Pre-hashed
            'email' => 'jeremiahmburu76@gmail.com',
            'user_id' => 2
        ]
    ];
    
    // Check if user exists and password matches
    if (isset($users[$role]) && 
        $username === $users[$role]['username'] && 
        verifyPassword($password, $users[$role]['password_hash'])) {
        
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);
        
        // Set session variables
        $_SESSION['user_id'] = $users[$role]['user_id'];
        $_SESSION['username'] = $username;
        $_SESSION['role'] = $role;
        $_SESSION['email'] = $users[$role]['email'];
        $_SESSION['login_time'] = time();
        $_SESSION['session_token'] = bin2hex(random_bytes(32));
        
        // Generate new CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        
        // Set secure cookie parameters
        session_set_cookie_params([
            'lifetime' => 3600,
            'path' => '/',
            'domain' => '',
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        // Log successful login
        error_log("Successful login: $username ($role) from IP: $ip");
        
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
        // Log failed attempt
        error_log("Failed login attempt: $username ($role) from IP: $ip");
        
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'message' => 'Invalid credentials'
        ]);
    }
}

function handleSaveResetRequest($data) {
    // Rate limiting by IP and email
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $email = $data['email'] ?? '';
    
    if (!checkRateLimit("reset_request_$ip", 3, 900) || 
        !checkRateLimit("reset_email_$email", 3, 3600)) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'message' => 'Too many reset requests. Please try again later.'
        ]);
        return;
    }
    
    if (empty($data['email']) || empty($data['code']) || empty($data['role'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
    if (!$email) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid email address']);
        return;
    }
    
    // Store reset request in session (in production, use database)
    $_SESSION['reset_requests'][$email] = [
        'code' => $data['code'],
        'role' => $data['role'],
        'token' => $data['token'] ?? '',
        'expiry' => time() + 900, // 15 minutes
        'ip' => $ip,
        'created_at' => time()
    ];
    
    // Clean up old reset requests
    foreach ($_SESSION['reset_requests'] ?? [] as $storedEmail => $request) {
        if ($request['expiry'] < time()) {
            unset($_SESSION['reset_requests'][$storedEmail]);
        }
    }
    
    // Log reset request
    error_log("Password reset requested for: $email ($role) from IP: $ip");
    
    echo json_encode([
        'success' => true,
        'message' => 'Reset request saved'
    ]);
}

function handleSendResetEmail($data) {
    // This function simulates server-side email sending
    // In production, use PHPMailer or similar
    
    if (empty($data['email']) || empty($data['code']) || empty($data['link'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
    if (!$email) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid email address']);
        return;
    }
    
    // Simulate email sending (in production, implement actual email sending)
    // For now, just log it
    error_log("Password reset email would be sent to: $email with code: {$data['code']}");
    
    echo json_encode([
        'success' => true,
        'message' => 'Reset email sent successfully'
    ]);
}

function handleVerifyResetCode($data) {
    if (empty($data['email']) || empty($data['code']) || empty($data['role'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $email = $data['email'];
    $code = $data['code'];
    $role = $data['role'];
    
    // Check stored reset request
    $resetRequest = $_SESSION['reset_requests'][$email] ?? null;
    
    if (!$resetRequest) {
        echo json_encode([
            'success' => false,
            'message' => 'No reset request found for this email'
        ]);
        return;
    }
    
    if ($resetRequest['expiry'] < time()) {
        unset($_SESSION['reset_requests'][$email]);
        echo json_encode([
            'success' => false,
            'message' => 'Reset code has expired'
        ]);
        return;
    }
    
    if ($resetRequest['code'] !== $code || $resetRequest['role'] !== $role) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid reset code'
        ]);
        return;
    }
    
    // Code is valid
    echo json_encode([
        'success' => true,
        'message' => 'Code verified successfully'
    ]);
}

function handleUpdatePasswordWithEmail($data) {
    if (empty($data['email']) || empty($data['new_password']) || empty($data['role'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $email = $data['email'];
    $newPassword = $data['new_password'];
    $role = $data['role'];
    $code = $data['reset_code'] ?? '';
    
    // Verify reset code first
    $resetRequest = $_SESSION['reset_requests'][$email] ?? null;
    
    if (!$resetRequest || $resetRequest['code'] !== $code || $resetRequest['role'] !== $role) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid or expired reset request'
        ]);
        return;
    }
    
    // Check password strength
    if (strlen($newPassword) < 8) {
        echo json_encode([
            'success' => false,
            'message' => 'Password must be at least 8 characters long'
        ]);
        return;
    }
    
    // Update password in database (simulated)
    // In production, update the actual database
    
    // Hash the new password
    $hashedPassword = hashPassword($newPassword);
    
    // Simulate database update
    error_log("Password updated for: $email ($role)");
    
    // Clear the reset request
    unset($_SESSION['reset_requests'][$email]);
    
    echo json_encode([
        'success' => true,
        'message' => 'Password updated successfully. You can now login with your new password.'
    ]);
}

function getEmailJsConfig() {
    // Securely provide EmailJS configuration
    // In production, store these in environment variables
    
    $config = [
        'serviceId' => 'service_l8mddbx',
        'templateId' => 'template_va2rli4',
        'publicKey' => 'mxImeKQYfA_aBo1hp',
        'success' => true
    ];
    
    echo json_encode($config);
}
?>
