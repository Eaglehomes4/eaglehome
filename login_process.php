<?php
// login_process.php - Complete Password Reset System
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// Database configuration (for production)
$host = 'localhost';
$dbname = 'eagle_homes';
$username = 'root';
$password = '';

// Demo data storage files
$usersFile = 'users.json';
$resetsFile = 'resets.json';
$logsFile = 'logs.json';

// Initialize files if they don't exist
function initFiles() {
    global $usersFile, $resetsFile, $logsFile;
    
    if (!file_exists($usersFile)) {
        $defaultUsers = [
            'owner_admin' => [
                'id' => 1,
                'email' => 'jeremiahmburu76@gmail.com',
                'username' => 'owner_admin',
                'password_hash' => hash('sha256', 'Eagles2026!'),
                'role' => 'owner',
                'created_at' => date('Y-m-d H:i:s'),
                'last_login' => null,
                'active' => true
            ],
            'secretary_entry' => [
                'id' => 2,
                'email' => 'secretary@example.com',
                'username' => 'secretary_entry',
                'password_hash' => hash('sha256', 'Secret2026!'),
                'role' => 'secretary',
                'created_at' => date('Y-m-d H:i:s'),
                'last_login' => null,
                'active' => true
            ]
        ];
        file_put_contents($usersFile, json_encode($defaultUsers, JSON_PRETTY_PRINT));
    }
    
    if (!file_exists($resetsFile)) {
        file_put_contents($resetsFile, json_encode([], JSON_PRETTY_PRINT));
    }
    
    if (!file_exists($logsFile)) {
        file_put_contents($logsFile, json_encode([], JSON_PRETTY_PRINT));
    }
}

// Log activity
function logActivity($action, $data, $ip = null) {
    global $logsFile;
    $ip = $ip ?: $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    
    $log = [
        'timestamp' => date('Y-m-d H:i:s'),
        'action' => $action,
        'ip' => $ip,
        'data' => $data
    ];
    
    $logs = file_exists($logsFile) ? json_decode(file_get_contents($logsFile), true) : [];
    $logs[] = $log;
    
    // Keep only last 1000 logs
    if (count($logs) > 1000) {
        $logs = array_slice($logs, -1000);
    }
    
    file_put_contents($logsFile, json_encode($logs, JSON_PRETTY_PRINT));
}

// Send email function
function sendResetEmail($to, $code, $token, $role) {
    $subject = "Eagle Homes - Password Reset Request";
    
    // Create reset link
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $resetLink = "$protocol://$host/index.html?token=" . urlencode($token);
    
    // HTML email content
    $message = "
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
            .container { border: 1px solid #e0e0e0; border-radius: 10px; overflow: hidden; }
            .header { background: linear-gradient(135deg, #2563eb, #1e40af); color: white; padding: 30px 20px; text-align: center; }
            .logo { font-size: 24px; font-weight: bold; margin-bottom: 10px; }
            .content { padding: 30px; background: white; }
            .code-box { background: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
            .code { font-size: 36px; font-weight: bold; color: #2563eb; letter-spacing: 5px; }
            .button { display: inline-block; background: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 15px 0; }
            .footer { text-align: center; color: #64748b; font-size: 12px; padding: 20px; border-top: 1px solid #e2e8f0; }
            .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 10px; margin: 15px 0; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <div class='logo'>🏠 Eagle Homes</div>
                <h2>Password Reset Request</h2>
            </div>
            
            <div class='content'>
                <p>Hello,</p>
                <p>You have requested to reset your password for your <strong>Eagle Homes $role account</strong>.</p>
                
                <div class='code-box'>
                    <p><strong>Your 6-digit reset code:</strong></p>
                    <div class='code'>$code</div>
                    <p style='font-size: 12px; color: #64748b;'>This code expires in 15 minutes</p>
                </div>
                
                <div style='text-align: center;'>
                    <p><strong>Or click the button below to reset:</strong></p>
                    <a href='$resetLink' class='button'>Reset Password Now</a>
                </div>
                
                <div class='warning'>
                    <strong>⚠️ Important:</strong>
                    <ul style='margin: 5px 0; padding-left: 20px;'>
                        <li>If you didn't request this, please ignore this email</li>
                        <li>Never share your reset code with anyone</li>
                        <li>The reset link will expire in 15 minutes</li>
                    </ul>
                </div>
                
                <p>If the button doesn't work, copy and paste this link in your browser:</p>
                <p style='background: #f1f5f9; padding: 10px; border-radius: 5px; word-break: break-all; font-size: 12px;'>
                    $resetLink
                </p>
            </div>
            
            <div class='footer'>
                <p>© " . date('Y') . " Eagle Homes. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
                <p>Contact: support@eaglehomes.com</p>
            </div>
        </div>
    </body>
    </html>
    ";
    
    // Headers for HTML email
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Eagle Homes <noreply@eaglehomes.com>" . "\r\n";
    $headers .= "Reply-To: noreply@eaglehomes.com" . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    // Try to send email
    $sent = mail($to, $subject, $message, $headers);
    
    // Also log the email for debugging
    $emailLog = [
        'to' => $to,
        'code' => $code,
        'link' => $resetLink,
        'sent' => $sent,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    file_put_contents('email_logs.txt', json_encode($emailLog) . PHP_EOL, FILE_APPEND);
    
    return $sent;
}

// Initialize files
initFiles();

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
        
    case 'reset_password':
        handleResetPassword($input);
        break;
        
    case 'check_reset_status':
        handleCheckResetStatus($input);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

// Handle login
function handleLogin($input) {
    $username = $input['username'] ?? '';
    $password = $input['password'] ?? '';
    $role = $input['role'] ?? 'owner';
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username and password required']);
        return;
    }
    
    // Log login attempt
    logActivity('login_attempt', [
        'username' => $username,
        'role' => $role,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    
    // Load users
    $usersFile = 'users.json';
    $users = json_decode(file_get_contents($usersFile), true);
    
    // Find user by username or email
    $foundUser = null;
    foreach ($users as $user) {
        if (($user['username'] === $username || $user['email'] === $username) && 
            $user['role'] === $role && 
            $user['active'] === true) {
            $foundUser = $user;
            break;
        }
    }
    
    if (!$foundUser) {
        logActivity('login_failed', ['reason' => 'user_not_found', 'username' => $username]);
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        return;
    }
    
    // Check password (compare hashes)
    $inputHash = hash('sha256', $password);
    if ($inputHash === $foundUser['password_hash']) {
        // Update last login
        $users[$foundUser['username']]['last_login'] = date('Y-m-d H:i:s');
        file_put_contents($usersFile, json_encode($users, JSON_PRETTY_PRINT));
        
        // Generate session token
        $sessionToken = bin2hex(random_bytes(32));
        
        // Store session (in production, use database)
        $sessionsFile = 'sessions.json';
        $sessions = file_exists($sessionsFile) ? json_decode(file_get_contents($sessionsFile), true) : [];
        $sessions[$sessionToken] = [
            'user_id' => $foundUser['id'],
            'username' => $foundUser['username'],
            'role' => $foundUser['role'],
            'created' => time(),
            'expires' => time() + (24 * 60 * 60) // 24 hours
        ];
        file_put_contents($sessionsFile, json_encode($sessions, JSON_PRETTY_PRINT));
        
        logActivity('login_success', ['username' => $foundUser['username'], 'role' => $foundUser['role']]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'session_token' => $sessionToken,
                'username' => $foundUser['username'],
                'email' => $foundUser['email'],
                'role' => $foundUser['role']
            ]
        ]);
    } else {
        logActivity('login_failed', ['reason' => 'wrong_password', 'username' => $foundUser['username']]);
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
    }
}

// Handle sending reset email
function handleSendResetEmail($input) {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    $role = $input['role'] ?? 'owner';
    $token = $input['token'] ?? '';
    
    if (empty($email) || empty($code)) {
        echo json_encode(['success' => false, 'message' => 'Email and code required']);
        return;
    }
    
    // Load users to verify email exists
    $usersFile = 'users.json';
    $users = json_decode(file_get_contents($usersFile), true);
    
    $userExists = false;
    foreach ($users as $user) {
        if ($user['email'] === $email && $user['role'] === $role) {
            $userExists = true;
            break;
        }
    }
    
    if (!$userExists) {
        echo json_encode(['success' => false, 'message' => 'No account found with this email and role']);
        return;
    }
    
    // Store reset request
    $resetsFile = 'resets.json';
    $resets = file_exists($resetsFile) ? json_decode(file_get_contents($resetsFile), true) : [];
    
    // Remove any existing resets for this email
    $resets = array_filter($resets, function($reset) use ($email) {
        return $reset['email'] !== $email;
    });
    
    // Add new reset request
    $resetData = [
        'email' => $email,
        'role' => $role,
        'code' => $code,
        'token' => $token,
        'created' => time(),
        'expires' => time() + (15 * 60), // 15 minutes
        'verified' => false,
        'used' => false
    ];
    
    $resets[] = $resetData;
    file_put_contents($resetsFile, json_encode($resets, JSON_PRETTY_PRINT));
    
    // Try to send email
    $emailSent = sendResetEmail($email, $code, $token, $role);
    
    logActivity('reset_request', [
        'email' => $email,
        'role' => $role,
        'email_sent' => $emailSent
    ]);
    
    if ($emailSent) {
        echo json_encode([
            'success' => true,
            'message' => 'Reset email sent successfully',
            'data' => [
                'email' => $email,
                'code' => $code,
                'expires' => $resetData['expires']
            ]
        ]);
    } else {
        // Still return success but note email may be delayed
        echo json_encode([
            'success' => true,
            'message' => 'Reset request recorded. Email may be delayed.',
            'data' => [
                'email' => $email,
                'code' => $code,
                'expires' => $resetData['expires'],
                'note' => 'Check spam folder or use manual code'
            ]
        ]);
    }
}

// Handle reset code verification
function handleVerifyResetCode($input) {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    
    if (empty($email) || empty($code) || strlen($code) !== 6) {
        echo json_encode(['success' => false, 'message' => 'Valid email and 6-digit code required']);
        return;
    }
    
    $resetsFile = 'resets.json';
    $resets = file_exists($resetsFile) ? json_decode(file_get_contents($resetsFile), true) : [];
    
    foreach ($resets as &$reset) {
        if ($reset['email'] === $email && $reset['code'] === $code) {
            if ($reset['expires'] > time()) {
                if (!$reset['used']) {
                    $reset['verified'] = true;
                    $reset['verified_at'] = time();
                    file_put_contents($resetsFile, json_encode($resets, JSON_PRETTY_PRINT));
                    
                    logActivity('reset_verified', ['email' => $email, 'success' => true]);
                    
                    echo json_encode([
                        'success' => true,
                        'message' => 'Code verified successfully',
                        'data' => [
                            'email' => $email,
                            'role' => $reset['role'],
                            'expires' => $reset['expires']
                        ]
                    ]);
                    return;
                } else {
                    echo json_encode(['success' => false, 'message' => 'Reset code already used']);
                    return;
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'Reset code has expired']);
                return;
            }
        }
    }
    
    logActivity('reset_verified', ['email' => $email, 'success' => false, 'reason' => 'code_not_found']);
    echo json_encode(['success' => false, 'message' => 'Invalid reset code']);
}

// Handle password reset
function handleResetPassword($input) {
    $email = $input['email'] ?? '';
    $role = $input['role'] ?? 'owner';
    $newPassword = $input['new_password'] ?? ''; // Already hashed from frontend
    $code = $input['code'] ?? '';
    
    if (empty($email) || empty($newPassword) || empty($code)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    // Load reset requests
    $resetsFile = 'resets.json';
    $resets = file_exists($resetsFile) ? json_decode(file_get_contents($resetsFile), true) : [];
    
    // Find and verify the reset request
    $resetFound = false;
    $resetIndex = -1;
    
    foreach ($resets as $index => $reset) {
        if ($reset['email'] === $email && 
            $reset['role'] === $role && 
            $reset['code'] === $code && 
            $reset['verified'] === true &&
            $reset['expires'] > time() &&
            !$reset['used']) {
            $resetFound = true;
            $resetIndex = $index;
            break;
        }
    }
    
    if (!$resetFound) {
        echo json_encode(['success' => false, 'message' => 'Invalid or expired reset request']);
        return;
    }
    
    // Load users
    $usersFile = 'users.json';
    $users = json_decode(file_get_contents($usersFile), true);
    
    // Update user password
    $userUpdated = false;
    foreach ($users as $username => &$user) {
        if ($user['email'] === $email && $user['role'] === $role) {
            $user['password_hash'] = $newPassword;
            $user['password_changed_at'] = date('Y-m-d H:i:s');
            $userUpdated = true;
            break;
        }
    }
    
    if (!$userUpdated) {
        echo json_encode(['success' => false, 'message' => 'User not found']);
        return;
    }
    
    // Save updated users
    file_put_contents($usersFile, json_encode($users, JSON_PRETTY_PRINT));
    
    // Mark reset as used
    $resets[$resetIndex]['used'] = true;
    $resets[$resetIndex]['used_at'] = time();
    file_put_contents($resetsFile, json_encode($resets, JSON_PRETTY_PRINT));
    
    // Clear any other reset requests for this email
    $resets = array_filter($resets, function($r) use ($email) {
        return $r['email'] !== $email || $r['used'];
    });
    file_put_contents($resetsFile, json_encode($resets, JSON_PRETTY_PRINT));
    
    logActivity('password_reset', [
        'email' => $email,
        'role' => $role,
        'success' => true
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => 'Password reset successfully! You can now login with your new password.',
        'data' => [
            'email' => $email,
            'role' => $role,
            'timestamp' => date('Y-m-d H:i:s')
        ]
    ]);
}

// Handle reset status check
function handleCheckResetStatus($input) {
    $email = $input['email'] ?? '';
    $token = $input['token'] ?? '';
    
    if (empty($email)) {
        echo json_encode(['success' => false, 'message' => 'Email required']);
        return;
    }
    
    $resetsFile = 'resets.json';
    $resets = file_exists($resetsFile) ? json_decode(file_get_contents($resetsFile), true) : [];
    
    foreach ($resets as $reset) {
        if ($reset['email'] === $email) {
            $status = [
                'exists' => true,
                'expired' => $reset['expires'] <= time(),
                'verified' => $reset['verified'] ?? false,
                'used' => $reset['used'] ?? false,
                'expires_in' => max(0, $reset['expires'] - time())
            ];
            
            echo json_encode([
                'success' => true,
                'message' => 'Reset request found',
                'data' => $status
            ]);
            return;
        }
    }
    
    echo json_encode([
        'success' => false,
        'message' => 'No reset request found',
        'data' => ['exists' => false]
    ]);
}
?>
