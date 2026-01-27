<?php
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

// Simple file-based storage for demo
$usersFile = 'users.json';
$resetsFile = 'resets.json';

// Initialize files if they don't exist
if (!file_exists($usersFile)) {
    $defaultUsers = [
        'owner_admin' => [
            'email' => 'jeremiahmburu76@gmail.com',
            'password' => 'Eagles2026!', // Will be hashed on first use
            'role' => 'owner',
            'username' => 'owner_admin'
        ],
        'secretary_entry' => [
            'email' => 'secretary@example.com',
            'password' => 'Secret2026!',
            'role' => 'secretary',
            'username' => 'secretary_entry'
        ]
    ];
    file_put_contents($usersFile, json_encode($defaultUsers, JSON_PRETTY_PRINT));
}

if (!file_exists($resetsFile)) {
    file_put_contents($resetsFile, json_encode([]));
}

switch ($action) {
    case 'login':
        handleLogin($input);
        break;
        
    case 'request_reset':
        handleRequestReset($input);
        break;
        
    case 'verify_reset_code':
        handleVerifyCode($input);
        break;
        
    case 'reset_password':
        handleResetPassword($input);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

function handleLogin($data) {
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $role = $data['role'] ?? 'owner';
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username and password required']);
        return;
    }
    
    $users = json_decode(file_get_contents('users.json'), true);
    
    // Check if user exists
    if (isset($users[$username])) {
        $user = $users[$username];
        
        // For demo, we'll store plain password first time, then check
        if (!isset($user['password_hash'])) {
            // First time login - create hash from plain password
            if ($user['password'] === $password && $user['role'] === $role) {
                // Create hash for future logins
                $users[$username]['password_hash'] = hash('sha256', $password);
                unset($users[$username]['password']);
                file_put_contents('users.json', json_encode($users, JSON_PRETTY_PRINT));
                
                $sessionToken = bin2hex(random_bytes(32));
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => [
                        'session_token' => $sessionToken,
                        'username' => $username,
                        'role' => $user['role'],
                        'email' => $user['email']
                    ]
                ]);
                return;
            }
        } else {
            // Check hashed password
            if (hash('sha256', $password) === $user['password_hash'] && $user['role'] === $role) {
                $sessionToken = bin2hex(random_bytes(32));
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => [
                        'session_token' => $sessionToken,
                        'username' => $username,
                        'role' => $user['role'],
                        'email' => $user['email']
                    ]
                ]);
                return;
            }
        }
    }
    
    // Also check by email for password reset scenarios
    foreach ($users as $userData) {
        if (isset($userData['email']) && $userData['email'] === $username && isset($userData['password_hash'])) {
            if (hash('sha256', $password) === $userData['password_hash'] && $userData['role'] === $role) {
                $sessionToken = bin2hex(random_bytes(32));
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => [
                        'session_token' => $sessionToken,
                        'username' => $userData['username'],
                        'role' => $userData['role'],
                        'email' => $userData['email']
                    ]
                ]);
                return;
            }
        }
    }
    
    echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
}

function handleRequestReset($data) {
    $email = $data['email'] ?? '';
    $role = $data['role'] ?? 'owner';
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Valid email address required']);
        return;
    }
    
    $users = json_decode(file_get_contents('users.json'), true);
    
    // Find user by email and role
    $foundUser = null;
    foreach ($users as $user) {
        if (isset($user['email']) && $user['email'] === $email && $user['role'] === $role) {
            $foundUser = $user;
            break;
        }
    }
    
    if (!$foundUser) {
        echo json_encode(['success' => false, 'message' => 'No account found with this email and role']);
        return;
    }
    
    // Generate reset code (6 digits)
    $resetCode = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
    
    // Create reset token
    $resetData = [
        'email' => $email,
        'role' => $role,
        'code' => $resetCode,
        'expires' => time() + (15 * 60), // 15 minutes
        'created' => time(),
        'verified' => false,
        'username' => $foundUser['username']
    ];
    
    // Store reset data
    $resets = json_decode(file_get_contents('resets.json'), true);
    // Remove any existing resets for this email
    $resets = array_filter($resets, function($reset) use ($email) {
        return $reset['email'] !== $email;
    });
    $resets[] = $resetData;
    file_put_contents('resets.json', json_encode($resets, JSON_PRETTY_PRINT));
    
    // Return success - frontend will handle EmailJS
    echo json_encode([
        'success' => true,
        'message' => 'Reset code generated',
        'data' => [
            'email' => $email,
            'role' => $role,
            'code' => $resetCode,
            'expires' => $resetData['expires'],
            'reset_token' => base64_encode(json_encode($resetData))
        ]
    ]);
}

function handleVerifyCode($data) {
    $email = $data['email'] ?? '';
    $code = $data['code'] ?? '';
    
    if (empty($email) || empty($code) || strlen($code) !== 6) {
        echo json_encode(['success' => false, 'message' => 'Valid email and 6-digit code required']);
        return;
    }
    
    $resets = json_decode(file_get_contents('resets.json'), true);
    
    foreach ($resets as &$reset) {
        if ($reset['email'] === $email && $reset['code'] === $code) {
            if ($reset['expires'] > time()) {
                $reset['verified'] = true;
                file_put_contents('resets.json', json_encode($resets, JSON_PRETTY_PRINT));
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Code verified successfully',
                    'data' => [
                        'email' => $email,
                        'role' => $reset['role'],
                        'username' => $reset['username']
                    ]
                ]);
                return;
            } else {
                echo json_encode(['success' => false, 'message' => 'Reset code has expired']);
                return;
            }
        }
    }
    
    echo json_encode(['success' => false, 'message' => 'Invalid reset code']);
}

function handleResetPassword($data) {
    $email = $data['email'] ?? '';
    $role = $data['role'] ?? 'owner';
    $newPassword = $data['new_password'] ?? '';
    $code = $data['code'] ?? '';
    
    if (empty($email) || empty($newPassword) || empty($code)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    // Check password strength
    if (strlen($newPassword) < 8) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters']);
        return;
    }
    
    $resets = json_decode(file_get_contents('resets.json'), true);
    $users = json_decode(file_get_contents('users.json'), true);
    
    // Find and verify the reset request
    $resetFound = false;
    foreach ($resets as $reset) {
        if ($reset['email'] === $email && 
            $reset['role'] === $role && 
            $reset['code'] === $code && 
            $reset['verified'] === true &&
            $reset['expires'] > time()) {
            $resetFound = true;
            break;
        }
    }
    
    if (!$resetFound) {
        echo json_encode(['success' => false, 'message' => 'Invalid or expired reset request']);
        return;
    }
    
    // Update password in users file
    foreach ($users as $username => &$user) {
        if ($user['email'] === $email && $user['role'] === $role) {
            // Hash the new password
            $user['password_hash'] = hash('sha256', $newPassword);
            if (isset($user['password'])) {
                unset($user['password']);
            }
            
            // Save users
            file_put_contents('users.json', json_encode($users, JSON_PRETTY_PRINT));
            
            // Remove the used reset request
            $resets = array_filter($resets, function($r) use ($email) {
                return $r['email'] !== $email;
            });
            file_put_contents('resets.json', json_encode($resets, JSON_PRETTY_PRINT));
            
            echo json_encode([
                'success' => true,
                'message' => 'Password reset successfully! You can now login with your new password.',
                'data' => [
                    'email' => $email,
                    'username' => $user['username'],
                    'role' => $role
                ]
            ]);
            return;
        }
    }
    
    echo json_encode(['success' => false, 'message' => 'User not found']);
}
?>
