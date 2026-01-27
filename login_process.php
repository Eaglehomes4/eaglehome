<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Database configuration
$host = 'localhost';
$dbname = 'eagle_homes';
$username = 'root';
$password = '';

// Get POST data
$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// Database connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit;
}

function createPasswordHash($password) {
    // Use password_hash for secure password hashing
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

switch ($action) {
    case 'login':
        handleLogin($input, $pdo);
        break;
        
    case 'reset_password':
        handlePasswordReset($input, $pdo);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

function handleLogin($data, $pdo) {
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $role = $data['role'] ?? 'owner';
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username and password required']);
        return;
    }
    
    try {
        // For demo purposes - in production, query from database
        $demoAccounts = [
            'owner_admin' => [
                'password_hash' => createPasswordHash('Eagles2026!'),
                'role' => 'owner',
                'email' => 'jeremiahmburu76@gmail.com'
            ],
            'secretary_entry' => [
                'password_hash' => createPasswordHash('Secret2026!'),
                'role' => 'secretary',
                'email' => 'secretary@example.com'
            ]
        ];
        
        if (isset($demoAccounts[$username])) {
            $account = $demoAccounts[$username];
            
            // In production, verify against database hash
            // For demo, we'll use the plain password check
            $demoPasswords = [
                'owner_admin' => 'Eagles2026!',
                'secretary_entry' => 'Secret2026!'
            ];
            
            if (isset($demoPasswords[$username]) && $demoPasswords[$username] === $password) {
                $sessionToken = bin2hex(random_bytes(32));
                
                // Store session in database (for production)
                // $stmt = $pdo->prepare("INSERT INTO user_sessions (username, session_token, expires_at) VALUES (?, ?, ?)");
                // $stmt->execute([$username, $sessionToken, date('Y-m-d H:i:s', strtotime('+1 hour'))]);
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => [
                        'session_token' => $sessionToken,
                        'username' => $username,
                        'role' => $account['role']
                    ]
                ]);
                return;
            }
        }
        
        echo json_encode(['success' => false, 'message' => 'Invalid credentials']);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Login error: ' . $e->getMessage()]);
    }
}

function handlePasswordReset($data, $pdo) {
    $email = $data['email'] ?? '';
    $role = $data['role'] ?? 'owner';
    $newPassword = $data['new_password'] ?? '';
    $resetCode = $data['reset_code'] ?? '';
    $token = $data['token'] ?? '';
    
    if (empty($email) || empty($newPassword) || empty($resetCode)) {
        echo json_encode(['success' => false, 'message' => 'Required fields missing']);
        return;
    }
    
    try {
        // Decode token for verification
        $tokenData = json_decode(base64_decode($token), true);
        
        // Verify token data matches
        if (!$tokenData || 
            $tokenData['email'] !== $email || 
            $tokenData['code'] !== $resetCode ||
            $tokenData['role'] !== $role) {
            echo json_encode(['success' => false, 'message' => 'Invalid reset token']);
            return;
        }
        
        // Check if token is expired (15 minutes)
        if ($tokenData['expiry'] < time() * 1000) {
            echo json_encode(['success' => false, 'message' => 'Reset token expired']);
            return;
        }
        
        // For demo purposes - update password in "database"
        // In production, update the actual database
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success' => false, 'message' => 'Invalid email format']);
            return;
        }
        
        // Validate password strength
        if (strlen($newPassword) < 8) {
            echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters']);
            return;
        }
        
        if (!preg_match('/[A-Z]/', $newPassword)) {
            echo json_encode(['success' => false, 'message' => 'Password must contain at least one uppercase letter']);
            return;
        }
        
        if (!preg_match('/\d/', $newPassword)) {
            echo json_encode(['success' => false, 'message' => 'Password must contain at least one number']);
            return;
        }
        
        if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $newPassword)) {
            echo json_encode(['success' => false, 'message' => 'Password must contain at least one special character']);
            return;
        }
        
        // In production, hash the password and update database
        // $hashedPassword = createPasswordHash($newPassword);
        // $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE email = ? AND role = ?");
        // $stmt->execute([$hashedPassword, $email, $role]);
        
        // For demo, store in session or file
        $resetData = [
            'email' => $email,
            'role' => $role,
            'password_updated' => time(),
            'status' => 'reset_completed'
        ];
        
        // Store in a file for demo (in production, use database)
        file_put_contents('password_resets.log', json_encode($resetData) . PHP_EOL, FILE_APPEND);
        
        echo json_encode([
            'success' => true,
            'message' => 'Password reset successfully',
            'data' => [
                'email' => $email,
                'role' => $role,
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Password reset error: ' . $e->getMessage()]);
    }
}
?>
