<?php
session_start();
header('Content-Type: application/json');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// CORS - Allow from any origin for testing
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Simple error handling
error_reporting(0);

// Get request data
$input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

if (empty($input['action'])) {
    echo json_encode(['success' => false, 'message' => 'No action specified']);
    exit();
}

// Route actions
switch ($input['action']) {
    case 'login':
        handleLogin($input);
        break;
        
    case 'request_reset':
        // Just acknowledge the request since EmailJS handles email sending
        echo json_encode([
            'success' => true,
            'message' => 'Reset request received. Email will be sent via EmailJS.'
        ]);
        break;
        
    case 'update_password_with_email':
        handleUpdatePasswordWithEmail($input);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

// ==================== FUNCTIONS ====================

function handleLogin($data) {
    // Simple demo login - in production, use database
    if (isset($data['username']) && isset($data['password']) && isset($data['role'])) {
        
        // Demo credentials
        if ($data['role'] === 'owner' && 
            $data['username'] === 'owner_admin' && 
            $data['password'] === 'Eagles2026!') {
            
            $_SESSION['user_id'] = 1;
            $_SESSION['username'] = 'owner_admin';
            $_SESSION['role'] = 'owner';
            $_SESSION['email'] = 'jeremiahmburu76@gmail.com';
            $_SESSION['session_token'] = bin2hex(random_bytes(16));
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'data' => [
                    'user_id' => 1,
                    'username' => 'owner_admin',
                    'role' => 'owner',
                    'email' => 'jeremiahmburu76@gmail.com',
                    'session_token' => $_SESSION['session_token']
                ]
            ]);
            return;
            
        } else if ($data['role'] === 'secretary' && 
                   $data['username'] === 'secretary_entry' && 
                   $data['password'] === 'Secret2026!') {
            
            $_SESSION['user_id'] = 2;
            $_SESSION['username'] = 'secretary_entry';
            $_SESSION['role'] = 'secretary';
            $_SESSION['email'] = 'jeremiahmburu76@gmail.com';
            $_SESSION['session_token'] = bin2hex(random_bytes(16));
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'data' => [
                    'user_id' => 2,
                    'username' => 'secretary_entry',
                    'role' => 'secretary',
                    'email' => 'jeremiahmburu76@gmail.com',
                    'session_token' => $_SESSION['session_token']
                ]
            ]);
            return;
        }
    }
    
    echo json_encode([
        'success' => false,
        'message' => 'Invalid credentials'
    ]);
}

function handleUpdatePasswordWithEmail($data) {
    // This is a demo function - in production, update database
    
    if (empty($data['email']) || empty($data['new_password']) || empty($data['role'])) {
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    // Simulate password update
    sleep(1); // Simulate processing time
    
    echo json_encode([
        'success' => true,
        'message' => 'Password updated successfully. You can now login with your new password.'
    ]);
}

?>
