<?php
header('Content-Type: application/json');
session_start();

// Check if user is logged in and is secretary
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'secretary') {
    echo json_encode(['success' => false, 'error' => 'Unauthorized access']);
    exit();
}

// Database credentials
$host = "localhost";
$db_user = "root";
$db_pass = ""; // Set your actual password
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    echo json_encode(['success' => false, 'error' => 'Database connection failed']);
    exit();
}

// Get data from the Secretary's form
$house_id = $_POST['house_id'] ?? '';
$water = floatval($_POST['water'] ?? 0);
$electricity = floatval($_POST['electricity'] ?? 0);
$garbage = 200; // Fixed rate as per your rules

if (empty($house_id)) {
    echo json_encode(['success' => false, 'error' => 'House ID is required']);
    exit();
}

// Start transaction
$conn->begin_transaction();

try {
    // 1. Save the readings for this month
    $sql = "INSERT INTO utility_bills (house_id, water, electricity, garbage, billing_month, created_at) 
            VALUES (?, ?, ?, ?, NOW(), NOW())";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sddd", $house_id, $water, $electricity, $garbage);
    $stmt->execute();
    
    // 2. Get house rent
    $sql = "SELECT monthly_rent FROM houses WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $house_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception('House not found');
    }
    
    $house = $result->fetch_assoc();
    $monthly_rent = floatval($house['monthly_rent']);
    
    // 3. Get total payments for this house
    $sql = "SELECT SUM(amount) as paid FROM payments WHERE house_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $house_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $payment = $result->fetch_assoc();
    $total_paid = floatval($payment['paid'] ?? 0);
    
    // 4. Calculate balance
    $total_due = $monthly_rent + $water + $electricity + $garbage;
    $final_balance = $total_due - $total_paid;
    
    // 5. Determine status
    if (abs($final_balance) < 0.01) {
        $status = 'Paid';
    } elseif ($final_balance < 0) {
        $status = 'Credit';
    } else {
        $status = 'Arrears';
    }
    
    // 6. Update the House Status
    $sql = "UPDATE houses SET status = ?, balance = ?, last_updated = NOW() WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sds", $status, $final_balance, $house_id);
    $stmt->execute();
    
    // Commit transaction
    $conn->commit();
    
    echo json_encode([
        'success' => true, 
        'new_status' => $status,
        'balance' => $final_balance,
        'total_due' => $total_due,
        'total_paid' => $total_paid
    ]);
    
} catch (Exception $e) {
    // Rollback transaction on error
    $conn->rollback();
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

$stmt->close();
$conn->close();
?>
