<?php
header('Content-Type: application/json');
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

// Database credentials
$host = "localhost";
$db_user = "root";
$db_pass = ""; // Set your actual password
$db_name = "eagles_home";

$conn = new mysqli($host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    echo json_encode(['error' => 'Database connection failed']);
    exit();
}

// Query to sum all immutable bank payments for the current month
$sql = "SELECT SUM(amount) as total FROM payments WHERE MONTH(payment_date) = MONTH(CURRENT_DATE()) AND YEAR(payment_date) = YEAR(CURRENT_DATE())";
$result = $conn->query($sql);

if ($result) {
    $row = $result->fetch_assoc();
    $total = $row['total'] ?? 0;
    echo json_encode(['total_collected' => $total, 'currency' => 'KES']);
} else {
    echo json_encode(['error' => 'Query failed']);
}

$conn->close();
?>
