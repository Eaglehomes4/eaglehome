<?php
// Connect to your database
$conn = new mysqli("localhost", "username", "password", "eagles_home");

// Query to sum all immutable bank payments for the current month
$sql = "SELECT SUM(amount) as total FROM payments WHERE MONTH(payment_date) = MONTH(CURRENT_DATE())";
$result = $conn->query($sql);
$row = $result->fetch_assoc();

// Send the result back to the dashboard in a format it understands (JSON)
echo json_encode(['total_collected' => $row['total'] ?? 0]);

$conn->close();
?>
