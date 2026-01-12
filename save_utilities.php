<?php
// Connect to your database
$conn = new mysqli("localhost", "username", "password", "eagle_homes");

// Get data from the Secretary's form
$house_id = $_POST['house_id'];
$water = $_POST['water'] ?? 0;
$electricity = $_POST['electricity'] ?? 0;
$garbage = 200; // Fixed rate as per your rules

// 1. Save the readings for this month
$sql = "INSERT INTO utility_bills (house_id, water, electricity, garbage, billing_month) 
        VALUES ('$house_id', '$water', '$electricity', '$garbage', NOW())";
$conn->query($sql);

// 2. Logic: Recalculate Balance
// Balance = (Rent + Utilities) - Total Immutable Payments
$result = $conn->query("SELECT monthly_rent FROM houses WHERE id = '$house_id'");
$house = $result->fetch_assoc();

$paymentResult = $conn->query("SELECT SUM(amount) as paid FROM payments WHERE house_id = '$house_id'");
$payment = $paymentResult->fetch_assoc();

$total_due = $house['monthly_rent'] + $water + $electricity + $garbage;
$final_balance = $total_due - ($payment['paid'] ?? 0);

// 3. Update the House Status Badge
$status = ($final_balance <= 0) ? 'Paid' : 'Arrears';
if ($final_balance < 0) $status = 'Credit';

$conn->query("UPDATE houses SET status = '$status' WHERE id = '$house_id'");

echo json_encode(['success' => true, 'new_status' => $status]);
$conn->close();
?>
