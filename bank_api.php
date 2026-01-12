<?php
// Receive data from Bank API
$jsonResponse = file_get_contents('php://input');
$data = json_decode($jsonResponse, true);

$billRef = $data['BillRefNumber']; // e.g., "JH-01"
$amount = $data['TransAmount'];
$receipt = $data['TransID'];

// 1. Find the house in the database matching the BillRef
// 2. Insert the payment into the 'payments' table (Immutable)
// 3. Update the house status to 'Paid' or 'Credit'

echo json_encode(["ResultCode" => 0, "ResultDesc" => "Success"]);
?>
