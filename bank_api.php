<?php
// 1. Receive JSON data from the Bank API
$jsonResponse = file_get_contents('php://input');
$data = json_decode($jsonResponse, true);

// Extract raw values
$rawBillRef = strtoupper(trim($data['BillRefNumber'])); // e.g., "200200-A1" or "JH-01"
$amount = (float)$data['TransAmount'];
$transId = $data['TransID'];
$paybill = $data['BusinessShortCode']; // The Paybill number used

$houseIdentifier = "";

// 2. Identification Logic based on the Paybill
if ($paybill == "222111") {
    // FAMILY BANK: Remove the "200200-" prefix to get just the House Number
    // If the input is "200200-A1", it captures everything after the hyphen
    if (strpos($rawBillRef, '-') !== false) {
        $parts = explode('-', $rawBillRef);
        $houseIdentifier = end($parts); // Result: "A1"
    } else {
        // Fallback if they forgot the hyphen but typed the house number after 200200
        $houseIdentifier = str_replace("200200", "", $rawBillRef);
    }
} elseif ($paybill == "417185") {
    // CO-OPERATIVE BANK: The BillRef is already the House Number
    $houseIdentifier = $rawBillRef; // Result: "JH-01"
}

// Clean up any extra spaces
$houseIdentifier = trim($houseIdentifier);

// 3. DATABASE OPERATIONS (Conceptual)
// A. Check if $houseIdentifier exists in the 'houses' table
// B. If it exists, find the total debt (Rent + Water + Garbage + Penalties)
// C. Insert the payment into 'payments' table (Immutable)
// D. Update house balance: New Balance = Old Balance - $amount

echo json_encode(["ResultCode" => 0, "ResultDesc" => "Success"]);
?>
