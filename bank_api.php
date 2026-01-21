<?php
// 1. Receive JSON data from the Bank API
$jsonResponse = file_get_contents('php://input');
$data = json_decode($jsonResponse, true);

// Extract raw values
$rawBillRef = strtoupper(trim($data['BillRefNumber'])); 
$amount = (float)$data['TransAmount'];
$paybill = $data['BusinessShortCode']; 

$houseIdentifier = "";

// 2. Identification Logic - STRICT SEPARATION
if ($paybill == "222111") {
    // --- FAMILY BANK ONLY ---
    // Look specifically for the # within the 200200 context
    if (strpos($rawBillRef, '#') !== false) {
        $parts = explode('#', $rawBillRef);
        $houseIdentifier = end($parts); // Grabs "A1" from "200200#A1"
    } else {
        // Fallback: Just strip the prefix if they forgot the #
        $houseIdentifier = str_replace("200200", "", $rawBillRef);
    }
} elseif ($paybill == "417185") {
    // --- CO-OPERATIVE BANK ONLY ---
    // No splitting needed. The reference IS the house number.
    $houseIdentifier = $rawBillRef; // Result: "A1"
}

// Final cleanup (remove accidental spaces)
$houseIdentifier = trim($houseIdentifier);

// 3. AUTOMATIC UTILITY DEDUCTION LOGIC
// At this point, $houseIdentifier is "A1" regardless of which bank it came from.
// The system now looks at what the Secretary keyed in for "A1".
?>
