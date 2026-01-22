<?php
// 1. RECEIVE DATA
$jsonResponse = file_get_contents('php://input');
$data = json_decode($jsonResponse, true);

$paybill = $data['BusinessShortCode'] ?? '';
$destAcc = $data['DestinationAccount'] ?? ''; // For direct deposits
$rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
$amount = (float)($data['TransAmount'] ?? 0);

$houseIdentifier = "";
$paymentMethod = "";

// 2. IDENTIFICATION LOGIC (The 4 Paths)
if ($paybill == "222111" || $destAcc == "045000037386") {
    $paymentMethod = "Family Bank";
    $houseIdentifier = (strpos($rawBillRef, '#') !== false) 
        ? end(explode('#', $rawBillRef)) 
        : str_replace("200200", "", $rawBillRef);
} 
elseif ($paybill == "417185" || $destAcc == "01192156596100") {
    $paymentMethod = "Co-op Bank";
    $houseIdentifier = $rawBillRef; // Direct House No.
} 
elseif (isset($data['manual_type']) && $data['manual_type'] == "PAYSLIP") {
    $paymentMethod = "Payslip";
    $houseIdentifier = $data['selected_house']; // From Secretary's selection
}

$houseIdentifier = trim($houseIdentifier);

// 3. AUTOMATIC WATERFALL DEDUCTION
if (!empty($houseIdentifier)) {
    // A. Fetch unpaid utilities entered by Secretary (Water, Garbage, etc.)
    // Ordered by your priority preference
    $unpaidBills = $db->query("SELECT * FROM bills WHERE house_id = ? AND status = 'unpaid' ORDER BY priority ASC", [$houseIdentifier]);

    $deductions = [];
    
    foreach ($unpaidBills as $bill) {
        if ($amount >= $bill['amount']) {
            $amount -= $bill['amount'];
            $deductions[$bill['type']] = $bill['amount'];
            // Update DB: Mark bill as PAID
        } else {
            // Partial payment logic if needed
            break; 
        }
    }

    // B. Apply remaining amount to Rent
    $currentRentDue = 15000; // Example monthly rent
    if ($amount >= $currentRentDue) {
        $amount -= $currentRentDue;
        // Mark Rent as PAID
    } else {
        // Partial Rent payment
        $amount = 0;
    }

    // C. FOR THE NEXT MONTH (Credit Balance)
    if ($amount > 0) {
        // Save $amount to a 'tenant_credits' table
        // This will be used automatically in the next billing cycle
    }
}
?>
    // In bank_api.php, after the identification logic:
if (empty($houseIdentifier)) {
    // 1. Tag it as "MISSING_HOUSE"
    // 2. Save it to the payments table with house_id = 'UNKNOWN'
    $db->execute("INSERT INTO payments (amount, method, reference, status) 
                  VALUES (?, ?, ?, 'Unidentified')", [$amount, $paymentMethod, $rawBillRef]);
}
