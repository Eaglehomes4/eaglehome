<?php
// ============================================
// CONFIGURATION & CONSTANTS
// ============================================
define('FAMILY_BANK_PAYBILL', '222111');
define('FAMILY_BANK_ACCOUNT', '045000037386');
define('COOP_BANK_PAYBILL', '417185');
define('COOP_BANK_ACCOUNT', '01192156596100');
define('DEFAULT_RENT_AMOUNT', 15000);

/**
 * 1. SMART IDENTIFICATION
 * Detects which of the 4 paths the money came from.
 */
function identifyPaymentSource($data) {
    $paybill = $data['BusinessShortCode'] ?? '';
    $destAcc = $data['DestinationAccount'] ?? '';
    $rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
    $amount = (float)($data['TransAmount'] ?? 0);
    
    $houseId = "";
    $method = "M-Pesa"; // Default path

    // PATH 1: Family Bank
    if ($paybill == FAMILY_BANK_PAYBILL || $destAcc == FAMILY_BANK_ACCOUNT) {
        $method = "Family Bank";
        // Logic: Extract house after '#' or strip the 200200 prefix
        if (strpos($rawBillRef, '#') !== false) {
            $parts = explode('#', $rawBillRef);
            $houseId = end($parts);
        } else {
            $houseId = str_replace("200200", "", $rawBillRef);
        }
    } 
    // PATH 2: Co-op Bank
    elseif ($paybill == COOP_BANK_PAYBILL || $destAcc == COOP_BANK_ACCOUNT) {
        $method = "Co-op Bank";
        $houseId = $rawBillRef; 
    } 
    // PATH 3: Payslip (Manual Entry)
    elseif (isset($data['isPayslip']) && $data['isPayslip'] == true) {
        $method = "Payslip";
        $houseId = $data['BillRefNumber'] ?? '';
    }
    // PATH 4: Standard M-Pesa (Fallback)
    else {
        $houseId = $rawBillRef;
    }
    
    return [
        'house_id' => strtoupper(trim($houseId)),
        'method'   => $method,
        'amount'   => $amount,
        'ref'      => $data['TransID'] ?? 'REF'.time()
    ];
}

/**
 * 2. THE WATERFALL ENGINE
 * Automatically deducts: Utilities -> Rent -> Credits
 */
function runWaterfall($houseId, $amount, $pdo) {
    $remaining = $amount;
    $breakdown = [];
    
    // A. UTILITIES (Water, Garbage, Electricity)
    $stmt = $pdo->prepare("SELECT * FROM utility_bills WHERE house_id = ? AND status = 'unpaid' ORDER BY priority ASC");
    $stmt->execute([$houseId]);
    
    while ($bill = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if ($remaining <= 0) break;
        
        $paymentForBill = min($remaining, (float)$bill['amount']);
        $remaining -= $paymentForBill;
        $breakdown[$bill['bill_type']] = $paymentForBill;
        
        if ($paymentForBill >= (float)$bill['amount']) {
            $pdo->prepare("UPDATE utility_bills SET status = 'paid' WHERE id = ?")->execute([$bill['id']]);
        } else {
            $pdo->prepare("UPDATE utility_bills SET amount = amount - ? WHERE id = ?")->execute([$paymentForBill, $bill['id']]);
        }
    }
    
    // B. RENT
    if ($remaining > 0) {
        $stmt = $pdo->prepare("SELECT monthly_rent FROM houses WHERE id = ?");
        $stmt->execute([$houseId]);
        $house = $stmt->fetch();
        $rentDue = $house['monthly_rent'] ?? DEFAULT_RENT_AMOUNT;

        $paymentForRent = min($remaining, (float)$rentDue);
        $remaining -= $paymentForRent;
        $breakdown['rent'] = $paymentForRent;
    }
    
    // C. OVERPAYMENT (Credit for next month)
    if ($remaining > 0) {
        $breakdown['credit_applied'] = $remaining;
        $pdo->prepare("INSERT INTO tenant_credits (house_id, balance) VALUES (?, ?) 
                       ON DUPLICATE KEY UPDATE balance = balance + ?")
            ->execute([$houseId, $remaining, $remaining]);
        $remaining = 0;
    }
    
    return $breakdown;
}

// ============================================
// 3. EXECUTION
// ============================================
try {
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    
    $pdo = new PDO('mysql:host=localhost;dbname=rental_db', 'root', '');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $payment = identifyPaymentSource($data);
    $houseId = $payment['house_id'];
    
    $pdo->beginTransaction();

    // Check if House exists
    $stmt = $pdo->prepare("SELECT id FROM houses WHERE id = ?");
    $stmt->execute([$houseId]);
    $exists = $stmt->fetch();

    if (!$exists) {
        // Record as Suspense (Unidentified)
        $stmt = $pdo->prepare("INSERT INTO payments (amount, method, reference, house_id, status) VALUES (?, ?, ?, 'UNKNOWN', 'Unidentified')");
        $stmt->execute([$payment['amount'], $payment['method'], $payment['ref']]);
    } else {
        // Run Waterfall and Record
        $deductions = runWaterfall($houseId, $payment['amount'], $pdo);
        $stmt = $pdo->prepare("INSERT INTO payments (house_id, amount, method, reference, deductions_json, status) VALUES (?, ?, ?, ?, ?, 'Processed')");
        $stmt->execute([
            $houseId, 
            $payment['amount'], 
            $payment['method'], 
            $payment['ref'], 
            json_encode($deductions)
        ]);
    }

    $pdo->commit();
    echo json_encode(['status' => 'success']);

} catch (Exception $e) {
    if (isset($pdo)) $pdo->rollBack();
    header('Content-Type: application/json', true, 500);
    echo json_encode(['error' => $e->getMessage()]);
}
