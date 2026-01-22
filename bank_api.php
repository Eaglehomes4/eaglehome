<?php
// ============================================
// CONFIGURATION & CONSTANTS
// ============================================
define('FAMILY_BANK_PAYBILL', '222111');
define('FAMILY_BANK_ACCOUNT', '045000037386');
define('COOP_BANK_PAYBILL', '417185');
define('COOP_BANK_ACCOUNT', '01192156596100');
define('RENT_AMOUNT', 15000);

// ============================================
// 1. PAYMENT IDENTIFICATION & SANITIZATION
// ============================================
function identifyPayment($data) {
    $paybill = $data['BusinessShortCode'] ?? '';
    $destAcc = $data['DestinationAccount'] ?? '';
    $rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
    $amount = (float)($data['TransAmount'] ?? 0);
    
    $houseIdentifier = "";
    $paymentMethod = "";
    
    if ($paybill == FAMILY_BANK_PAYBILL || $destAcc == FAMILY_BANK_ACCOUNT) {
        $paymentMethod = "Family Bank";
        $houseIdentifier = extractHouseIdentifier($rawBillRef, 'family');
    } 
    elseif ($paybill == COOP_BANK_PAYBILL || $destAcc == COOP_BANK_ACCOUNT) {
        $paymentMethod = "Co-op Bank";
        $houseIdentifier = $rawBillRef; 
    } 
    elseif (isset($data['manual_type']) && $data['manual_type'] == "PAYSLIP") {
        $paymentMethod = "Payslip";
        $houseIdentifier = $data['selected_house'] ?? '';
    }
    
    // SANITIZATION: Remove symbols, dots, or spaces from House ID (e.g., "A.1" becomes "A1")
    $cleanHouseId = preg_replace('/[^A-Z0-9]/', '', strtoupper($houseIdentifier));
    
    return [
        'house_identifier' => $cleanHouseId,
        'payment_method' => $paymentMethod,
        'amount' => $amount,
        'reference' => $rawBillRef
    ];
}

function extractHouseIdentifier($reference, $bankType) {
    if ($bankType === 'family') {
        if (strpos($reference, '#') !== false) {
            $parts = explode('#', $reference);
            return end($parts);
        }
        return str_replace("200200", "", $reference);
    }
    return $reference;
}

// ============================================
// 2. WATERFALL DEDUCTION ENGINE
// ============================================
function processWaterfallDeductions($houseId, $amount, $pdo) {
    $remainingCash = $amount;
    $deductionsMade = [];
    
    // A. Deduct unpaid utility bills (Using the priority keyed by Secretary)
    $stmt = $pdo->prepare("SELECT * FROM utility_bills 
                          WHERE house_id = ? AND status = 'unpaid' 
                          ORDER BY priority ASC, id ASC");
    $stmt->execute([$houseId]);
    $unpaidBills = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($unpaidBills as $bill) {
        if ($remainingCash >= $bill['amount']) {
            $remainingCash -= $bill['amount'];
            $deductionsMade[$bill['bill_type']] = $bill['amount'];
            
            $update = $pdo->prepare("UPDATE utility_bills SET status = 'paid', date_paid = NOW() WHERE id = ?");
            $update->execute([$bill['id']]);
        } else {
            // Amount insufficient for next priority bill - Stop waterfall
            break;
        }
    }
    
    // B. Apply to Rent
    $rentDue = getRentDue($houseId, $pdo);
    if ($remainingCash >= $rentDue) {
        $remainingCash -= $rentDue;
        $deductionsMade['rent'] = $rentDue;
        markRentAsPaid($houseId, $pdo);
    } elseif ($remainingCash > 0) {
        $deductionsMade['rent_partial'] = $remainingCash;
        // Logic to update a partial_rent_balance table could go here
        $remainingCash = 0; 
    }
    
    // C. CREDIT BALANCE FOR THE NEXT MONTH
    if ($remainingCash > 0) {
        creditTenantBalance($houseId, $remainingCash, $pdo);
    }
    
    return [
        'deductions' => $deductionsMade,
        'remaining_balance' => $remainingCash
    ];
}

// ============================================
// 3. MAIN PAYMENT PROCESSING (With Transactions)
// ============================================
function processPayment($data, $pdo) {
    $paymentInfo = identifyPayment($data);
    
    // START TRANSACTION: If anything fails, nothing is saved.
    $pdo->beginTransaction();

    try {
        if (empty($paymentInfo['house_identifier'])) {
            $stmt = $pdo->prepare("INSERT INTO payments 
                                  (amount, method, reference, house_id, status, created_at) 
                                  VALUES (?, ?, ?, 'UNKNOWN', 'Unidentified', NOW())");
            $stmt->execute([
                $paymentInfo['amount'],
                $paymentInfo['payment_method'],
                $paymentInfo['reference']
            ]);
            $pdo->commit();
            return ['status' => 'unidentified', 'message' => 'Payment moved to Suspense Account'];
        }
        
        $result = processWaterfallDeductions($paymentInfo['house_identifier'], $paymentInfo['amount'], $pdo);
        
        $stmt = $pdo->prepare("INSERT INTO payments 
                              (house_id, amount, method, reference, deductions_json, status, created_at) 
                              VALUES (?, ?, ?, ?, ?, 'Processed', NOW())");
        $stmt->execute([
            $paymentInfo['house_identifier'],
            $paymentInfo['amount'],
            $paymentInfo['payment_method'],
            $paymentInfo['reference'],
            json_encode($result['deductions'])
        ]);
        
        $pdo->commit(); // Save everything
        return [
            'status' => 'processed',
            'house_id' => $paymentInfo['house_identifier'],
            'deductions' => $result['deductions'],
            'carried_forward' => $result['remaining_balance']
        ];

    } catch (Exception $e) {
        $pdo->rollBack(); // Undo everything if there's an error
        throw $e;
    }
}

// ============================================
// HELPER FUNCTIONS
// ============================================
function getRentDue($houseId, $pdo) {
    $stmt = $pdo->prepare("SELECT monthly_rent FROM houses WHERE id = ?");
    $stmt->execute([$houseId]);
    $house = $stmt->fetch(PDO::FETCH_ASSOC);
    return $house['monthly_rent'] ?? RENT_AMOUNT;
}

function markRentAsPaid($houseId, $pdo) {
    // Logic to mark the specific month's rent ledger as cleared
    $stmt = $pdo->prepare("UPDATE rent_ledger SET status = 'paid' WHERE house_id = ? AND month = MONTH(NOW()) AND year = YEAR(NOW())");
    $stmt->execute([$houseId]);
}

function creditTenantBalance($houseId, $amount, $pdo) {
    $stmt = $pdo->prepare("INSERT INTO tenant_credits (house_id, balance, updated_at) 
                          VALUES (?, ?, NOW()) 
                          ON DUPLICATE KEY UPDATE 
                          balance = balance + ?, updated_at = NOW()");
    $stmt->execute([$houseId, $amount, $amount]);
}

// ============================================
// EXECUTION POINT
// ============================================
try {
    $jsonResponse = file_get_contents('php://input');
    $data = json_decode($jsonResponse, true);
    
    // DB Credentials - Change to your actual details
    $pdo = new PDO('mysql:host=localhost;dbname=rental_db;charset=utf8', 'root', '');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $result = processPayment($data, $pdo);
    
    header('Content-Type: application/json');
    echo json_encode($result);
    
} catch (Exception $e) {
    header('Content-Type: application/json');
    http_response_code(500);
    echo json_encode(['error' => 'Critical System Error: ' . $e->getMessage()]);
}
?>
