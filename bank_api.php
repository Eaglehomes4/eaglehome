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
// 1. PAYMENT IDENTIFICATION & LOGGING
// ============================================
function identifyPayment($data) {
    $paybill = $data['BusinessShortCode'] ?? '';
    $destAcc = $data['DestinationAccount'] ?? '';
    $rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
    $amount = (float)($data['TransAmount'] ?? 0);
    $phoneNumber = $data['MSISDN'] ?? ''; // Added to capture phone
    $transactionId = $data['TransID'] ?? 'TXN_'.time(); 
    
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
    
    // SMART SANITIZATION: 
    // We trim spaces but keep hyphens/dots in case your DB uses "EH-01"
    $cleanHouseId = trim(strtoupper($houseIdentifier));
    
    return [
        'house_identifier' => $cleanHouseId,
        'payment_method' => $paymentMethod,
        'amount' => $amount,
        'reference' => $transactionId, // Using M-Pesa TransID as reference
        'bill_ref' => $rawBillRef,      // What the user actually typed
        'phone' => $phoneNumber
    ];
}

function extractHouseIdentifier($reference, $bankType) {
    if ($bankType === 'family') {
        // If user typed 200200#EH01, extract EH01
        if (strpos($reference, '#') !== false) {
            $parts = explode('#', $reference);
            return end($parts);
        }
        // If user just typed 200200EH01, remove the prefix
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
    
    // A. Deduct unpaid utility bills
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
            break;
        }
    }
    
    // B. Apply to Rent
    $rentDue = getRentDue($houseId, $pdo);
    if ($remainingCash >= $rentDue && $rentDue > 0) {
        $remainingCash -= $rentDue;
        $deductionsMade['rent'] = $rentDue;
        markRentAsPaid($houseId, $pdo);
    } elseif ($remainingCash > 0) {
        $deductionsMade['rent_partial'] = $remainingCash;
        $remainingCash = 0; 
    }
    
    // C. CREDIT BALANCE
    if ($remainingCash > 0) {
        creditTenantBalance($houseId, $remainingCash, $pdo);
    }
    
    return [
        'deductions' => $deductionsMade,
        'remaining_balance' => $remainingCash
    ];
}

// ============================================
// 3. MAIN PROCESSING
// ============================================
function processPayment($data, $pdo) {
    $paymentInfo = identifyPayment($data);
    $pdo->beginTransaction();

    try {
        // Check if House exists in your system
        $checkHouse = $pdo->prepare("SELECT id FROM houses WHERE id = ?");
        $checkHouse->execute([$paymentInfo['house_identifier']]);
        $houseExists = $checkHouse->fetch();

        if (!$houseExists || empty($paymentInfo['house_identifier'])) {
            $stmt = $pdo->prepare("INSERT INTO payments 
                                  (amount, method, reference, bill_ref, phone, house_id, status, created_at) 
                                  VALUES (?, ?, ?, ?, ?, 'UNKNOWN', 'Unidentified', NOW())");
            $stmt->execute([
                $paymentInfo['amount'],
                $paymentInfo['payment_method'],
                $paymentInfo['reference'],
                $paymentInfo['bill_ref'],
                $paymentInfo['phone']
            ]);
            $pdo->commit();
            return ['status' => 'unidentified', 'message' => 'Payment moved to Suspense'];
        }
        
        $result = processWaterfallDeductions($paymentInfo['house_identifier'], $paymentInfo['amount'], $pdo);
        
        $stmt = $pdo->prepare("INSERT INTO payments 
                              (house_id, amount, method, reference, bill_ref, phone, deductions_json, status, created_at) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, 'Processed', NOW())");
        $stmt->execute([
            $paymentInfo['house_identifier'],
            $paymentInfo['amount'],
            $paymentInfo['payment_method'],
            $paymentInfo['reference'],
            $paymentInfo['bill_ref'],
            $paymentInfo['phone'],
            json_encode($result['deductions'])
        ]);
        
        $pdo->commit();
        return ['status' => 'processed', 'house_id' => $paymentInfo['house_identifier']];

    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

// ============================================
// EXECUTION & DEBUGGING
// ============================================
try {
    $jsonResponse = file_get_contents('php://input');
    
    // CRITICAL: Log every hit to a file so we can see why it failed
    file_put_contents('bank_debug.log', "[" . date('Y-m-d H:i:s') . "] Data: " . $jsonResponse . PHP_EOL, FILE_APPEND);

    $data = json_decode($jsonResponse, true);
    if (!$data) {
        throw new Exception("Invalid JSON received");
    }

    $pdo = new PDO('mysql:host=localhost;dbname=rental_db;charset=utf8', 'root', '');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $result = processPayment($data, $pdo);
    
    header('Content-Type: application/json');
    echo json_encode($result);
    
} catch (Exception $e) {
    file_put_contents('bank_debug.log', "[" . date('Y-m-d H:i:s') . "] ERROR: " . $e->getMessage() . PHP_EOL, FILE_APPEND);
    header('Content-Type: application/json');
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

// Helper functions (getRentDue, markRentAsPaid, creditTenantBalance) remain same as your previous version.
?>
