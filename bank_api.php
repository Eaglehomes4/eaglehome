<?php
// bank_api.php - The "Brain"
define('FAMILY_BANK_PAYBILL', '222111');
define('FAMILY_BANK_ACCOUNT', '045000037386');
define('COOP_BANK_PAYBILL', '417185');
define('COOP_BANK_ACCOUNT', '01192156596100');

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

// 1. RECEIVE DATA
$jsonResponse = file_get_contents('php://input');
file_put_contents('bank_debug.log', "[" . date('Y-m-d H:i:s') . "] Data: " . $jsonResponse . PHP_EOL, FILE_APPEND);
$data = json_decode($jsonResponse, true);

if ($data) {
    try {
        $pdo = new PDO('mysql:host=localhost;dbname=rental_db;charset=utf8', 'root', '');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->beginTransaction();

        // 2. IDENTIFY
        $paybill = $data['BusinessShortCode'] ?? '';
        $destAcc = $data['DestinationAccount'] ?? '';
        $rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
        $amount = (float)($data['TransAmount'] ?? 0);
        $transactionId = $data['TransID'] ?? 'TXN_'.time();
        
        $houseId = ($paybill == FAMILY_BANK_PAYBILL || $destAcc == FAMILY_BANK_ACCOUNT) 
                   ? extractHouseIdentifier($rawBillRef, 'family') 
                   : $rawBillRef;
        $houseId = trim(strtoupper($houseId));

        // 3. CHECK HOUSE & PROCESS WATERFALL
        $check = $pdo->prepare("SELECT id FROM houses WHERE id = ?");
        $check->execute([$houseId]);
        
        $deductions = [];
        $status = 'Unidentified';

        if ($check->fetch() && !empty($houseId)) {
            $status = 'Processed';
            $remaining = $amount;

            // Waterfall: Water -> Garbage -> Electricity -> Rent
            $stmt = $pdo->prepare("SELECT * FROM utility_bills WHERE house_id = ? AND status = 'unpaid' ORDER BY priority ASC");
            $stmt->execute([$houseId]);
            while ($bill = $stmt->fetch(PDO::FETCH_ASSOC)) {
                if ($remaining >= $bill['amount']) {
                    $remaining -= $bill['amount'];
                    $deductions[$bill['bill_type']] = $bill['amount'];
                    $pdo->prepare("UPDATE utility_bills SET status='paid', date_paid=NOW() WHERE id=?")->execute([$bill['id']]);
                }
            }
            if ($remaining > 0) {
                $deductions['rent'] = $remaining;
            }
        }

        // 4. SAVE TO DATABASE
        $stmt = $pdo->prepare("INSERT INTO payments (house_id, amount, reference, phone, bill_ref, deductions_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
        $stmt->execute([
            $houseId ?: 'UNKNOWN', 
            $amount, 
            $transactionId, 
            $data['MSISDN'] ?? '', 
            $rawBillRef, 
            json_encode($deductions), 
            $status
        ]);

        $pdo->commit();
        echo json_encode(['status' => 'success']);

    } catch (Exception $e) {
        if(isset($pdo)) $pdo->rollBack();
        file_put_contents('bank_debug.log', "ERROR: " . $e->getMessage() . PHP_EOL, FILE_APPEND);
    }
}
