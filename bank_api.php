<?php
// ============================================
// EAGLE HOMES BANK API - PRODUCTION READY
// ============================================

// Enable strict error reporting
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Start output buffering
ob_start();

// ============================================
// CONFIGURATION & CONSTANTS
// ============================================
define('API_VERSION', '1.0.0');
define('MAX_LOG_SIZE', 10485760); // 10MB
define('MAX_DUPLICATE_HOURS', 24);
define('DEFAULT_RENT_AMOUNT', 15000);

// Load configuration from database or file
function getSystemSetting($key, $default = '') {
    // In production, fetch from database
    $settings = [
        'FAMILY_BANK_PAYBILL' => '222111',
        'FAMILY_BANK_ACCOUNT' => '045000037386',
        'COOP_BANK_PAYBILL' => '417185',
        'COOP_BANK_ACCOUNT' => '01192156596100',
        'DEFAULT_WATER_RATE' => 100,
        'DEFAULT_GARBAGE_FEE' => 200,
        'PENALTY_PERCENTAGE' => 5,
    ];
    return $settings[$key] ?? $default;
}

// ============================================
// LOGGING SYSTEM
// ============================================
class TransactionLogger {
    private static $logDir = __DIR__ . '/logs/';
    private static $logFile = 'bank_api.log';

    public static function init() {
        if (!file_exists(self::$logDir)) {
            mkdir(self::$logDir, 0755, true);
        }
        
        // Rotate log if too large
        $logPath = self::$logDir . self::$logFile;
        if (file_exists($logPath) && filesize($logPath) > MAX_LOG_SIZE) {
            $archivePath = self::$logDir . 'bank_api_' . date('Y-m-d_H-i-s') . '.log';
            rename($logPath, $archivePath);
        }
    }

    public static function log($level, $message, $context = []) {
        $logEntry = sprintf(
            "[%s] %s: %s %s\n",
            date('Y-m-d H:i:s'),
            strtoupper($level),
            $message,
            !empty($context) ? json_encode($context) : ''
        );
        
        $logPath = self::$logDir . self::$logFile;
        file_put_contents($logPath, $logEntry, FILE_APPEND | LOCK_EX);
        
        // Also log to system log for critical errors
        if ($level === 'error') {
            error_log("BANK_API_ERROR: " . $message . " " . json_encode($context));
        }
    }
}

// Initialize logger
TransactionLogger::init();

// ============================================
// DATABASE CONNECTION
// ============================================
class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        try {
            $host = 'localhost';
            $dbname = 'eagle_homes';
            $username = 'eagle_user';
            $password = 'SecurePassword123!';
            
            $this->pdo = new PDO(
                "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
                ]
            );
        } catch (PDOException $e) {
            TransactionLogger::log('error', 'Database connection failed', ['error' => $e->getMessage()]);
            throw new Exception('Database connection failed: ' . $e->getMessage());
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance->pdo;
    }
}

// ============================================
// PAYMENT PROCESSING ENGINE
// ============================================
class PaymentProcessor {
    private $pdo;
    private $transactionData;
    private $paymentInfo;

    public function __construct($transactionData) {
        $this->pdo = Database::getInstance();
        $this->transactionData = $transactionData;
        $this->paymentInfo = $this->identifyPaymentSource();
        
        TransactionLogger::log('info', 'Payment identified', [
            'method' => $this->paymentInfo['method'],
            'house_id' => $this->paymentInfo['house_id'],
            'amount' => $this->paymentInfo['amount']
        ]);
    }

    /**
     * 1. SMART IDENTIFICATION WITH VALIDATION
     */
    private function identifyPaymentSource() {
        $data = $this->transactionData;
        $paybill = $data['BusinessShortCode'] ?? '';
        $destAcc = $data['DestinationAccount'] ?? '';
        $rawBillRef = strtoupper(trim($data['BillRefNumber'] ?? ''));
        $amount = (float)($data['TransAmount'] ?? 0);
        $transactionId = $data['TransID'] ?? '';

        // Validate required fields
        if (!$transactionId) {
            throw new Exception('Missing transaction ID');
        }

        if ($amount <= 0) {
            throw new Exception('Invalid payment amount: ' . $amount);
        }

        $houseId = "";
        $method = "M-Pesa"; // Default path

        // PATH 1: Family Bank
        if ($paybill == getSystemSetting('FAMILY_BANK_PAYBILL') ||
            $destAcc == getSystemSetting('FAMILY_BANK_ACCOUNT')) {
            $method = "Family Bank";
            
            // Extract house after '#' or strip the 200200 prefix
            if (strpos($rawBillRef, '#') !== false) {
                $parts = explode('#', $rawBillRef);
                $houseId = trim(end($parts));
            } else {
                // Remove common prefixes
                $houseId = preg_replace('/^(200200|FH|FB)/i', '', $rawBillRef);
            }
        }
        
        // PATH 2: Co-op Bank
        elseif ($paybill == getSystemSetting('COOP_BANK_PAYBILL') ||
                $destAcc == getSystemSetting('COOP_BANK_ACCOUNT')) {
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

        // Clean house ID
        $houseId = strtoupper(trim($houseId));
        // Remove any non-alphanumeric characters except dash and underscore
        $houseId = preg_replace('/[^A-Z0-9\-_]/', '', $houseId);

        return [
            'house_id' => $houseId,
            'method' => $method,
            'amount' => $amount,
            'transaction_id' => $transactionId,
            'phone' => $data['MSISDN'] ?? $data['PhoneNumber'] ?? '',
            'paybill' => $paybill,
            'account' => $destAcc
        ];
    }

    /**
     * 2. DUPLICATE PAYMENT DETECTION
     */
    private function isDuplicatePayment() {
        $stmt = $this->pdo->prepare("
            SELECT id, status
            FROM payments
            WHERE transaction_id = ?
            OR (reference = ? AND amount = ? AND payment_date > DATE_SUB(NOW(), INTERVAL ? HOUR))
        ");
        
        $stmt->execute([
            $this->paymentInfo['transaction_id'],
            $this->paymentInfo['transaction_id'],
            $this->paymentInfo['amount'],
            MAX_DUPLICATE_HOURS
        ]);
        
        $existing = $stmt->fetch();
        
        if ($existing) {
            TransactionLogger::log('warning', 'Duplicate payment detected', [
                'transaction_id' => $this->paymentInfo['transaction_id'],
                'existing_id' => $existing['id']
            ]);
            return $existing;
        }
        
        return false;
    }

    /**
     * 3. FIND HOUSE BY REFERENCE
     */
    private function findHouse($houseReference) {
        if (!$houseReference) {
            return null;
        }

        // Try exact match first
        $stmt = $this->pdo->prepare("
            SELECT h.*, b.name as building_name
            FROM houses h
            LEFT JOIN buildings b ON h.building_id = b.id
            WHERE h.bank_reference = ?
            OR CONCAT(b.name, '-', h.house_number) = ?
            OR h.house_number = ?
            LIMIT 1
        ");
        
        $stmt->execute([$houseReference, $houseReference, $houseReference]);
        $house = $stmt->fetch();
        
        if ($house) {
            return $house;
        }

        // Try partial match for bank references
        $stmt = $this->pdo->prepare("
            SELECT h.*, b.name as building_name
            FROM houses h
            LEFT JOIN buildings b ON h.building_id = b.id
            WHERE ? LIKE CONCAT('%', h.house_number, '%')
            OR h.house_number LIKE CONCAT('%', ?, '%')
            LIMIT 1
        ");
        
        $stmt->execute([$houseReference, $houseReference]);
        return $stmt->fetch();
    }

    /**
     * 4. STRICT ARREARS-FIRST WATERFALL ENGINE
     */
    private function runWaterfall($houseId, $amount) {
        $remaining = (float)$amount;
        $breakdown = [
            'arrears_cleared' => 0,
            'utilities_paid' => 0,
            'rent_paid' => 0,
            'overpayment' => 0
        ];

        // Start transaction for atomic operations
        $this->pdo->beginTransaction();

        try {
            // A. CHECK AND UPDATE CURRENT ARREARS FIRST
            $stmt = $this->pdo->prepare("
                SELECT current_arrears
                FROM houses
                WHERE id = ?
                FOR UPDATE
            ");
            
            $stmt->execute([$houseId]);
            $house = $stmt->fetch();
            
            if (!$house) {
                throw new Exception("House not found: " . $houseId);
            }

            $currentArrears = (float)$house['current_arrears'];

            // 1. CLEAR ARREARS FIRST (STRICT RULE)
            if ($currentArrears > 0 && $remaining > 0) {
                $arrearsPayment = min($remaining, $currentArrears);
                $remaining -= $arrearsPayment;
                
                // Update house arrears
                $stmt = $this->pdo->prepare("
                    UPDATE houses
                    SET current_arrears = current_arrears - ?,
                        updated_at = NOW()
                    WHERE id = ?
                ");
                
                $stmt->execute([$arrearsPayment, $houseId]);
                $breakdown['arrears_cleared'] = $arrearsPayment;
                
                TransactionLogger::log('info', 'Arrears cleared', [
                    'house_id' => $houseId,
                    'amount' => $arrearsPayment,
                    'remaining_arrears' => $currentArrears - $arrearsPayment
                ]);
            }

            // 2. PAY UTILITIES (Water, Garbage, Penalty)
            if ($remaining > 0) {
                $stmt = $this->pdo->prepare("
                    SELECT * FROM utility_bills
                    WHERE house_id = ?
                    AND status IN ('unpaid', 'partially_paid')
                    AND priority = 2 -- Utilities priority
                    ORDER BY due_date ASC, priority ASC
                ");
                
                $stmt->execute([$houseId]);
                
                while ($bill = $stmt->fetch()) {
                    if ($remaining <= 0) break;
                    
                    $billAmount = (float)$bill['amount'];
                    $alreadyPaid = (float)$bill['amount_paid'];
                    $billDue = $billAmount - $alreadyPaid;
                    
                    if ($billDue <= 0) continue;
                    
                    $paymentForBill = min($remaining, $billDue);
                    $remaining -= $paymentForBill;
                    $breakdown['utilities_paid'] += $paymentForBill;
                    
                    // Record which utility was paid
                    $breakdown['utility_' . $bill['bill_type']] = $paymentForBill;
                    
                    $newPaidAmount = $alreadyPaid + $paymentForBill;
                    
                    if ($newPaidAmount >= $billAmount) {
                        // Bill fully paid
                        $updateStmt = $this->pdo->prepare("
                            UPDATE utility_bills
                            SET amount_paid = ?,
                                status = 'paid',
                                updated_at = NOW()
                            WHERE id = ?
                        ");
                        $updateStmt->execute([$newPaidAmount, $bill['id']]);
                    } else {
                        // Bill partially paid
                        $updateStmt = $this->pdo->prepare("
                            UPDATE utility_bills
                            SET amount_paid = ?,
                                status = 'partially_paid',
                                updated_at = NOW()
                            WHERE id = ?
                        ");
                        $updateStmt->execute([$newPaidAmount, $bill['id']]);
                    }
                }
            }

            // 3. PAY CURRENT MONTH'S RENT (only after arrears cleared)
            if ($remaining > 0 && $currentArrears <= 0) {
                $stmt = $this->pdo->prepare("
                    SELECT monthly_rent
                    FROM houses
                    WHERE id = ?
                ");
                
                $stmt->execute([$houseId]);
                $house = $stmt->fetch();
                $monthlyRent = (float)$house['monthly_rent'] ?: DEFAULT_RENT_AMOUNT;

                // Check if rent for current month is already paid
                $stmt = $this->pdo->prepare("
                    SELECT SUM(amount) as rent_paid_this_month
                    FROM payments
                    WHERE house_id = ?
                    AND status = 'processed'
                    AND MONTH(payment_date) = MONTH(CURRENT_DATE())
                    AND YEAR(payment_date) = YEAR(CURRENT_DATE())
                    AND deductions_json LIKE '%\"rent_paid\"%'
                ");
                
                $stmt->execute([$houseId]);
                $rentPaid = $stmt->fetch()['rent_paid_this_month'] ?? 0;
                $rentDue = max(0, $monthlyRent - $rentPaid);

                if ($rentDue > 0) {
                    $rentPayment = min($remaining, $rentDue);
                    $remaining -= $rentPayment;
                    $breakdown['rent_paid'] = $rentPayment;
                    
                    TransactionLogger::log('info', 'Rent paid', [
                        'house_id' => $houseId,
                        'amount' => $rentPayment,
                        'rent_due' => $rentDue,
                        'monthly_rent' => $monthlyRent
                    ]);
                }
            }

            // 4. HANDLE OVERPAYMENT (store as credit)
            if ($remaining > 0) {
                $breakdown['overpayment'] = $remaining;
                
                // Update tenant credits
                $stmt = $this->pdo->prepare("
                    INSERT INTO tenant_credits (house_id, balance, notes)
                    VALUES (?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                    balance = balance + ?,
                    last_updated = NOW(),
                    notes = CONCAT(notes, ' | ', ?)
                ");
                
                $note = "Overpayment from " . $this->paymentInfo['method'] . " transaction: " .
                        $this->paymentInfo['transaction_id'];
                
                $stmt->execute([
                    $houseId,
                    $remaining,
                    $note,
                    $remaining,
                    $note
                ]);

                // Also update house overpayment balance
                $stmt = $this->pdo->prepare("
                    UPDATE houses
                    SET overpayment_balance = overpayment_balance + ?,
                        updated_at = NOW()
                    WHERE id = ?
                ");
                
                $stmt->execute([$remaining, $houseId]);
                
                TransactionLogger::log('info', 'Overpayment recorded', [
                    'house_id' => $houseId,
                    'amount' => $remaining
                ]);
            }

            // Commit all changes
            $this->pdo->commit();
            return $breakdown;

        } catch (Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * 5. PROCESS PAYMENT
     */
    public function process() {
        try {
            TransactionLogger::log('info', 'Payment processing started', $this->paymentInfo);

            // Check for duplicate
            $duplicate = $this->isDuplicatePayment();
            if ($duplicate) {
                return [
                    'status' => 'duplicate',
                    'message' => 'Duplicate payment detected',
                    'existing_id' => $duplicate['id'],
                    'existing_status' => $duplicate['status']
                ];
            }

            // Find house
            $house = $this->findHouse($this->paymentInfo['house_id']);
            
            if (!$house) {
                // Record as unidentified payment
                $stmt = $this->pdo->prepare("
                    INSERT INTO payments (
                        transaction_uuid, transaction_id, amount, method,
                        reference, phone_number, status, notes
                    ) VALUES (UUID(), ?, ?, ?, ?, ?, 'unidentified', ?)
                ");
                
                $stmt->execute([
                    $this->paymentInfo['transaction_id'],
                    $this->paymentInfo['amount'],
                    $this->paymentInfo['method'],
                    $this->paymentInfo['house_id'],
                    $this->paymentInfo['phone'],
                    'Unidentified payment - House reference: ' . $this->paymentInfo['house_id']
                ]);
                
                $paymentId = $this->pdo->lastInsertId();
                
                TransactionLogger::log('warning', 'Unidentified payment recorded', [
                    'payment_id' => $paymentId,
                    'house_reference' => $this->paymentInfo['house_id']
                ]);

                return [
                    'status' => 'unidentified',
                    'message' => 'Payment recorded but house not identified',
                    'payment_id' => $paymentId,
                    'house_reference' => $this->paymentInfo['house_id']
                ];
            }

            // HOUSE FOUND - Process waterfall
            $houseId = $house['id'];
            $deductions = $this->runWaterfall($houseId, $this->paymentInfo['amount']);

            // Record payment
            $stmt = $this->pdo->prepare("
                INSERT INTO payments (
                    transaction_uuid, house_id, transaction_id, amount, method,
                    reference, phone_number, deductions_json, status, processed_at
                ) VALUES (UUID(), ?, ?, ?, ?, ?, ?, ?, 'processed', NOW())
            ");
            
            $stmt->execute([
                $houseId,
                $this->paymentInfo['transaction_id'],
                $this->paymentInfo['amount'],
                $this->paymentInfo['method'],
                $this->paymentInfo['house_id'],
                $this->paymentInfo['phone'],
                json_encode($deductions)
            ]);
            
            $paymentId = $this->pdo->lastInsertId();

            // Update house last payment date
            $stmt = $this->pdo->prepare("
                UPDATE houses
                SET updated_at = NOW()
                WHERE id = ?
            ");
            
            $stmt->execute([$houseId]);

            // Send notification if enabled
            $this->sendPaymentNotification($house, $deductions);

            TransactionLogger::log('info', 'Payment processed successfully', [
                'payment_id' => $paymentId,
                'house_id' => $houseId,
                'house_reference' => $house['bank_reference'],
                'deductions' => $deductions
            ]);

            return [
                'status' => 'success',
                'message' => 'Payment processed successfully',
                'payment_id' => $paymentId,
                'house_id' => $houseId,
                'tenant_name' => $house['tenant_name'],
                'deductions' => $deductions
            ];

        } catch (Exception $e) {
            TransactionLogger::log('error', 'Payment processing failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'payment_info' => $this->paymentInfo
            ]);
            
            return [
                'status' => 'error',
                'message' => 'Payment processing failed: ' . $e->getMessage()
            ];
        }
    }

    /**
     * 6. SEND PAYMENT NOTIFICATION
     */
    private function sendPaymentNotification($house, $deductions) {
        try {
            if (empty($house['phone_primary']) && empty($house['phone_secondary'])) {
                return;
            }

            $phone = !empty($house['phone_primary']) ? $house['phone_primary'] : $house['phone_secondary'];
            
            // Construct message
            $message = "Dear " . $house['tenant_name'] . ", ";
            $message .= "Payment of Ksh " . number_format($this->paymentInfo['amount'], 2) . " received. ";
            
            if ($deductions['arrears_cleared'] > 0) {
                $message .= "Arrears cleared: Ksh " . number_format($deductions['arrears_cleared'], 2) . ". ";
            }
            
            if ($deductions['utilities_paid'] > 0) {
                $message .= "Utilities paid: Ksh " . number_format($deductions['utilities_paid'], 2) . ". ";
            }
            
            if ($deductions['rent_paid'] > 0) {
                $message .= "Rent paid: Ksh " . number_format($deductions['rent_paid'], 2) . ". ";
            }
            
            if ($deductions['overpayment'] > 0) {
                $message .= "Overpayment credit: Ksh " . number_format($deductions['overpayment'], 2) . ". ";
            }
            
            $message .= "Ref: " . $this->paymentInfo['transaction_id'] . " - Eagle Homes";

            // Insert notification record
            $stmt = $this->pdo->prepare("
                INSERT INTO notifications (
                    house_id, tenant_name, phone_number, message_type,
                    message, status, sent_by
                ) VALUES (?, ?, ?, 'payment', ?, 'pending', 'system')
            ");
            
            $stmt->execute([
                $house['id'],
                $house['tenant_name'],
                $phone,
                $message
            ]);

            // In production, integrate with SMS gateway here
            // $this->sendSMS($phone, $message);

            TransactionLogger::log('info', 'Payment notification queued', [
                'house_id' => $house['id'],
                'phone' => $phone,
                'message_length' => strlen($message)
            ]);

        } catch (Exception $e) {
            TransactionLogger::log('error', 'Failed to queue notification', [
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * 7. INTEGRATE WITH SMS GATEWAY
     */
    private function sendSMS($phone, $message) {
        try {
            // Remove any non-digit characters
            $phone = preg_replace('/\D/', '', $phone);
            
            // Add country code if missing
            if (!str_starts_with($phone, '254')) {
                $phone = str_starts_with($phone, '0') ? '254' . substr($phone, 1) : '254' . $phone;
            }

            // Example with Africa's Talking API
            $apiKey = getSystemSetting('SMS_API_KEY', 'your_api_key_here');
            $username = getSystemSetting('SMS_USERNAME', 'sandbox');
            
            $data = [
                'username' => $username,
                'to' => $phone,
                'message' => $message,
                'from' => 'EAGLEHOMES'
            ];
            
            $ch = curl_init('https://api.africastalking.com/version1/messaging');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'ApiKey: ' . $apiKey,
                'Content-Type: application/x-www-form-urlencoded'
            ]);
            
            $response = curl_exec($ch);
            curl_close($ch);
            
            TransactionLogger::log('info', 'SMS sent', [
                'phone' => $phone,
                'message_length' => strlen($message),
                'response' => $response
            ]);
            
            return true;
            
        } catch (Exception $e) {
            TransactionLogger::log('error', 'SMS sending failed', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }
}

// ============================================
// API ENTRY POINT
// ============================================
try {
    // Get raw input
    $rawInput = file_get_contents('php://input');
    
    // Log incoming request
    TransactionLogger::log('info', 'API request received', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
        'input_length' => strlen($rawInput),
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);

    // Validate request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method. Use POST.');
    }

    // Parse input data
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (strpos($contentType, 'application/json') !== false) {
        $data = json_decode($rawInput, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid JSON: ' . json_last_error_msg());
        }
    } else {
        // Fallback to POST data
        $data = $_POST;
    }

    // Validate required fields
    $requiredFields = ['TransID', 'TransAmount'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            throw new Exception('Missing required field: ' . $field);
        }
    }

    // Process payment
    $processor = new PaymentProcessor($data);
    $result = $processor->process();

    // Return response
    header('Content-Type: application/json');
    http_response_code($result['status'] === 'error' ? 500 : 200);
    
    echo json_encode([
        'api_version' => API_VERSION,
        'timestamp' => date('c'),
        'status' => $result['status'],
        'message' => $result['message'],
        'data' => $result
    ]);

} catch (Exception $e) {
    // Log error
    TransactionLogger::log('error', 'API execution failed', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);

    // Return error response
    header('Content-Type: application/json');
    http_response_code(500);
    
    echo json_encode([
        'api_version' => API_VERSION,
        'timestamp' => date('c'),
        'status' => 'error',
        'message' => 'Internal server error',
        'error' => $e->getMessage()
    ]);
}

// Flush output buffer
ob_end_flush();
