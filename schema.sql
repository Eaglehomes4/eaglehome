-- ============================================
-- EAGLE HOMES COMPLETE DATABASE SCHEMA
-- ============================================

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Users table with enhanced security
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('owner', 'secretary') NOT NULL DEFAULT 'secretary',
    full_name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Buildings table
CREATE TABLE buildings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    address TEXT,
    total_units INTEGER DEFAULT 0,
    owner_name VARCHAR(255),
    owner_phone VARCHAR(20),
    owner_account VARCHAR(100),
    notes TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Houses/Units table with comprehensive fields
CREATE TABLE houses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    building_id INTEGER NOT NULL,
    house_number VARCHAR(50) NOT NULL,
    bank_reference VARCHAR(100) UNIQUE, -- Format: BUILDING-UNIT (e.g., ROSALIA-1)
    tenant_name VARCHAR(255),
    phone_primary VARCHAR(20),
    phone_secondary VARCHAR(20),
    monthly_rent DECIMAL(12, 2) DEFAULT 0.00,
    deposit_paid DECIMAL(12, 2) DEFAULT 0.00,
    deposit_held DECIMAL(12, 2) DEFAULT 0.00,
    current_arrears DECIMAL(12, 2) DEFAULT 0.00,
    overpayment_balance DECIMAL(12, 2) DEFAULT 0.00,
    status ENUM('occupied', 'vacant', 'landlord', 'caretaker', 'store', 'under_renovation') DEFAULT 'vacant',
    entry_date DATE,
    exit_date DATE,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(id) ON DELETE CASCADE,
    UNIQUE(building_id, house_number)
);

-- Utility bills table with arrears-first priority
CREATE TABLE utility_bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    house_id INTEGER NOT NULL,
    bill_type ENUM('water', 'garbage', 'electricity', 'penalty', 'other') NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    description TEXT,
    bill_date DATE NOT NULL,
    due_date DATE,
    priority INTEGER DEFAULT 1, -- 1=highest (arrears), 2=utilities, 3=current rent
    status ENUM('unpaid', 'partially_paid', 'paid', 'waived') DEFAULT 'unpaid',
    amount_paid DECIMAL(12, 2) DEFAULT 0.00,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE CASCADE,
    INDEX idx_house_status (house_id, status),
    INDEX idx_bill_type (bill_type)
);

-- Tenant credits/overpayments table
CREATE TABLE tenant_credits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    house_id INTEGER NOT NULL,
    balance DECIMAL(12, 2) DEFAULT 0.00,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE CASCADE,
    UNIQUE(house_id)
);

-- Payments table with comprehensive tracking
CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_uuid VARCHAR(36) UNIQUE NOT NULL,
    house_id INTEGER,
    transaction_id VARCHAR(100), -- M-Pesa/Bank transaction ID
    amount DECIMAL(12, 2) NOT NULL,
    method ENUM('M-Pesa', 'Family Bank', 'Co-op Bank', 'Payslip', 'Cash', 'Cheque') NOT NULL,
    reference VARCHAR(255),
    phone_number VARCHAR(20),
    deductions_json TEXT,
    status ENUM('pending', 'processed', 'unidentified', 'failed', 'refunded') DEFAULT 'pending',
    processed_at DATETIME,
    payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_duplicate BOOLEAN DEFAULT 0,
    duplicate_of INTEGER,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE SET NULL,
    INDEX idx_transaction_id (transaction_id),
    INDEX idx_status (status),
    INDEX idx_house_date (house_id, payment_date)
);

-- Refunds table for overpayment handling
CREATE TABLE refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id INTEGER NOT NULL,
    house_id INTEGER NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    reason TEXT NOT NULL,
    status ENUM('pending', 'processed', 'failed') DEFAULT 'pending',
    processed_by INTEGER,
    processed_at DATETIME,
    transaction_reference VARCHAR(100),
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (payment_id) REFERENCES payments(id),
    FOREIGN KEY (house_id) REFERENCES houses(id),
    FOREIGN KEY (processed_by) REFERENCES users(id)
);

-- Notifications table
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    house_id INTEGER,
    tenant_name VARCHAR(255),
    phone_number VARCHAR(20),
    message_type ENUM('arrears', 'broadcast', 'holiday', 'payment', 'utility', 'refund') NOT NULL,
    message TEXT NOT NULL,
    status ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
    sent_at DATETIME,
    sent_by ENUM('system', 'owner', 'secretary') DEFAULT 'system',
    response TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE SET NULL,
    INDEX idx_message_type (message_type),
    INDEX idx_status (status)
);

-- Audit log for all transactions
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action_type VARCHAR(50) NOT NULL,
    table_name VARCHAR(50),
    record_id INTEGER,
    old_values TEXT,
    new_values TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- System settings
CREATE TABLE system_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    data_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    is_public BOOLEAN DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Landlord statements
CREATE TABLE landlord_statements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    building_id INTEGER NOT NULL,
    statement_month DATE NOT NULL,
    total_rent DECIMAL(12, 2) DEFAULT 0.00,
    total_collected DECIMAL(12, 2) DEFAULT 0.00,
    commission_rate DECIMAL(5, 2) DEFAULT 0.00,
    commission_amount DECIMAL(12, 2) DEFAULT 0.00,
    total_expenses DECIMAL(12, 2) DEFAULT 0.00,
    net_to_landlord DECIMAL(12, 2) DEFAULT 0.00,
    status ENUM('draft', 'finalized', 'paid') DEFAULT 'draft',
    notes TEXT,
    created_by INTEGER,
    finalized_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE(building_id, statement_month)
);

-- Statement details
CREATE TABLE statement_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    statement_id INTEGER NOT NULL,
    house_id INTEGER NOT NULL,
    rent_amount DECIMAL(12, 2) DEFAULT 0.00,
    amount_paid DECIMAL(12, 2) DEFAULT 0.00,
    garbage_fee DECIMAL(12, 2) DEFAULT 0.00,
    other_charges DECIMAL(12, 2) DEFAULT 0.00,
    remarks TEXT,
    FOREIGN KEY (statement_id) REFERENCES landlord_statements(id) ON DELETE CASCADE,
    FOREIGN KEY (house_id) REFERENCES houses(id)
);

-- ============================================
-- DEFAULT DATA
-- ============================================

-- Insert default users (password: Eagles2026! hashed)
INSERT INTO users (username, password_hash, role, full_name) VALUES 
('owner', '$2y$10$YourHashedPasswordHere', 'owner', 'System Owner'),
('secretary', '$2y$10$YourHashedPasswordHere', 'secretary', 'System Secretary');

-- Insert default settings
INSERT INTO system_settings (setting_key, setting_value, data_type, description) VALUES
('company_name', 'Eagle Homes Agencies', 'string', 'Company display name'),
('default_water_rate', '100', 'number', 'Default water charge per unit'),
('default_garbage_fee', '200', 'number', 'Default monthly garbage fee'),
('penalty_percentage', '5', 'number', 'Late payment penalty percentage'),
('commission_rate', '10', 'number', 'Default management commission rate'),
('family_bank_paybill', '222111', 'string', 'Family Bank paybill number'),
('family_bank_account', '045000037386', 'string', 'Family Bank account number'),
('coop_bank_paybill', '417185', 'string', 'Co-op Bank paybill number'),
('coop_bank_account', '01192156596100', 'string', 'Co-op Bank account number'),
('notification_arrears_day', '5', 'number', 'Day of month to send arrears reminders'),
('holiday_messages', '["2024-10-20:Mashujaa Day", "2024-06-01:Madaraka Day", "2024-12-25:Merry Christmas"]', 'json', 'Holiday dates and messages');

-- Create sample building
INSERT INTO buildings (name, address, total_units, owner_name) VALUES
('ROSALIA HOUSE', 'Nairobi, Kenya', 10, 'John Doe');

-- Create triggers for audit logging
CREATE TRIGGER houses_audit_update AFTER UPDATE ON houses
BEGIN
    INSERT INTO audit_log (table_name, record_id, action_type, old_values, new_values)
    VALUES ('houses', NEW.id, 'UPDATE', 
        json_object('monthly_rent', OLD.monthly_rent, 'current_arrears', OLD.current_arrears),
        json_object('monthly_rent', NEW.monthly_rent, 'current_arrears', NEW.current_arrears)
    );
END;

CREATE TRIGGER payments_audit_insert AFTER INSERT ON payments
BEGIN
    INSERT INTO audit_log (table_name, record_id, action_type, new_values)
    VALUES ('payments', NEW.id, 'INSERT',
        json_object('amount', NEW.amount, 'method', NEW.method, 'house_id', NEW.house_id)
    );
END;

-- Create indexes for performance
CREATE INDEX idx_houses_building ON houses(building_id, status);
CREATE INDEX idx_payments_house_date ON payments(house_id, payment_date);
CREATE INDEX idx_utility_bills_due ON utility_bills(house_id, due_date, status);
CREATE INDEX idx_notifications_sent ON notifications(sent_at, status);
CREATE INDEX idx_audit_created ON audit_log(created_at);
