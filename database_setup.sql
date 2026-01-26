-- Create database
CREATE DATABASE IF NOT EXISTS eagles_home;
USE eagles_home;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role ENUM('owner', 'secretary') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Houses table
CREATE TABLE IF NOT EXISTS houses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    house_number VARCHAR(20) UNIQUE NOT NULL,
    owner_name VARCHAR(100) NOT NULL,
    monthly_rent DECIMAL(10, 2) NOT NULL,
    status ENUM('Paid', 'Arrears', 'Credit') DEFAULT 'Arrears',
    balance DECIMAL(10, 2) DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Utility bills table
CREATE TABLE IF NOT EXISTS utility_bills (
    id INT PRIMARY KEY AUTO_INCREMENT,
    house_id INT NOT NULL,
    water DECIMAL(10, 2) DEFAULT 0,
    electricity DECIMAL(10, 2) DEFAULT 0,
    garbage DECIMAL(10, 2) DEFAULT 200,
    billing_month DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE CASCADE
);

-- Payments table (immutable records)
CREATE TABLE IF NOT EXISTS payments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    house_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    payment_date DATE NOT NULL,
    reference VARCHAR(100),
    bank_name VARCHAR(100),
    is_immutable BOOLEAN DEFAULT TRUE,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (house_id) REFERENCES houses(id) ON DELETE CASCADE
);

-- Insert sample data
INSERT INTO users (username, password, email, role) VALUES
('owner_admin', 'Eagles2026!', 'owner@example.com', 'owner'),
('secretary_entry', 'Secret2026!', 'secretary@example.com', 'secretary');

INSERT INTO houses (house_number, owner_name, monthly_rent, status, balance) VALUES
('A101', 'John Doe', 15000.00, 'Paid', 0),
('A102', 'Jane Smith', 18000.00, 'Arrears', 2500.00),
('B201', 'Robert Johnson', 12000.00, 'Credit', -1500.00),
('B202', 'Mary Williams', 20000.00, 'Paid', 0);

INSERT INTO payments (house_id, amount, payment_date, reference, bank_name) VALUES
(1, 15000.00, CURDATE(), 'REF001', 'Co-op Bank'),
(2, 15500.00, CURDATE(), 'REF002', 'Family Bank'),
(4, 20000.00, CURDATE(), 'REF003', 'Co-op Bank');

-- Create indexes for better performance
CREATE INDEX idx_payments_date ON payments(payment_date);
CREATE INDEX idx_utility_month ON utility_bills(billing_month);
CREATE INDEX idx_houses_status ON houses(status);
