-- Create the Buildings Table
CREATE TABLE buildings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the Houses/Tenants Table
CREATE TABLE houses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    building_id INT,
    house_number VARCHAR(50),
    bank_reference VARCHAR(100) UNIQUE, -- e.g., JH-01
    tenant_name VARCHAR(255),
    monthly_rent DECIMAL(10, 2),
    deposit_paid DECIMAL(10, 2),
    status ENUM('Paid', 'Arrears', 'Credit', 'Unpaid') DEFAULT 'Unpaid',
    FOREIGN KEY (building_id) REFERENCES buildings(id)
);

-- Create the Payments Table (Immutable)
CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    house_id INT,
    transaction_id VARCHAR(100) UNIQUE, -- M-Pesa Receipt
    amount DECIMAL(10, 2),
    source ENUM('Co-op', 'Family'),
    payment_date DATETIME,
    FOREIGN KEY (house_id) REFERENCES houses(id)
);
