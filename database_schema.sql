-- Create database
CREATE DATABASE IF NOT EXISTS pentest_db;
USE pentest_db;

-- Users table (matches what setup.php / reset.php actually create)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    privilege_level VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attack / activity log
CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    attack_type VARCHAR(100),
    attack_payload TEXT,
    success BOOLEAN,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- NEW: brute-force defense — tracks failed logins per username so
-- login.php can enforce incremental lockout + "attempts remaining".
CREATE TABLE IF NOT EXISTS login_attempts (
    username VARCHAR(255) PRIMARY KEY,
    fail_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert test users (plaintext passwords for penetration testing)
INSERT INTO users (username, password, privilege_level) VALUES
('admin', 'admin123', 'admin'),
('administrator', 'password123', 'admin'),
('test', 'test123', 'user'),
('user', 'password123', 'user'),
('demo', 'demo', 'guest'),
('guest', '1234', 'guest'),
('john', 'john123', 'user'),
('alice', 'alice456', 'admin'),
('bob', 'bobpass', 'user'),
('root', 'root123', 'admin');
