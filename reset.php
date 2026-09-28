<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
$db_host = 'localhost';
$db_user = 'root';
$db_password = '';

$conn = new mysqli($db_host, $db_user, $db_password);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'error' => 'Connection failed: ' . $conn->connect_error]));
}

$conn->query("DROP DATABASE IF EXISTS pentest_db");

$sql = "CREATE DATABASE IF NOT EXISTS pentest_db";
$conn->query($sql);

$conn->select_db('pentest_db');

$create_table = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    privilege_level VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
$conn->query($create_table);

$create_log = "CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    attack_type VARCHAR(100),
    attack_payload TEXT,
    success BOOLEAN,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
$conn->query($create_log);

$create_attempts = "CREATE TABLE IF NOT EXISTS login_attempts (
    username VARCHAR(255) PRIMARY KEY,
    fail_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)";
$conn->query($create_attempts);

$users = [
    ['admin', 'admin123', 'admin'],
    ['administrator', 'password123', 'admin'],
    ['test', 'test123', 'user'],
    ['user', 'password123', 'user'],
    ['demo', 'demo', 'guest'],
    ['guest', '1234', 'guest'],
    ['john', 'john123', 'user'],
    ['alice', 'alice456', 'admin'],
    ['bob', 'bobpass', 'user'],
    ['root', 'root123', 'admin']
];

foreach ($users as $user) {
    $username = $user[0];
    $password = $user[1];
    $privilege = $user[2];
    $insert = "INSERT IGNORE INTO users (username, password, privilege_level) VALUES ('$username', '$password', '$privilege')";
    $conn->query($insert);
}

$conn->close();
echo json_encode(['success' => true, 'message' => 'Database reset and setup complete with privilege levels']);
?>
