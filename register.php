<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

$username = isset($_POST['username']) ? $_POST['username'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';

if (empty($username) || empty($password)) {
    echo json_encode(['success' => false, 'error' => 'Username and password required']);
    exit;
}

$check_query = "SELECT * FROM users WHERE username = '" . $username . "'";
$check_result = $conn->query($check_query);

if ($check_result->num_rows > 0) {
    echo json_encode(['success' => false, 'error' => 'Username already exists']);
    exit;
}

$insert_query = "INSERT INTO users (username, password) VALUES ('" . $username . "', '" . $password . "')";

if ($conn->query($insert_query) === TRUE) {
    echo json_encode(['success' => true, 'message' => 'Account created successfully']);
} else {
    echo json_encode(['success' => false, 'error' => $conn->error]);
}

$conn->close();
?>
