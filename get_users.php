<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

$query = "SELECT username, password, privilege_level, created_at FROM users ORDER BY privilege_level DESC, username ASC";
$result = $conn->query($query);

if (!$result) {
    echo json_encode(['success' => false, 'error' => $conn->error]);
    exit;
}

$users = [];
while ($row = $result->fetch_assoc()) {
    $users[] = $row;
}

echo json_encode([
    'success' => true,
    'total_users' => count($users),
    'users' => $users
]);

$conn->close();
?>
