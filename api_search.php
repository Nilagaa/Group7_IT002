<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

$search = isset($_GET['search']) ? trim($_GET['search']) : '';

if ($search === '') {
    echo json_encode(['success' => false, 'error' => 'Search parameter required']);
    exit;
}

if (mb_strlen($search) > 50) {
    $search = mb_substr($search, 0, 50);
}

if (!preg_match('/^[A-Za-z0-9 _-]+$/', $search)) {
    $log_query = "INSERT INTO attack_logs (username, attack_type, attack_payload, success) VALUES ('anonymous', 'sql_injection_blocked', '" . addslashes($search) . "', 0)";
    $conn->query($log_query);
    echo json_encode(['success' => false, 'error' => 'Invalid characters in search. Only letters, numbers, spaces, hyphens and underscores are allowed.']);
    exit;
}

$like = '%' . $search . '%';
$stmt = $conn->prepare("SELECT username, privilege_level FROM users WHERE username LIKE ? OR privilege_level LIKE ?");
$stmt->bind_param('ss', $like, $like);
$stmt->execute();
$result = $stmt->get_result();

$users = [];
while ($row = $result->fetch_assoc()) {
    $users[] = $row;
}
$stmt->close();

$log_query = "INSERT INTO attack_logs (username, attack_type, attack_payload, success) VALUES ('anonymous', 'user_search', '" . addslashes($search) . "', " . (count($users) > 0 ? 1 : 0) . ")";
$conn->query($log_query);

echo json_encode(['success' => true, 'results' => $users, 'count' => count($users)]);

$conn->close();
?>