<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 50;

$query = "SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT " . $limit;

$result = $conn->query($query);

if (!$result) {
    echo json_encode(['success' => false, 'error' => $conn->error]);
    exit;
}

$logs = [];
while ($row = $result->fetch_assoc()) {
    $logs[] = $row;
}

echo json_encode([
    'success' => true,
    'logs' => $logs,
    'total' => count($logs)
]);

$conn->close();
?>
