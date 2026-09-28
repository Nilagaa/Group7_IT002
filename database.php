<?php

mysqli_report(MYSQLI_REPORT_OFF);

$db_host = 'localhost';
$db_user = 'root';
$db_password = '';
$db_name = 'pentest_db';

$conn = new mysqli($db_host, $db_user, $db_password, $db_name);

if ($conn->connect_error) {
    die(json_encode(['success' => false, 'error' => 'Connection failed: ' . $conn->connect_error]));
}

$conn->set_charset("utf8");
?>
