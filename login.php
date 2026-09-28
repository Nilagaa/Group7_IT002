<?php

header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

const MAX_ATTEMPTS = 5;
const LOCKOUT_SCHEDULE = [15, 30, 60, 120, 1800];

/*
 * Only allow POST requests
 */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'error' => 'Method not allowed'
    ]);
    exit;
}

/*
 * Get login information
 */
$username = isset($_POST['username'])
    ? trim($_POST['username'])
    : '';

$password = isset($_POST['password'])
    ? $_POST['password']
    : '';

/*
 * Check required fields
 */
if ($username === '' || $password === '') {
    echo json_encode([
        'success' => false,
        'error' => 'Username and password required'
    ]);
    exit;
}

/*
 * Limit username length
 */
if (strlen($username) > 255) {
    echo json_encode([
        'success' => false,
        'error' => 'Invalid username'
    ]);
    exit;
}

$lookup_key = strtolower($username);

/*
 * Calculate lockout duration
 */
function lockout_seconds($fail_count)
{
    $index = min(
        max($fail_count, 1),
        count(LOCKOUT_SCHEDULE)
    ) - 1;

    return LOCKOUT_SCHEDULE[$index];
}

/*
 * Check previous failed attempts
 */
$stmt = $conn->prepare(
    "SELECT fail_count, locked_until
     FROM login_attempts
     WHERE username = ?"
);

if (!$stmt) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error: ' . $conn->error
    ]);
    exit;
}

$stmt->bind_param('s', $lookup_key);

if (!$stmt->execute()) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error: ' . $stmt->error
    ]);
    $stmt->close();
    exit;
}

$stmt->store_result();

$fail_count = 0;
$locked_until = null;

if ($stmt->num_rows > 0) {
    $stmt->bind_result(
        $fail_count,
        $locked_until
    );

    $stmt->fetch();

    $fail_count = (int) $fail_count;
}

$stmt->close();

/*
 * Check lockout status
 */
$now = time();

$locked_until_ts = $locked_until
    ? strtotime($locked_until)
    : null;

if ($locked_until_ts !== null && $locked_until_ts > $now) {

    echo json_encode([
        'success' => false,
        'locked' => true,
        'error' => 'Too many failed attempts. Account locked.',
        'retry_after' => $locked_until_ts - $now,
        'attempts_remaining' => 0
    ]);

    exit;
}

/*
 * Secure login query
 *
 * Prepared statement prevents SQL injection.
 */
$stmt = $conn->prepare(
    "SELECT username, password, privilege_level
     FROM users
     WHERE username = ? AND password = ?
     LIMIT 1"
);

if (!$stmt) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error: ' . $conn->error
    ]);
    exit;
}

$stmt->bind_param(
    'ss',
    $username,
    $password
);

if (!$stmt->execute()) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error: ' . $stmt->error
    ]);
    $stmt->close();
    exit;
}

$stmt->store_result();

/*
 * Successful login
 */
if ($stmt->num_rows > 0) {

    $stmt->bind_result(
        $db_username,
        $db_password,
        $db_privilege
    );

    $stmt->fetch();

    $stmt->close();

    /*
     * Clear failed login attempts
     */
    $clear = $conn->prepare(
        "DELETE FROM login_attempts
         WHERE username = ?"
    );

    if ($clear) {
        $clear->bind_param(
            's',
            $lookup_key
        );

        $clear->execute();
        $clear->close();
    }

    /*
     * Log successful login
     */
    $log = $conn->prepare(
        "INSERT INTO attack_logs
         (username, attack_type, attack_payload, success)
         VALUES (?, ?, ?, ?)"
    );

    if ($log) {

        $attack_type = 'login_success';
        $payload = '';
        $success = 1;

        $log->bind_param(
            'sssi',
            $username,
            $attack_type,
            $payload,
            $success
        );

        $log->execute();
        $log->close();
    }

    /*
     * Generate login token
     */
    $token = bin2hex(random_bytes(32));

    echo json_encode([
        'success' => true,
        'token' => $token,
        'user' => $db_username,
        'privilege' => $db_privilege
    ]);

    $conn->close();
    exit;
}

/*
 * Invalid login
 */
$stmt->close();

$fail_count++;

$duration = lockout_seconds($fail_count);

$new_locked_until = date(
    'Y-m-d H:i:s',
    $now + $duration
);

$locked_flag = $fail_count >= MAX_ATTEMPTS;

/*
 * Update login attempt counter
 */
$upsert = $conn->prepare(
    "INSERT INTO login_attempts
     (username, fail_count, locked_until)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE
        fail_count = ?,
        locked_until = ?"
);

if ($upsert) {

    $upsert->bind_param(
        'sisis',
        $lookup_key,
        $fail_count,
        $new_locked_until,
        $fail_count,
        $new_locked_until
    );

    $upsert->execute();
    $upsert->close();
}

/*
 * Log failed login
 */
$log = $conn->prepare(
    "INSERT INTO attack_logs
     (username, attack_type, attack_payload, success)
     VALUES (?, ?, ?, ?)"
);

if ($log) {

    $attack_type = 'failed_login';
    $payload = '';
    $success = 0;

    $log->bind_param(
        'sssi',
        $username,
        $attack_type,
        $payload,
        $success
    );

    $log->execute();
    $log->close();
}

/*
 * Return failed login response
 */
$response = [
    'success' => false,
    'error' => 'Invalid username or password.',
    'locked' => $locked_flag,
    'retry_after' => $duration,
    'attempts_remaining' => max(
        0,
        MAX_ATTEMPTS - $fail_count
    )
];

if ($locked_flag) {
    $response['error'] =
        'Too many failed attempts. Account locked.';
}

echo json_encode($response);

$conn->close();
?>