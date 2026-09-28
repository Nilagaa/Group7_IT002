```php
<?php
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Type: application/json');

require 'database.php';

const MAX_ATTEMPTS = 5;
const LOCKOUT_SCHEDULE = [15, 30, 60, 120, 1800];

/*
 * Create login attempt table
 */
$conn->query("CREATE TABLE IF NOT EXISTS login_attempts (
    username VARCHAR(255) PRIMARY KEY,
    fail_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)");

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

$lookup_key = strtolower($username);

/*
 * Calculate lockout duration
 */
function lockout_seconds($fail_count)
{
    $idx = min($fail_count, count(LOCKOUT_SCHEDULE)) - 1;

    if ($idx < 0) {
        $idx = 0;
    }

    return LOCKOUT_SCHEDULE[$idx];
}

/*
 * Check previous login attempts
 *
 * Prepared statement prevents SQL injection.
 */
$stmt = $conn->prepare(
    "SELECT fail_count, locked_until
     FROM login_attempts
     WHERE username = ?"
);

if (!$stmt) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error'
    ]);
    exit;
}

$stmt->bind_param('s', $lookup_key);
$stmt->execute();

/*
 * Use store_result instead of get_result
 * for compatibility with PHP installations
 * that do not have mysqlnd enabled.
 */
$stmt->store_result();

$attempt_row = null;

if ($stmt->num_rows > 0) {

    $stmt->bind_result(
        $db_fail_count,
        $db_locked_until
    );

    $stmt->fetch();

    $attempt_row = [
        'fail_count' => $db_fail_count,
        'locked_until' => $db_locked_until
    ];
}

$stmt->close();

$fail_count = $attempt_row
    ? (int) $attempt_row['fail_count']
    : 0;

$locked_until_ts =
    ($attempt_row && $attempt_row['locked_until'])
    ? strtotime($attempt_row['locked_until'])
    : null;

$now_ts = time();

/*
 * Check if account is locked
 */
if ($locked_until_ts !== null && $locked_until_ts > $now_ts) {

    echo json_encode([
        'success' => false,
        'locked' => true,
        'error' => 'Too many failed attempts. Account locked.',
        'retry_after' => $locked_until_ts - $now_ts,
        'attempts_remaining' => 0
    ]);

    exit;
}

/*
 * SECURE LOGIN QUERY
 *
 * The username and password are parameters.
 * They cannot modify the SQL query.
 */
$stmt = $conn->prepare(
    "SELECT username, password, privilege_level
     FROM users
     WHERE username = ? AND password = ?"
);

if (!$stmt) {
    echo json_encode([
        'success' => false,
        'error' => 'Database query error'
    ]);
    exit;
}

$stmt->bind_param(
    'ss',
    $username,
    $password
);

$stmt->execute();

/*
 * Use store_result instead of get_result
 */
$stmt->store_result();

if ($stmt->num_rows > 0) {

    /*
     * Get user information
     */
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
     * Generate token
     */
    $token = base64_encode(
        $username . ':' . time()
    );

    echo json_encode([
        'success' => true,
        'token' => $token,
        'user' => $db_username,
        'privilege' => $db_privilege
    ]);

} else {

    $stmt->close();

    /*
     * Failed login
     */
    $fail_count++;

    $duration = lockout_seconds($fail_count);

    $new_locked_until = date(
        'Y-m-d H:i:s',
        $now_ts + $duration
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
}

$conn->close();
?>
```