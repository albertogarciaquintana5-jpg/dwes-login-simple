<?php
require_once 'db.php';
session_start();

function secure_session_start() {

    if (session_status() === PHP_SESSION_NONE) {

        $cookieParams = session_get_cookie_params();

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $cookieParams['path'],
            'domain' => $cookieParams['domain'],
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        session_start();
    }
}

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    if (empty($token) || empty($_SESSION['csrf_token'])) return false;
    $valid = hash_equals($_SESSION['csrf_token'], $token);
    return $valid;
}

function is_session_expired() {
    $max_lifetime = 2 * 3600; 
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $max_lifetime)) {
        return true;
    }
    return false;
}

function update_session_activity() {
    $_SESSION['last_activity'] = time();
}

function maybe_regenerate_session_id($interval_seconds = 15 * 60) {
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
        return;
    }
    if (time() - $_SESSION['created'] > $interval_seconds) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

function record_login_attempt($pdo, $username, $ip, $success) {
    $stmt = $pdo->prepare("INSERT INTO login_attempts (username, ip, success) VALUES (?, ?, ?)");
    $stmt->execute([$username, $ip, $success ? 1 : 0]);

    if (!$success) {
        $stmt = $pdo->prepare("UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_at = NOW() WHERE username = ?");
        $stmt->execute([$username]);
    } else {
        $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, last_failed_at = NULL WHERE username = ?");
        $stmt->execute([$username]);
    }
}

function get_failed_attempts_info($pdo, $username) {
    $stmt = $pdo->prepare("SELECT failed_attempts, last_failed_at FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch();
}

function sanitize_username($u) {
    return preg_replace('/[^A-Za-z0-9_.\-]/', '', $u);
}

function secure_logout() {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
}

function validate_password_policy($password) {
    $min = 8; $max = 15;
    if (strlen($password) < $min || strlen($password) > $max) return false;
    if (!preg_match('/[A-Z]/', $password)) return false;
    if (!preg_match('/[a-z]/', $password)) return false;
    if (!preg_match('/[0-9]/', $password)) return false;
    if (!preg_match('/[!@#$%^&*\-_\+=\.,\?:;]/', $password)) return false;
    if (preg_match('/[\'"\\\\\/<>=\(\)]/', $password)) return false;
    return true;
}
