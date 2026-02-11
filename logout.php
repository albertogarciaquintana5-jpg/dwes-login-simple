<?php
require_once 'functions.php';
secure_session_start();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}

secure_logout();

header('Location: login.php');
exit;
