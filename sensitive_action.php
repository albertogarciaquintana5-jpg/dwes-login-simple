<?php
require_once 'functions.php';
secure_session_start();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') http_response_code(405);

if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF inválido, operación denegada.');
}

echo "Operación realizada.";
