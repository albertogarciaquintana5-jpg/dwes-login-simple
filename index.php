<?php
require_once 'functions.php';
secure_session_start();
generate_csrf_token();
update_session_activity();
maybe_regenerate_session_id();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        http_response_code(400);
        die('Token CSRF inválido.');
    }

    $username = sanitize_username($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];

    $info = get_failed_attempts_info($pdo, $username);
    $max_attempts = 5;
    $lockout_seconds = 15 * 60;

    if ($info) {
        if ($info['failed_attempts'] >= $max_attempts) {
            $last = strtotime($info['last_failed_at']);
            if (time() - $last < $lockout_seconds) {
                die('Cuenta temporalmente bloqueada por intentos fallidos. Intenta más tarde.');
            } else {
                $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0 WHERE username = ?");
                $stmt->execute([$username]);
            }
        }
    }

    $stmt = $pdo->prepare("SELECT id, password_hash, is_approved FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    $success = false;
    if ($user && password_verify($password, $user['password_hash'])) {
        if (!$user['is_approved']) {
            die('Tu registro está pendiente de aprobación por un administrador.');
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $username;
        update_session_activity();
        $_SESSION['created'] = time();

        $success = true;
    }

    record_login_attempt($pdo, $username, $ip, $success);
    if ($success) {
        header('Location: protected.php');
        exit;
    } else {
        echo "Usuario/contraseña incorrectos.";
    }
}
?>

<!-- Formulario HTML (frontend JS validación abajo) -->
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
    body { background: #e9eef3; }
    .card { border-radius: 20px; }
</style>

</head>
<body>

<div class="container d-flex justify-content-center align-items-center" style="height:100vh;">
    <div class="card p-4 shadow-lg" style="width: 380px;">
        <h3 class="text-center mb-3">Iniciar Sesión</h3>

        <form id="loginForm" method="post" action="login.php" novalidate>
            <div class="mb-3">
                <label class="form-label">Usuario</label>
                <input type="text" name="username" id="username" class="form-control" required>
            </div>

            <div class="mb-3">
                <label class="form-label">Contraseña</label>
                <input type="password" name="password" id="password" class="form-control" required>
            </div>

            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <button class="btn btn-primary w-100 mt-2">Entrar</button>
        </form>

        <p class="text-center mt-3">
            ¿No tienes cuenta?  
            <a href="register.php" class="text-decoration-none">Registrarse</a>
        </p>
    </div>
</div>

<script src="validation.js"></script>
</body>
</html>

