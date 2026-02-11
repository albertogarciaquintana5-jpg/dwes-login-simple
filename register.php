<?php
require_once 'functions.php';
secure_session_start();
generate_csrf_token();
update_session_activity();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) die('CSRF inválido');

    $username = sanitize_username($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);

    if (empty($username) || empty($password)) {
        die('Datos faltan.');
    }
    if (!validate_password_policy($password)) {
        die('Contraseña no cumple la política.');
    }

    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, email, is_approved) VALUES (?, ?, ?, ?)");
    try {
        $stmt->execute([$username, $password_hash, $email, 0]);
        echo "Registro realizado. Espera aprobación de administrador.";
    } catch (PDOException $e) {
        echo "Error al registrar: " . htmlentities($e->getMessage());
    }
}
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Registro</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
    body {
        background: #f2f4f8;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .card-custom {
        border-radius: 15px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    .btn-primary {
        border-radius: 10px;
        padding: 10px 20px;
    }
    .container-center {
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
    }
</style>
</head>

<body style="background:#eef2f5;">

<div class="container d-flex justify-content-center align-items-center" style="height:100vh;">
    <div class="card p-4 shadow-lg" style="width:420px; border-radius:20px;">
        <h3 class="text-center mb-3">Registro de Usuario</h3>

        <form method="post" action="register.php">
            <div class="mb-3">
                <label class="form-label">Usuario</label>
                <input name="username" class="form-control" required>
            </div>

            <div class="mb-3">
                <label class="form-label">Correo</label>
                <input type="email" name="email" class="form-control">
            </div>

            <div class="mb-3">
                <label class="form-label">Contraseña</label>
                <input type="password" name="password" class="form-control" required>
            </div>

            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <button class="btn btn-success w-100 mt-2">Crear Cuenta</button>
        </form>

        <p class="text-center mt-3">
            ¿Ya tienes cuenta?  
            <a href="index.php">Iniciar sesión</a>
        </p>
    </div>
</div>

</body>
</html>

