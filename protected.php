<?php
require_once 'functions.php';
secure_session_start();

if (is_session_expired()) {
    secure_logout();
    die('Sesión expirada. Por favor inicia sesión de nuevo.');
}

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

maybe_regenerate_session_id(15*60);
update_session_activity();

echo "Bienvenido, " . htmlspecialchars($_SESSION['username']);
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Panel protegido</title>

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
<body style="background:#f1f5f9;">

<div class="container p-5">

    <div class="alert alert-success text-center">
        Bienvenido <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>
    </div>

    <div class="card p-4 shadow-sm">
        <h4>Zona Segura</h4>
        <p>Esta información solo aparece para usuarios autenticados.</p>

        <form method="post" action="sensitive_action.php" class="mt-3">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <button class="btn btn-danger">Acción peligrosa</button>
        </form>

        <a href="logout.php" class="btn btn-secondary mt-3">Cerrar Sesión</a>
    </div>

</div>

</body>
</html>

