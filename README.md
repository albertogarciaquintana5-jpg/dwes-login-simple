
<div align="center">
  <h1>🔒 dwes-login-simple</h1>
  <img src="inicio.png" alt="Pantalla de inicio" width="600"/>
</div>

Autenticación sencilla en PHP con buenas prácticas de seguridad, ideal para formación y proyectos DWES.

---

## ✨ Características
- Login y registro de usuarios
- Bloqueo tras varios intentos fallidos
- Expiración y regeneración segura de sesión
- Protección CSRF en formularios
- Panel seguro solo para usuarios autenticados

## 🚀 Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/albertogarciaquintana5-jpg/dwes-login-simple.git
   cd dwes-login-simple
   ```
2. Configura la base de datos:
   - Importa el archivo `migrations.sql` en tu base de datos MySQL.
   - Ajusta los datos de conexión en `db.php`.
3. Accede desde tu navegador a `index.php`.

## 🖼️ Capturas de pantalla

### Pantalla de inicio
Visualización tras iniciar sesión correctamente, mostrando el panel protegido.
<img src="inicio.png" alt="Pantalla de inicio" width="600"/>

### Login
Formulario para que los usuarios registrados accedan al sistema.
<img src="login.png" alt="Login" width="400"/>

### Registro
Formulario para crear una nueva cuenta de usuario.
<img src="registro.png" alt="Registro" width="400"/>

### Panel protegido
Solo accesible para usuarios autenticados.
<img src="inicio.png" alt="Panel protegido" width="600"/>

## 🛡️ Seguridad
- Contraseñas cifradas con `password_hash()`
- Prevención de ataques CSRF y fuerza bruta
- Expiración y regeneración segura de sesión

## 📁 Estructura del proyecto
```
dwes-login-simple/
├── db.php
├── functions.php
├── index.php
├── inicio.png
├── login.png
├── logout.php
├── migrations.sql
├── protected.php
├── README.md
├── register.php
├── registro.png
├── sensitive_action.php
├── validation.js
```

## 👤 Autor
Alberto García Quintana

---
> **Nota:** Si tienes problemas, revisa la configuración de la base de datos y tu entorno PHP.
