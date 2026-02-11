# dwes-login-simple

Autenticación sencilla en PHP con buenas prácticas de seguridad para formación.

## Descripción

Este proyecto proporciona un sistema de login para aplicaciones PHP, ideal para prácticas de DWES. Incorpora protección CSRF, gestión segura de sesiones, bloqueo tras intentos fallidos y validación robusta de contraseñas.

## Funcionalidades

- Página de inicio de sesión (login) y registro de usuarios.
- Bloqueo de cuenta tras varios intentos fallidos.
- Control de sesión expirada y regeneración de ID para mayor seguridad.
- Protección CSRF en formularios.
- Validación frontend y backend de usuario y contraseña.
- Panel seguro solo accesible para usuarios autenticados.

## Instalación

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/albertogarciaquintana5-jpg/dwes-login-simple.git
   cd dwes-login-simple
   ```

2. **Configura la base de datos:**
   - Crea una base de datos MySQL y una tabla `users` (y `login_attempts`).
   - Ajusta los datos de conexión en tu archivo de configuración.

3. **Instala dependencias (si las hubiera)**

   Este proyecto está listo para PHP; solo se requiere un entorno compatible.

4. **Configura el documento raíz (document root) de tu servidor para que apunte a la carpeta del proyecto.**

## Uso

- Accede a `index.php` y utiliza un usuario y contraseña válidos.
- El login aplica validaciones y protección desde el frontend (`validation.js`) y backend (PHP).
- Si tu usuario no está aprobado, no podrás acceder.
- La zona protegida está en `protected.php` y solo podrán acceder usuarios autenticados y con sesión activa.
- Puedes cerrar sesión desde `logout.php`.

## Seguridad

- Contraseñas cifradas y validación estricta.
- Prevención ataques CSRF y fuerza bruta.
- Expiración y regeneración segura de sesión.
- No se almacenan contraseñas ni sesiones inseguras.

## Créditos

Desarrollado por [albertogarciaquintana5-jpg](https://github.com/albertogarciaquintana5-jpg)

---

> **Nota:** Si tienes problemas, revisa la configuración de la base de datos y tu entorno PHP.
