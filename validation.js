
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  const username = document.getElementById('username');
  const password = document.getElementById('password');

  function validPassword(pw) {
    const min = 8, max = 15;
    if (pw.length < min || pw.length > max) return false;
    if (!/[A-Z]/.test(pw)) return false;
    if (!/[a-z]/.test(pw)) return false;
    if (!/[0-9]/.test(pw)) return false;
    if (!/[!@#$%^&*\-_\+=\.,\?:;]/.test(pw)) return false;
    if (/[\'"\\\/<>=()]/.test(pw)) return false;
    return true;
  }

  form.addEventListener('submit', (e) => {
    const u = username.value.trim();
    const p = password.value;

    if (u.length < 8 || u.length > 15) {
      e.preventDefault();
      alert('El idusuario debe tener entre 8 y 15 caracteres.');
      return;
    }
    if (!validPassword(p)) {
      e.preventDefault();
      alert('La contraseña debe tener 8-15 chars, mayúscula, minúscula, número y caracter especial permitido.');
      return;
    }
  });
});
