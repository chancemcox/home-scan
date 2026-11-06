const BASE = (document.querySelector('meta[name="homescan-base"]') || {}).content || '';
const url = (path) => BASE + path;
document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.getElementById('login-error');
  const button = event.target.querySelector('button[type=submit]');
  error.textContent = '';
  button.disabled = true;
  try {
    const response = await fetch(url('/api/login'), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        remember: document.getElementById('remember').checked
      })
    });
    const result = await response.json();
    if (!response.ok) throw Error(result.error || 'Sign in failed');
    location.replace(url('/'));
  } catch (e) {
    error.textContent = e.message;
  } finally {
    button.disabled = false;
  }
});
