import { api } from '/static/common.js';

const form = document.getElementById('login-form');
const errorEl = document.getElementById('login-error');
const submitButton = form.querySelector('button[type="submit"]');

api('/api/reseller/me')
  .then(() => {
    window.location.replace('/reseller');
  })
  .catch(() => {});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorEl.textContent = '';
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  if (!username || !password) {
    errorEl.textContent = 'Enter your username and password.';
    return;
  }
  submitButton.disabled = true;
  const label = submitButton.textContent;
  submitButton.textContent = 'Signing in…';
  try {
    await api('/api/login/reseller', {
      method: 'POST',
      body: { username, password },
    });
    window.location.replace('/reseller');
  } catch (error) {
    errorEl.textContent = error.message || 'Could not sign in.';
    submitButton.disabled = false;
    submitButton.textContent = label;
  }
});

fetch('/api/health')
  .then((response) => (response.ok ? response.json() : Promise.reject(new Error('offline'))))
  .then(() => {
    document.getElementById('api-dot').classList.add('online');
    document.getElementById('api-status').textContent = 'API online';
  })
  .catch(() => {
    document.getElementById('api-dot').classList.add('offline');
    document.getElementById('api-status').textContent = 'API unreachable';
  });
