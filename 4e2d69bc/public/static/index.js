import { api } from '/static/common.js';

const $ = (id) => document.getElementById(id);

const form = $('verify-form');
const keyInput = $('key');
const errorEl = $('verify-error');
const button = $('verify-btn');

function setBusy(busy) {
  button.disabled = busy;
  button.textContent = busy ? 'Verifying…' : 'Verify & continue';
}

function showError(message) {
  errorEl.textContent = message || '';
}

async function hasSession() {
  try {
    await api('/api/portal/session');
    return true;
  } catch {
    return false;
  }
}

function showMaintenance(message) {
  $('verify').hidden = true;
  $('maintenance-card').hidden = false;
  if (message) $('maintenance-message').textContent = message;
  form.hidden = true;
}

async function boot() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('expired') === '1') {
    showError('Your key expired or was revoked. Enter a new key to continue.');
  } else if (params.get('banned') === '1') {
    showError('This network or device has been blocked.');
  }

  if (await hasSession()) {
    window.location.replace('/dashboard');
    return;
  }

  fetch('/api/health')
    .then((response) => (response.ok ? response.json() : Promise.reject(new Error('offline'))))
    .then((health) => {
      $('api-dot').classList.add('online');
      $('api-status').textContent = 'Service online';
      const maintenance = health.maintenance;
      if (maintenance && maintenance.on && maintenance.block_resellers) {
        showMaintenance(maintenance.message);
      }
    })
    .catch(() => {
      $('api-dot').classList.add('offline');
      $('api-status').textContent = 'Service unreachable';
    });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');
  const key = keyInput.value.trim();
  if (!key) {
    showError('Enter your license key.');
    keyInput.focus();
    return;
  }
  setBusy(true);
  try {
    const data = await api('/api/portal/verify', {
      method: 'POST',
      body: { key },
    });
    if (data.valid) {
      button.textContent = 'Verified — opening…';
      window.location.replace('/dashboard');
      return;
    }
    showError(data.message || 'This key cannot be used.');
    setBusy(false);
  } catch (error) {
    if (error.status === 503) {
      showMaintenance(error.message);
    } else {
      showError(error.message || 'Could not verify this key.');
    }
    setBusy(false);
  }
});

boot();
