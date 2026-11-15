import {
  api,
  esc,
  money,
  fmtDateTime,
  fmtDuration,
  badge,
  toast,
  shorten,
  debounce,
  bindCopy,
} from '/static/common.js';

const $ = (id) => document.getElementById(id);

const state = {
  keys: [],
  resellers: [],
  stats: null,
  integration: null,
  keySeq: 0,
  resellerSeq: 0,
};

function showLogin() {
  $('login-view').hidden = false;
  $('app-view').hidden = true;
}

function showApp() {
  $('login-view').hidden = true;
  $('app-view').hidden = false;
}

function handleError(error, inlineEl) {
  if (error.status === 401) {
    showLogin();
    toast('Your session expired. Sign in again.', 'error');
    return;
  }
  if (inlineEl) {
    inlineEl.textContent = error.message;
    return;
  }
  toast(error.message || 'Request failed.', 'error');
}

function renderStats() {
  if (!state.stats) return;
  document.querySelectorAll('[data-stat]').forEach((el) => {
    const value = state.stats[el.dataset.stat];
    el.textContent = Number.isFinite(value) ? Number(value).toLocaleString() : '—';
  });
  if (Number.isFinite(state.stats.reseller_keys)) {
    $('reseller-summary').textContent =
      `${state.stats.reseller_keys.toLocaleString()} keys sold through resellers · ` +
      `${money(state.stats.reseller_balances_cents)} held in reseller balances`;
  }
}

async function refreshStats() {
  try {
    const data = await api('/api/admin/overview');
    state.stats = data.stats;
    renderStats();
  } catch (error) {
    handleError(error);
  }
}

function actionButton(action, label, id, style) {
  return `<button type="button" class="btn ${style || 'btn-ghost'} btn-xs" data-action="${action}" data-id="${id}">${label}</button>`;
}

function actionsFor(key) {
  const parts = [];
  if (key.status === 'active') parts.push(actionButton('suspend', 'Suspend', key.id));
  if (key.status === 'suspended') parts.push(actionButton('unsuspend', 'Unsuspend', key.id));
  if (key.status !== 'revoked') parts.push(actionButton('revoke', 'Revoke', key.id, 'btn-warn'));
  if (key.device_mode === 'single' && key.hwid) {
    parts.push(actionButton('reset-device', 'Reset device', key.id));
  }
  parts.push(actionButton('delete', 'Delete', key.id, 'btn-danger'));
  return `<div class="row-actions">${parts.join('')}</div>`;
}

function renderKeys() {
  const tbody = $('admin-keys-body');
  $('keys-count').textContent = state.keys.length
    ? `${state.keys.length.toLocaleString()} key${state.keys.length === 1 ? '' : 's'} shown`
    : 'No keys match this view';
  if (!state.keys.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="empty">No keys match this view yet.</td></tr>';
    return;
  }
  tbody.innerHTML = state.keys.map((key) => {
    let device = '<span class="muted">Any</span>';
    if (key.device_mode === 'single') {
      device = key.hwid
        ? `<span class="mono small" title="${esc(key.hwid)}">${esc(shorten(key.hwid, 22))}</span>`
        : '<span class="muted">Unbound</span>';
    }
    const lastCheck = key.last_verified_at
      ? `Last check: ${esc(fmtDateTime(key.last_verified_at))}`
      : 'Never verified';
    const expires = key.expires_at
      ? fmtDateTime(key.expires_at)
      : (key.duration_minutes === null ? 'Never' : '—');
    return `<tr>
      <td><div class="key-cell"><code>${esc(key.key)}</code><button type="button" class="copy-btn" data-copy="${esc(key.key)}">Copy</button></div></td>
      <td>${badge(key.state)}</td>
      <td>${key.device_mode === 'single' ? 'Single' : 'Unlimited'}</td>
      <td>${fmtDuration(key.duration_minutes)}</td>
      <td>${device}</td>
      <td>${fmtDateTime(key.activated_at)}</td>
      <td>${expires}</td>
      <td><span title="${lastCheck}">${Number(key.verify_count || 0).toLocaleString()}</span></td>
      <td><div class="origin"><span>${esc(key.created_by)}</span><small>${fmtDateTime(key.created_at)}</small></div></td>
      <td>${actionsFor(key)}</td>
    </tr>`;
  }).join('');
}

async function loadKeys() {
  const sequence = ++state.keySeq;
  const tbody = $('admin-keys-body');
  const params = new URLSearchParams();
  const search = $('key-search').value.trim();
  const status = $('key-status').value;
  if (search) params.set('search', search);
  if (status && status !== 'all') params.set('status', status);
  tbody.innerHTML = '<tr><td colspan="10" class="empty">Loading keys…</td></tr>';
  try {
    const suffix = params.toString() ? `?${params.toString()}` : '';
    const data = await api(`/api/admin/keys${suffix}`);
    if (sequence !== state.keySeq) return;
    state.keys = data.keys;
    renderKeys();
  } catch (error) {
    if (sequence !== state.keySeq) return;
    tbody.innerHTML = `<tr><td colspan="10" class="empty">${esc(error.message)}</td></tr>`;
    handleError(error);
  }
}

async function runKeyAction(button, action, key) {
  const prompts = {
    suspend: `Suspend key ${key.key}? Verification will fail until you unsuspend it.`,
    unsuspend: `Unsuspend key ${key.key}? It can be verified again.`,
    revoke: `Revoke key ${key.key}?\n\nThis permanently disables it and cannot be undone.`,
    'reset-device': `Reset the bound device for ${key.key}?\n\nThe key will bind to the next device that verifies it. Its timer does not restart.`,
    delete: `Delete key ${key.key} permanently?\n\nThis cannot be undone and resellers are not refunded.`,
  };
  if (!window.confirm(prompts[action] || 'Continue?')) return;
  button.disabled = true;
  try {
    if (action === 'delete') {
      await api(`/api/admin/keys/${key.id}`, { method: 'DELETE' });
    } else {
      await api(`/api/admin/keys/${key.id}/${action}`, { method: 'POST', body: {} });
    }
    const labels = {
      suspend: 'Key suspended.',
      unsuspend: 'Key unsuspended.',
      revoke: 'Key revoked.',
      'reset-device': 'Device binding cleared.',
      delete: 'Key deleted.',
    };
    toast(labels[action] || 'Key updated.', 'success');
    await Promise.all([loadKeys(), refreshStats()]);
  } catch (error) {
    handleError(error);
    button.disabled = false;
  }
}

function renderResellers() {
  const tbody = $('admin-resellers-body');
  if (!state.resellers.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No reseller accounts yet. Create one above.</td></tr>';
    return;
  }
  tbody.innerHTML = state.resellers.map((reseller) => {
    const status = reseller.active
      ? '<span class="badge badge-active">Enabled</span>'
      : '<span class="badge badge-revoked">Disabled</span>';
    return `<tr>
      <td><span class="mono">${esc(reseller.username)}</span></td>
      <td>${money(reseller.balance_cents)}</td>
      <td>${Number(reseller.key_count).toLocaleString()}</td>
      <td>${status}</td>
      <td>${fmtDateTime(reseller.created_at)}</td>
      <td>
        <div class="row-actions">
          <span class="adjust-group">
            <input type="number" step="0.01" class="mini-input" data-adjust-for="${reseller.id}" placeholder="± $" aria-label="Balance adjustment in dollars">
            <button type="button" class="btn btn-ghost btn-xs" data-action="adjust" data-id="${reseller.id}">Apply</button>
          </span>
          <button type="button" class="btn btn-ghost btn-xs" data-action="toggle" data-id="${reseller.id}">${reseller.active ? 'Disable' : 'Enable'}</button>
          <button type="button" class="btn btn-ghost btn-xs" data-action="password" data-id="${reseller.id}">Set password</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function loadResellers() {
  const sequence = ++state.resellerSeq;
  try {
    const data = await api('/api/admin/resellers');
    if (sequence !== state.resellerSeq) return;
    state.resellers = data.resellers;
    renderResellers();
    renderStats();
  } catch (error) {
    if (sequence !== state.resellerSeq) return;
    handleError(error);
  }
}

function showCreatedKeys(keys) {
  $('admin-result-panel').hidden = false;
  $('admin-result-keys').value = keys.join('\n');
  $('admin-copy-all').dataset.copy = keys.join('\n');
}

function initIntegration() {
  const origin = window.location.origin;
  $('verify-url').textContent = `${origin}/api/verify`;
  $('verify-sample').textContent =
    `curl -X POST ${origin}/api/verify \\\n` +
    '  -H "Content-Type: application/json" \\\n' +
    '  -d \'{"key":"7K2Q-F9XM-W3D4-H8PR-6T2V","hwid":"device-fingerprint"}\'';
  $('verify-php-url').textContent =
    `${origin}/api.php?key=YOUR-KEY&hwid=DEVICE-ID`;
  $('verify-php-get').textContent =
    '$result = json_decode(file_get_contents(\n' +
    `    '${origin}/api.php?key=7K2Q-F9XM-W3D4-H8PR-6T2V&hwid=device-fingerprint'\n` +
    '), true);\n\n' +
    "if (!empty($result['valid'])) {\n" +
    "    // licensed; timer started on the first successful check\n" +
    "    // expires_at is in milliseconds, or null for a lifetime key\n" +
    '}';
  $('verify-php').textContent =
    "<?php\n\n" +
    `$url = '${origin}/api/verify';\n` +
    "$body = json_encode(['key' => $licenseKey, 'hwid' => $hwid]);\n" +
    '$timestamp = (string) (int) floor(microtime(true) * 1000);\n' +
    '$nonce = bin2hex(random_bytes(16));\n' +
    "$signature = hash_hmac('sha256', $timestamp . '.' . $nonce . '.' . $body, $hmacSecret);\n\n" +
    '$ch = curl_init($url);\n' +
    'curl_setopt_array($ch, [\n' +
    '    CURLOPT_POST => true,\n' +
    '    CURLOPT_RETURNTRANSFER => true,\n' +
    '    CURLOPT_HTTPHEADER => [\n' +
    "        'Content-Type: application/json',\n" +
    "        'X-API-Key: ' . $apiKey,\n" +
    "        'X-Timestamp: ' . $timestamp,\n" +
    "        'X-Nonce: ' . $nonce,\n" +
    "        'X-Signature: ' . $signature,\n" +
    '    ],\n' +
    '    CURLOPT_POSTFIELDS => $body,\n' +
    ']);\n' +
    '$result = json_decode(curl_exec($ch), true);\n' +
    'curl_close($ch);';
}

function renderIntegration(data) {
  state.integration = data;
  $('require-api-key').checked = Boolean(data.require_api_key);
  $('require-hmac').checked = Boolean(data.require_hmac);
  $('require-basic').checked = Boolean(data.require_basic);
  $('allowed-ips').value = data.allowed_ips || '';

  const setChip = (id, configured, okText, missingText) => {
    const chip = $(id);
    chip.textContent = configured ? okText : missingText;
    chip.classList.toggle('cred-state-ok', Boolean(configured));
  };
  setChip('api-key-state', data.api_key_set, 'Generated', 'Not generated');
  setChip('hmac-state', data.hmac_set, 'Generated', 'Not generated');
  setChip('basic-state', data.basic_set, `User: ${data.basic_username}`, 'Not set');

  const active = [];
  if (data.require_api_key) active.push('API key');
  if (data.require_hmac) active.push('HMAC');
  if (data.require_basic) active.push('Basic');
  if (data.allowed_ips) active.push('IP allowlist');
  $('integration-status').textContent = active.length
    ? `${active.join(' + ')} required`
    : 'Open endpoint';
}

async function loadIntegration() {
  try {
    renderIntegration(await api('/api/admin/integration'));
  } catch (error) {
    handleError(error);
  }
}

function showGenerated(resultId, valueId, copyId, value) {
  $(resultId).hidden = false;
  $(valueId).value = value;
  $(copyId).dataset.copy = value;
  $(valueId).focus();
  $(valueId).select();
}

function initTabs() {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.tab;
      document.querySelectorAll('.tab').forEach((other) => {
        other.setAttribute('aria-selected', String(other === tab));
      });
      ['keys', 'resellers', 'settings'].forEach((section) => {
        $(`tab-${section}`).hidden = section !== name;
      });
      if (name === 'keys') loadKeys();
      if (name === 'resellers') loadResellers();
      if (name === 'settings') loadIntegration();
    });
  });
}

function initEvents() {
  bindCopy(document);
  initTabs();
  initIntegration();

  $('admin-login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('admin-login-error');
    errorEl.textContent = '';
    const username = $('admin-username').value.trim();
    const password = $('admin-password').value;
    if (!username || !password) {
      errorEl.textContent = 'Enter your username and password.';
      return;
    }
    const button = $('admin-login-btn');
    button.disabled = true;
    button.textContent = 'Unlocking…';
    try {
      await api('/api/login/admin', { method: 'POST', body: { username, password } });
      window.location.reload();
    } catch (error) {
      errorEl.textContent = error.message;
      button.disabled = false;
      button.textContent = 'Unlock console';
    }
  });

  $('admin-logout').addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST', body: {} });
    } catch {
      /* ignore */
    }
    window.location.reload();
  });

  $('overview-refresh').addEventListener('click', refreshStats);
  $('refresh-keys').addEventListener('click', loadKeys);
  $('refresh-resellers').addEventListener('click', loadResellers);

  $('key-search').addEventListener('input', debounce(loadKeys, 300));
  $('key-status').addEventListener('change', loadKeys);

  $('admin-keys-body').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const id = Number(button.dataset.id);
    const key = state.keys.find((item) => item.id === id);
    if (!key) return;
    runKeyAction(button, button.dataset.action, key);
  });

  $('admin-create-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('admin-create-error');
    errorEl.textContent = '';
    const button = $('admin-create-btn');

    let duration = null;
    const durationRaw = $('admin-duration').value.trim();
    if (durationRaw !== '') {
      const parsed = Number(durationRaw);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 10000000) {
        errorEl.textContent = 'Duration must be a whole number of minutes (1 to 10,000,000).';
        return;
      }
      duration = parsed;
    }

    const quantity = Number($('admin-quantity').value);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
      errorEl.textContent = 'Quantity must be a whole number between 1 and 100.';
      return;
    }

    const modeInput = document.querySelector('input[name="admin_device_mode"]:checked');
    const deviceMode = modeInput ? modeInput.value : 'single';

    button.disabled = true;
    button.textContent = 'Creating…';
    try {
      const data = await api('/api/admin/keys', {
        method: 'POST',
        body: { duration_minutes: duration, device_mode: deviceMode, quantity },
      });
      showCreatedKeys(data.keys);
      toast(`${data.keys.length} key${data.keys.length === 1 ? '' : 's'} created.`, 'success');
      await Promise.all([loadKeys(), refreshStats()]);
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Create keys';
    }
  });

  $('reseller-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('reseller-error');
    errorEl.textContent = '';
    const username = $('reseller-username').value.trim();
    const password = $('reseller-password').value;
    const rawBalance = $('reseller-balance').value.trim() || '0';
    const dollars = Number(rawBalance);
    if (!username || !password) {
      errorEl.textContent = 'Enter a username and password.';
      return;
    }
    if (!Number.isFinite(dollars) || dollars < 0) {
      errorEl.textContent = 'Starting balance must be zero or more.';
      return;
    }
    const button = $('reseller-create-btn');
    button.disabled = true;
    button.textContent = 'Creating…';
    try {
      await api('/api/admin/resellers', {
        method: 'POST',
        body: {
          username,
          password,
          balance_cents: Math.round(dollars * 100),
        },
      });
      $('reseller-username').value = '';
      $('reseller-password').value = '';
      $('reseller-balance').value = '0';
      toast('Reseller account created.', 'success');
      await Promise.all([loadResellers(), refreshStats()]);
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Create reseller';
    }
  });

  $('admin-resellers-body').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const id = Number(button.dataset.id);
    const reseller = state.resellers.find((item) => item.id === id);
    if (!reseller) return;
    const action = button.dataset.action;
    button.disabled = true;
    try {
      if (action === 'adjust') {
        const row = button.closest('tr');
        const input = row.querySelector('[data-adjust-for]');
        const raw = input.value.trim();
        const dollars = Number(raw);
        if (!raw || !Number.isFinite(dollars) || dollars === 0) {
          toast('Enter a non-zero dollar amount to add or subtract.', 'error');
          button.disabled = false;
          return;
        }
        const data = await api(`/api/admin/resellers/${id}/balance`, {
          method: 'POST',
          body: { delta_cents: Math.round(dollars * 100) },
        });
        input.value = '';
        toast(`Balance updated to ${money(data.balance_cents)}.`, 'success');
        await Promise.all([loadResellers(), refreshStats()]);
      } else if (action === 'toggle') {
        if (reseller.active && !window.confirm(`Disable ${reseller.username}? Their existing keys stay valid, but they cannot sign in or create keys.`)) {
          button.disabled = false;
          return;
        }
        await api(`/api/admin/resellers/${id}/toggle`, {
          method: 'POST',
          body: { active: !reseller.active },
        });
        toast(reseller.active ? 'Reseller disabled.' : 'Reseller enabled.', 'success');
        await Promise.all([loadResellers(), refreshStats()]);
      } else if (action === 'password') {
        const password = window.prompt(`New password for ${reseller.username} (minimum 8 characters):`);
        if (password === null) {
          button.disabled = false;
          return;
        }
        if (password.length < 8) {
          toast('Password must be at least 8 characters.', 'error');
          button.disabled = false;
          return;
        }
        await api(`/api/admin/resellers/${id}/password`, {
          method: 'POST',
          body: { password },
        });
        toast('Reseller password updated. Their sessions were signed out.', 'success');
      }
    } catch (error) {
      handleError(error);
      button.disabled = false;
    }
  });

  $('integration-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('integration-error');
    errorEl.textContent = '';
    const button = $('integration-save-btn');
    button.disabled = true;
    try {
      const data = await api('/api/admin/integration', {
        method: 'POST',
        body: {
          require_api_key: $('require-api-key').checked,
          require_hmac: $('require-hmac').checked,
          require_basic: $('require-basic').checked,
          allowed_ips: $('allowed-ips').value.trim(),
        },
      });
      renderIntegration(data);
      toast('API protection saved.', 'success');
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  $('generate-api-key').addEventListener('click', async () => {
    const button = $('generate-api-key');
    button.disabled = true;
    try {
      const data = await api('/api/admin/integration/credentials', {
        method: 'POST',
        body: { type: 'api_key' },
      });
      showGenerated('api-key-result', 'api-key-value', 'copy-api-key', data.api_key);
      toast('API key generated. Copy it now.', 'success');
      await loadIntegration();
    } catch (error) {
      handleError(error);
    } finally {
      button.disabled = false;
    }
  });

  $('generate-hmac').addEventListener('click', async () => {
    const button = $('generate-hmac');
    button.disabled = true;
    try {
      const data = await api('/api/admin/integration/credentials', {
        method: 'POST',
        body: { type: 'hmac' },
      });
      showGenerated('hmac-result', 'hmac-value', 'copy-hmac', data.hmac_secret);
      toast('HMAC secret generated. Copy it now.', 'success');
      await loadIntegration();
    } catch (error) {
      handleError(error);
    } finally {
      button.disabled = false;
    }
  });

  $('basic-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('basic-error');
    errorEl.textContent = '';
    const username = $('basic-username').value.trim();
    const password = $('basic-password').value;
    if (!username || !password) {
      errorEl.textContent = 'Enter a username and password.';
      return;
    }
    const button = $('basic-save-btn');
    button.disabled = true;
    try {
      await api('/api/admin/integration/credentials', {
        method: 'POST',
        body: { type: 'basic', username, password },
      });
      $('basic-password').value = '';
      toast('Basic credentials saved.', 'success');
      await loadIntegration();
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  $('password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('password-error');
    errorEl.textContent = '';
    const current = $('current-password').value;
    const next = $('new-password').value;
    const confirmValue = $('confirm-password').value;
    if (next.length < 8) {
      errorEl.textContent = 'New password must be at least 8 characters.';
      return;
    }
    if (next !== confirmValue) {
      errorEl.textContent = 'The new passwords do not match.';
      return;
    }
    const button = $('password-btn');
    button.disabled = true;
    try {
      await api('/api/admin/password', {
        method: 'POST',
        body: { current_password: current, new_password: next },
      });
      $('password-form').reset();
      toast('Admin password updated. Other sessions were signed out.', 'success');
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
}

async function boot() {
  initEvents();
  try {
    const overview = await api('/api/admin/overview');
    state.stats = overview.stats;
    renderStats();
    showApp();
    await Promise.all([loadKeys(), loadResellers(), loadIntegration()]);
  } catch (error) {
    showLogin();
    if (error.status !== 401) {
      toast(error.message || 'Could not open the console.', 'error');
    }
  }
}

boot();
