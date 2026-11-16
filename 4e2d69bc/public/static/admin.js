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
  access: null,
  proxy: null,
  plans: [],
  maintenance: null,
  policyReseller: null,
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

function policySummary(policy) {
  if (!policy) return 'Single · Unlimited';
  const parts = [];
  if (policy.allow_single) parts.push('Single');
  if (policy.allow_unlimited) parts.push('Unlimited');
  if (policy.allow_lifetime) parts.push('Lifetime');
  const durations = policy.allowed_durations || [];
  if (durations.length) parts.push(`${durations.length} duration${durations.length === 1 ? '' : 's'}`);
  return parts.length ? parts.join(' · ') : 'No keys';
}

function renderResellers() {
  const tbody = $('admin-resellers-body');
  if (!state.resellers.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No reseller accounts yet. Create one above.</td></tr>';
    return;
  }
  tbody.innerHTML = state.resellers.map((reseller) => {
    const status = reseller.active
      ? '<span class="badge badge-active">Enabled</span>'
      : '<span class="badge badge-revoked">Disabled</span>';
    const name = reseller.display_name || reseller.username;
    return `<tr>
      <td><div class="origin"><span>${esc(name)}</span><small>@${esc(reseller.username)}</small></div></td>
      <td>${money(reseller.balance_cents)}</td>
      <td>${Number(reseller.key_count).toLocaleString()}</td>
      <td><div class="type-cell"><span class="small">${esc(policySummary(reseller.policy))}</span><button type="button" class="btn btn-ghost btn-xs" data-action="policy" data-id="${reseller.id}">Edit</button></div></td>
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

function openPolicy(reseller) {
  state.policyReseller = reseller;
  const policy = reseller.policy || {};
  $('policy-reseller').textContent = reseller.display_name || reseller.username;
  $('policy-single').checked = Boolean(policy.allow_single);
  $('policy-unlimited').checked = Boolean(policy.allow_unlimited);
  $('policy-lifetime').checked = Boolean(policy.allow_lifetime);
  $('policy-durations').value = (policy.allowed_durations || []).join(', ');
  $('policy-error').textContent = '';
  $('policy-save').disabled = false;
  $('policy-save').textContent = 'Save key types';
  $('policy-dialog').showModal();
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

function planDuration(minutes) {
  return fmtDuration(minutes);
}

function renderPlans() {
  const tbody = $('plans-body');
  $('plans-count').textContent = state.plans.length
    ? `${state.plans.length} plan${state.plans.length === 1 ? '' : 's'} in the catalogue`
    : 'No plans yet';
  if (!state.plans.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No plans yet. Add one on the left.</td></tr>';
    return;
  }
  tbody.innerHTML = state.plans.map((plan) => `<tr>
    <td><strong>${esc(plan.label)}</strong></td>
    <td>${planDuration(plan.duration_minutes)}</td>
    <td>${money(plan.price_cents)}</td>
    <td>${plan.device_mode === 'single' ? 'Single' : 'Unlimited'}</td>
    <td>${plan.active
      ? '<span class="badge badge-active">Live</span>'
      : '<span class="badge badge-revoked">Hidden</span>'}</td>
    <td><div class="row-actions">
      <button type="button" class="btn btn-ghost btn-xs" data-plan-action="edit" data-id="${plan.id}">Edit</button>
      <button type="button" class="btn btn-ghost btn-xs" data-plan-action="toggle" data-id="${plan.id}">${plan.active ? 'Hide' : 'Publish'}</button>
      <button type="button" class="btn btn-danger btn-xs" data-plan-action="delete" data-id="${plan.id}">Delete</button>
    </div></td>
  </tr>`).join('');
}

function resetPlanForm() {
  $('plan-id').value = '';
  $('plan-label').value = '';
  $('plan-duration').value = '';
  $('plan-price').value = '';
  $('plan-mode').value = 'unlimited';
  $('plan-active').checked = true;
  $('plan-form-title').textContent = 'Add a plan';
  $('plan-save-btn').textContent = 'Add plan';
  $('plan-cancel-btn').hidden = true;
  $('plan-error').textContent = '';
}

function editPlan(plan) {
  $('plan-id').value = String(plan.id);
  $('plan-label').value = plan.label;
  $('plan-duration').value =
    plan.duration_minutes === null ? '' : String(plan.duration_minutes / 1440);
  $('plan-price').value = (plan.price_cents / 100).toFixed(2);
  $('plan-mode').value = plan.device_mode;
  $('plan-active').checked = Boolean(plan.active);
  $('plan-form-title').textContent = `Edit “${plan.label}”`;
  $('plan-save-btn').textContent = 'Save plan';
  $('plan-cancel-btn').hidden = false;
  $('plan-error').textContent = '';
  $('plan-label').focus();
}

function planPayload(plan, overrides) {
  return {
    label: plan.label,
    duration_minutes: plan.duration_minutes,
    price_cents: plan.price_cents,
    device_mode: plan.device_mode,
    active: plan.active,
    ...overrides,
  };
}

async function loadPlans() {
  try {
    const data = await api('/api/admin/plans');
    state.plans = data.plans;
    renderPlans();
  } catch (error) {
    handleError(error);
  }
}

function renderMaintenance(data) {
  state.maintenance = data;
  $('maintenance-on').checked = Boolean(data.maintenance);
  $('maintenance-pause').checked = Boolean(data.pause_keys);
  $('maintenance-block').checked = Boolean(data.block_resellers);
  $('maintenance-message').value = data.message || '';
  $('maintenance-pause').disabled = !data.maintenance;
  $('maintenance-block').disabled = !data.maintenance;
  $('maintenance-status').textContent = data.maintenance
    ? (data.pause_keys ? 'ON — key timers are paused' : 'ON — site open, timers running')
    : 'OFF — normal service';
}

async function loadMaintenance() {
  try {
    const data = await api('/api/admin/maintenance');
    renderMaintenance(data.maintenance);
  } catch (error) {
    handleError(error);
  }
}

function accessBadge(result) {
  const label = String(result || 'unknown').replace(/_/g, ' ');
  if (result === 'valid') return `<span class="badge badge-active">${esc(label)}</span>`;
  if (String(result).startsWith('banned')) {
    return `<span class="badge badge-revoked">${esc(label)}</span>`;
  }
  return `<span class="badge badge-expired">${esc(label)}</span>`;
}

function renderAccess() {
  if (!state.access) return;
  const { events, bans, summary } = state.access;
  $('access-summary').textContent =
    `${Number(summary.last_24h).toLocaleString()} checks in the last 24h · ` +
    `${Number(summary.last_24h_valid).toLocaleString()} passed · ` +
    `${Number(summary.bans).toLocaleString()} blocked value${summary.bans === 1 ? '' : 's'}`;

  const bansBody = $('bans-body');
  if (!bans.length) {
    bansBody.innerHTML = '<tr><td colspan="5" class="empty">No banned IPs or devices.</td></tr>';
  } else {
    bansBody.innerHTML = bans.map((ban) => `<tr>
      <td>${ban.kind === 'ip'
        ? '<span class="badge badge-unused">IP</span>'
        : '<span class="badge badge-suspended">HWID</span>'}</td>
      <td class="mono small">${esc(ban.value)}</td>
      <td>${ban.note ? esc(ban.note) : '<span class="muted">—</span>'}</td>
      <td>${fmtDateTime(ban.created_at)}</td>
      <td><button type="button" class="btn btn-ghost btn-xs" data-unban="${ban.id}">Unban</button></td>
    </tr>`).join('');
  }

  const eventsBody = $('access-body');
  if (!events.length) {
    eventsBody.innerHTML = '<tr><td colspan="6" class="empty">No verification attempts recorded yet.</td></tr>';
    return;
  }
  eventsBody.innerHTML = events.map((item) => `<tr>
    <td>${fmtDateTime(item.created_at)}</td>
    <td><span class="badge ${item.source === 'sub' ? 'badge-suspended' : 'badge-unused'}">${esc(item.source)}</span></td>
    <td><code class="small">${esc(item.key_display || '—')}</code></td>
    <td class="mono small">${esc(item.ip || '—')}</td>
    <td class="mono small">${item.hwid
      ? `<span title="${esc(item.hwid)}">${esc(shorten(item.hwid, 24))}</span>`
      : '<span class="muted">—</span>'}</td>
    <td>${accessBadge(item.result)}</td>
  </tr>`).join('');
}

async function loadAccess() {
  try {
    state.access = await api('/api/admin/access?limit=200');
    renderAccess();
  } catch (error) {
    handleError(error);
  }
}

function renderProxy(data) {
  state.proxy = data;
  $('proxy-mode').value = data.mode;
  $('proxy-host').value = data.host || '';
  $('proxy-port').value = data.port || '443';
  $('proxy-uuid').value = data.uuid || '';
  $('proxy-sni').value = data.sni || '';
  $('proxy-path').value = data.path || '/inri';
  $('proxy-remark').value = data.remark || 'INRI Proxy';
  $('proxy-base').value = data.public_base_url || '';
  $('proxy-test').textContent = data.test_config || '—';
  $('copy-proxy-test').dataset.copy = data.test_config || '';
  $('proxy-hint').textContent = data.local_proxy_hint || '';
  $('proxy-error').textContent = '';
}

async function loadProxy() {
  try {
    renderProxy(await api('/api/admin/proxy'));
  } catch (error) {
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
  $('php-action-url').textContent =
    `${origin}/api.php?action=validate&key=YOUR-KEY&hwid=DEVICE-ID`;
  $('php-action-sample').textContent =
    `GET ${origin}/api.php?action=validate&key=7K2Q-F9XM-W3D4-H8PR-6T2V&hwid=device-fingerprint\n\n` +
    '{"success":true,"valid":true,"status":"valid","key":"7K2Q-F9XM-W3D4-H8PR-6T2V",\n' +
    ' "hwid":"device-fingerprint","minutes_remaining":41,\n' +
    ' "expires_at":"2026-11-15T21:30:00.000Z","single_device":true}\n\n' +
    'GET .../api.php?action=info&key=YOUR-KEY        (read only, no timer)\n' +
    'POST .../api.php  action=generate&duration=60&mode=single\n' +
    '   header: X-API-Key: YOUR-API-KEY';
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
  const sections = ['keys', 'resellers', 'plans', 'maintenance', 'access', 'proxy', 'settings'];
  const loaders = {
    keys: loadKeys,
    resellers: loadResellers,
    plans: loadPlans,
    maintenance: loadMaintenance,
    access: loadAccess,
    proxy: loadProxy,
    settings: loadIntegration,
  };
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.tab;
      document.querySelectorAll('.tab').forEach((other) => {
        other.setAttribute('aria-selected', String(other === tab));
      });
      sections.forEach((section) => {
        $(`tab-${section}`).hidden = section !== name;
      });
      if (loaders[name]) loaders[name]();
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
  $('refresh-plans').addEventListener('click', loadPlans);

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
    const displayName = $('reseller-name').value.trim();
    const username = $('reseller-username').value.trim();
    const password = $('reseller-password').value;
    const rawBalance = $('reseller-balance').value.trim() || '0';
    const dollars = Number(rawBalance);
    if (displayName.length < 2) {
      errorEl.textContent = 'Add a name for the reseller (at least 2 characters).';
      return;
    }
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
          display_name: displayName,
          username,
          password,
          balance_cents: Math.round(dollars * 100),
        },
      });
      $('reseller-name').value = '';
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
    if (action === 'policy') {
      openPolicy(reseller);
      return;
    }
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

  $('plan-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('plan-error');
    errorEl.textContent = '';
    const label = $('plan-label').value.trim();
    if (!label) {
      errorEl.textContent = 'Name the plan (for example: 1 day).';
      return;
    }
    let duration = null;
    const rawDuration = $('plan-duration').value.trim();
    if (rawDuration !== '') {
      const days = Number(rawDuration);
      if (!Number.isFinite(days) || days <= 0) {
        errorEl.textContent = 'Duration must be a number of days, or blank for lifetime.';
        return;
      }
      duration = Math.round(days * 1440);
      if (duration < 1 || duration > 10000000) {
        errorEl.textContent = 'Duration must be between 1 minute and 10,000,000 minutes.';
        return;
      }
    }
    const price = Number($('plan-price').value);
    if (!Number.isFinite(price) || price < 0) {
      errorEl.textContent = 'Enter a price of $0 or more.';
      return;
    }
    const planId = $('plan-id').value;
    const body = {
      label,
      duration_minutes: duration,
      price_cents: Math.round(price * 100),
      device_mode: $('plan-mode').value,
      active: $('plan-active').checked,
    };
    const button = $('plan-save-btn');
    button.disabled = true;
    try {
      const data = await api(planId ? `/api/admin/plans/${planId}` : '/api/admin/plans', {
        method: 'POST',
        body,
      });
      toast(data.message || 'Plan saved.', 'success');
      resetPlanForm();
      await loadPlans();
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  $('plan-cancel-btn').addEventListener('click', resetPlanForm);

  $('plans-body').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-plan-action]');
    if (!button) return;
    const plan = state.plans.find((item) => item.id === Number(button.dataset.id));
    if (!plan) return;
    const action = button.dataset.planAction;
    if (action === 'edit') {
      editPlan(plan);
      return;
    }
    if (action === 'delete') {
      if (!window.confirm(`Delete the plan “${plan.label}”?\n\nKeys already sold keep their duration; the plan just disappears from the shop.`)) {
        return;
      }
      button.disabled = true;
      try {
        await api(`/api/admin/plans/${plan.id}/delete`, { method: 'POST', body: {} });
        toast('Plan deleted.', 'success');
        resetPlanForm();
        await loadPlans();
      } catch (error) {
        handleError(error);
        button.disabled = false;
      }
      return;
    }
    if (action === 'toggle') {
      button.disabled = true;
      try {
        await api(`/api/admin/plans/${plan.id}`, {
          method: 'POST',
          body: planPayload(plan, { active: !plan.active }),
        });
        toast(plan.active ? 'Plan hidden from resellers.' : 'Plan published.', 'success');
        await loadPlans();
      } catch (error) {
        handleError(error);
        button.disabled = false;
      }
    }
  });

  $('maintenance-on').addEventListener('change', () => {
    const on = $('maintenance-on').checked;
    $('maintenance-pause').disabled = !on;
    $('maintenance-block').disabled = !on;
  });

  $('maintenance-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('maintenance-error');
    errorEl.textContent = '';
    const button = $('maintenance-save');
    button.disabled = true;
    button.textContent = 'Saving…';
    try {
      const data = await api('/api/admin/maintenance', {
        method: 'POST',
        body: {
          on: $('maintenance-on').checked,
          pause_keys: $('maintenance-pause').checked,
          block_resellers: $('maintenance-block').checked,
          message: $('maintenance-message').value.trim(),
        },
      });
      renderMaintenance(data.maintenance);
      toast(
        data.maintenance.maintenance ? 'Maintenance mode is ON.' : 'Maintenance mode is OFF.',
        'success',
      );
      await refreshStats();
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Save maintenance settings';
    }
  });

  $('policy-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const reseller = state.policyReseller;
    if (!reseller) return;
    const errorEl = $('policy-error');
    errorEl.textContent = '';
    const allowSingle = $('policy-single').checked;
    const allowUnlimited = $('policy-unlimited').checked;
    const allowLifetime = $('policy-lifetime').checked;
    if (!allowSingle && !allowUnlimited) {
      errorEl.textContent = 'Allow single-device keys, unlimited-device keys, or both.';
      return;
    }
    const durations = [];
    const raw = $('policy-durations').value.trim();
    if (raw) {
      for (const part of raw.split(',')) {
        const text = part.trim();
        if (!text) continue;
        const value = Number(text);
        if (!Number.isInteger(value) || value < 1 || value > 10000000) {
          errorEl.textContent = 'Durations are whole minutes (1 to 10,000,000), separated by commas.';
          return;
        }
        if (!durations.includes(value)) durations.push(value);
      }
      if (durations.length > 16) {
        errorEl.textContent = 'Keep the duration list to 16 entries or fewer.';
        return;
      }
    }
    const button = $('policy-save');
    button.disabled = true;
    button.textContent = 'Saving…';
    try {
      await api(`/api/admin/resellers/${reseller.id}/policy`, {
        method: 'POST',
        body: {
          allow_single: allowSingle,
          allow_unlimited: allowUnlimited,
          allow_lifetime: allowLifetime,
          allowed_durations: durations,
        },
      });
      $('policy-dialog').close();
      toast('Key types updated.', 'success');
      await loadResellers();
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Save key types';
    }
  });

  $('policy-cancel').addEventListener('click', () => $('policy-dialog').close());

  $('refresh-access').addEventListener('click', loadAccess);

  $('ban-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('ban-error');
    errorEl.textContent = '';
    const kind = $('ban-kind').value;
    const value = $('ban-value').value.trim();
    const note = $('ban-note').value.trim();
    if (!value) {
      errorEl.textContent = 'Enter the IP address or device id to ban.';
      return;
    }
    const button = $('ban-btn');
    button.disabled = true;
    try {
      await api('/api/admin/bans', { method: 'POST', body: { kind, value, note } });
      $('ban-value').value = '';
      $('ban-note').value = '';
      toast(`${kind === 'ip' ? 'IP address' : 'Device'} banned.`, 'success');
      await loadAccess();
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  $('bans-body').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-unban]');
    if (!button) return;
    const banId = Number(button.dataset.unban);
    if (!banId || !window.confirm('Remove this ban? The IP or device can verify again.')) return;
    button.disabled = true;
    try {
      await api(`/api/admin/bans/${banId}`, { method: 'DELETE' });
      toast('Ban removed.', 'success');
      await loadAccess();
    } catch (error) {
      handleError(error);
      button.disabled = false;
    }
  });

  $('proxy-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorEl = $('proxy-error');
    errorEl.textContent = '';
    const button = $('proxy-save-btn');
    button.disabled = true;
    button.textContent = 'Saving…';
    try {
      const data = await api('/api/admin/proxy', {
        method: 'POST',
        body: {
          mode: $('proxy-mode').value,
          host: $('proxy-host').value.trim(),
          port: $('proxy-port').value.trim(),
          uuid: $('proxy-uuid').value.trim(),
          sni: $('proxy-sni').value.trim(),
          path: $('proxy-path').value.trim(),
          remark: $('proxy-remark').value.trim(),
          public_base_url: $('proxy-base').value.trim(),
        },
      });
      renderProxy(data);
      toast('Proxy settings saved. New subscriptions use them immediately.', 'success');
    } catch (error) {
      if (error.status === 401) handleError(error);
      else errorEl.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Save proxy';
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
