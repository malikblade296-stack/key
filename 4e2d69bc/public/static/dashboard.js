import { api, fmtDateTime, copyText } from '/static/common.js';

const $ = (id) => document.getElementById(id);

const state = {
  data: null,
  timer: null,
  poll: null,
};

function fmtLeft(ms) {
  if (ms === null || ms === undefined) return 'Lifetime';
  let seconds = Math.max(0, Math.floor(ms / 1000));
  const days = Math.floor(seconds / 86400);
  seconds -= days * 86400;
  const hours = Math.floor(seconds / 3600);
  seconds -= hours * 3600;
  const minutes = Math.floor(seconds / 60);
  seconds -= minutes * 60;
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours || days) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  if (!days) parts.push(`${String(seconds).padStart(2, '0')}s`);
  return parts.join(' ');
}

function currentLeft() {
  if (!state.data) return null;
  const expires = state.data.expires_at;
  if (!expires) return null;
  return Math.max(0, Number(expires) - Date.now());
}

function render() {
  const data = state.data;
  if (!data) return;
  $('key-chip').textContent = data.key;
  $('license-key').textContent = data.key;
  $('license-plan').textContent = data.device_mode === 'single' ? 'Single device' : 'Unlimited devices';
  $('license-device').textContent =
    data.device_mode === 'single' ? (data.locked_hwid || 'Not bound yet') : 'Any device';
  $('license-activated').textContent = fmtDateTime(data.activated_at);
  $('license-expires').textContent = data.expires_at ? fmtDateTime(data.expires_at) : 'Never (lifetime)';
  $('license-left').textContent =
    fmtLeft(currentLeft()) + (data.timer_paused ? ' · paused' : '');
  $('device-state').textContent =
    data.device_mode === 'single'
      ? (data.locked_hwid ? `Locked to ${data.locked_hwid}` : 'Waiting for the first app authorization')
      : 'Unlimited — no device lock';

  const bound = data.device_mode === 'single' && Boolean(data.locked_hwid);
  $('bind-note').textContent =
    data.device_mode !== 'single'
      ? 'Unlimited keys work on any device.'
      : bound
        ? 'This key is locked. Ask the administrator to reset it to move to another device.'
        : 'The device ID arrives automatically when the INRI app authorizes this key.';

  $('sub-url').value = data.subscription_url || '';
  const encrypted = Boolean(data.encrypted_links);
  const link = encrypted ? (data.happ_link || '') : (data.subscription_url || '');
  $('sub-url-wrap').hidden = encrypted;
  $('encrypted-note').hidden = !encrypted;
  $('manual-config').hidden = encrypted;
  $('copy-crypt').dataset.copy = link;
  $('encrypt-error').textContent = data.encryption_error || '';
  $('copy-sub-btn').dataset.copy = link;
  $('copy-url-2').dataset.copy = link;
  $('test-config').textContent = data.config || '';
  $('copy-config').dataset.copy = data.config || '';
  $('local-proxy-hint').textContent = data.local_proxy_hint || 'python scripts/dev_proxy.py 8899';

  const online = Boolean(data.web_online);
  const status = $('web-status');
  status.classList.toggle('online', online);
  status.classList.toggle('offline', !online);
  status.innerHTML = `<span class="proxy-dot"></span>${online ? 'WEB ONLINE' : 'WEB OFFLINE'}`;
  const lastSub = data.last_sub_at ? fmtDateTime(data.last_sub_at) : '';
  const lastApp = data.last_app_at ? fmtDateTime(data.last_app_at) : '';
  const lastSeen = lastApp || lastSub;
  $('status-note').textContent = online
    ? `The INRI app is connected${lastSeen ? ` — last check-in ${lastSeen}` : ''}.`
    : lastSeen
      ? `The INRI app was last seen ${lastSeen}. Open it to reconnect.`
      : 'Waiting for the INRI app: press Connect INRI Proxy and authorize this key.';
  $('license-online').textContent = online
    ? 'Online — INRI app connected'
    : lastSeen
      ? `Offline — last seen ${lastSeen}`
      : 'Not connected yet';

  if (data.expires_at && Number(data.expires_at) <= Date.now()) {
    window.location.replace('/?expired=1');
  }
}

function startTimers() {
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (!state.data) return;
    $('license-left').textContent =
      fmtLeft(currentLeft()) + (state.data.timer_paused ? ' · paused' : '');
    if (state.data.expires_at && Number(state.data.expires_at) <= Date.now()) {
      window.location.replace('/?expired=1');
    }
  }, 1000);
  if (state.poll) clearInterval(state.poll);
  state.poll = setInterval(refresh, 30000);
}

async function refresh() {
  try {
    state.data = await api('/api/portal/session');
    render();
  } catch (error) {
    window.location.replace(error.status === 401 ? '/?expired=1' : '/');
  }
}

async function connectApp() {
  const data = state.data;
  const errorEl = $('app-error');
  errorEl.textContent = '';
  if (!data) return;
  $('connect-btn').disabled = true;
  try {
    const ticket = await api('/api/portal/app-ticket', { method: 'POST', body: {} });
    $('status-note').textContent =
      'Authorization sent. Opening the INRI app — keep it on the waiting screen.';
    window.location.href = ticket.deep_link;
    setTimeout(() => {
      if (!document.hidden) {
        errorEl.textContent =
          'If the app did not open, install the INRI app on this phone and press Connect again.';
      }
      $('connect-btn').disabled = false;
    }, 2000);
  } catch (error) {
    errorEl.textContent = error.message || 'Could not create an app authorization.';
    $('connect-btn').disabled = false;
  }
}

async function copySub() {
  const data = state.data;
  const link = data ? (data.encrypted_links ? data.happ_link : data.subscription_url) : '';
  await copyText(link, $('copy-sub-btn'));
}

async function boot() {
  $('connect-btn').addEventListener('click', connectApp);
  $('copy-sub-btn').addEventListener('click', copySub);
  $('copy-url-2').addEventListener('click', () => {
    const data = state.data;
    const link = data ? (data.encrypted_links ? data.happ_link : data.subscription_url) : '';
    copyText(link, $('copy-url-2'));
  });
  $('copy-crypt').addEventListener('click', () => {
    const data = state.data;
    copyText(data ? data.happ_link : '', $('copy-crypt'));
  });
  $('copy-config').addEventListener('click', () => copyText(state.data.config, $('copy-config')));
  $('signout-btn').addEventListener('click', async () => {
    try {
      await api('/api/portal/logout', { method: 'POST', body: {} });
    } catch {
      /* ignore */
    }
    window.location.replace('/');
  });

  await refresh();
  if (state.data) {
    startTimers();
    render();
  }
}

boot();
