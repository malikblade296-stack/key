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
      ? (data.locked_hwid ? `Locked to ${data.locked_hwid}` : 'Waiting for the first Happ connection')
      : 'Unlimited — no device lock';

  const bound = data.device_mode === 'single' && Boolean(data.locked_hwid);
  $('bind-note').textContent =
    data.device_mode !== 'single'
      ? 'Unlimited keys work on any device.'
      : bound
        ? 'This key is locked. Ask the administrator to reset it to move to another device.'
        : 'The device ID arrives automatically from the Happ connection — nothing to paste.';

  $('sub-url').value = data.subscription_url || '';
  $('copy-sub-btn').dataset.copy = data.subscription_url || '';
  $('copy-url-2').dataset.copy = data.subscription_url || '';
  $('test-config').textContent = data.config || '';
  $('copy-config').dataset.copy = data.config || '';
  $('local-proxy-hint').textContent = data.local_proxy_hint || 'python scripts/dev_proxy.py 8899';

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

function connectHapp() {
  const data = state.data;
  if (!data) return;
  $('status-note').textContent =
    'Opening Happ… the web page stays offline; Happ holds the tunnel.';
  window.location.href = data.happ_link;
}

async function copySub() {
  await copyText(state.data.subscription_url, $('copy-sub-btn'));
}

async function boot() {
  $('connect-btn').addEventListener('click', connectHapp);
  $('copy-sub-btn').addEventListener('click', copySub);
  $('copy-url-2').addEventListener('click', () => copyText(state.data.subscription_url, $('copy-url-2')));
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
