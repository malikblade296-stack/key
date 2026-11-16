import {
  api,
  esc,
  money,
  fmtDateTime,
  fmtDuration,
  badge,
  toast,
  shorten,
  bindCopy,
} from '/static/common.js';

const $ = (id) => document.getElementById(id);

const state = {
  balance: 0,
  spent: 0,
  keys: [],
  plans: [],
  busy: false,
  reseller: null,
  spoken: false,
};

const els = {
  maintenanceView: $('maintenance-view'),
  maintenanceMessage: $('maintenance-message'),
  loginView: $('login-view'),
  appView: $('app-view'),
  loginForm: $('login-form'),
  loginUsername: $('login-username'),
  loginPassword: $('login-password'),
  loginError: $('login-error'),
  loginBtn: $('login-btn'),
  welcomeName: $('welcome-name'),
  welcomeLine: $('welcome-line'),
  welcomeSound: $('welcome-sound'),
  usernameChip: $('username-chip'),
  balance: $('balance-amount'),
  prefix: $('prefix'),
  quantity: $('quantity'),
  plansGrid: $('plans-grid'),
  buyError: $('buy-error'),
  resultPanel: $('result-panel'),
  resultKeys: $('result-keys'),
  copyAll: $('copy-all'),
  keysBody: $('keys-body'),
  keysSummary: $('keys-summary'),
  refreshBtn: $('refresh-btn'),
  logoutBtn: $('logout-btn'),
};

function showLogin() {
  els.maintenanceView.hidden = true;
  els.loginView.hidden = false;
  els.appView.hidden = true;
}

function showApp() {
  els.maintenanceView.hidden = true;
  els.loginView.hidden = true;
  els.appView.hidden = false;
}

function showMaintenance(message) {
  els.loginView.hidden = true;
  els.appView.hidden = true;
  els.maintenanceView.hidden = false;
  els.maintenanceMessage.textContent = message || 'INRI PROXY ON MAINTENANCE — COME BACK LATER';
}

function renderBalance() {
  els.balance.textContent = money(state.balance);
}

function quantityValue() {
  const value = parseInt(els.quantity.value, 10);
  if (!Number.isFinite(value)) return 1;
  return Math.min(100, Math.max(1, value));
}

function planDuration(minutes) {
  return fmtDuration(minutes);
}

function planAllowed(plan) {
  const policy = (state.reseller && state.reseller.policy) || {};
  if (policy.allow_single === false && plan.device_mode === 'single') return false;
  if (policy.allow_unlimited === false && plan.device_mode === 'unlimited') return false;
  if (plan.duration_minutes === null && policy.allow_lifetime === false) return false;
  const allowed = policy.allowed_durations || [];
  if (plan.duration_minutes !== null && allowed.length && !allowed.includes(plan.duration_minutes)) {
    return false;
  }
  return true;
}

function renderPlans() {
  if (!state.plans.length) {
    els.plansGrid.innerHTML =
      '<p class="muted small">No plans are available right now. Check back later.</p>';
    return;
  }
  const quantity = quantityValue();
  els.plansGrid.innerHTML = state.plans.map((plan) => {
    const allowed = planAllowed(plan);
    const total = plan.price_cents * quantity;
    const affordable = state.balance >= total;
    const disabled = !allowed || !affordable || state.busy;
    let label = `Buy · ${money(total)}`;
    if (!allowed) label = 'Not available on this account';
    else if (!affordable) label = `Needs ${money(total)}`;
    return `<article class="plan-card${allowed ? '' : ' plan-card-off'}">
      <div class="plan-card-head">
        <h3>${esc(plan.label)}</h3>
        <strong>${money(plan.price_cents)}</strong>
      </div>
      <p class="plan-meta">${planDuration(plan.duration_minutes)} · ${plan.device_mode === 'single' ? 'Single device' : 'Unlimited devices'}</p>
      <p class="plan-hint">Timer starts on first activation.</p>
      <button type="button" class="btn btn-primary btn-block" data-buy="${plan.id}" ${disabled ? 'disabled' : ''}>${label}</button>
    </article>`;
  }).join('');
}

function applyAccount(data) {
  if (data.reseller) {
    state.reseller = data.reseller;
    state.balance = data.reseller.balance_cents;
  }
  if (Number.isFinite(data.spent_cents)) state.spent = data.spent_cents;
  renderBalance();
}

async function loadPlans() {
  try {
    const data = await api('/api/reseller/plans');
    applyAccount(data);
    state.plans = data.plans;
    renderPlans();
  } catch (error) {
    handleError(error);
  }
}

function speakWelcome(name) {
  if (!('speechSynthesis' in window) || !name) return;
  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(`Welcome ${name}`);
    utterance.rate = 0.96;
    utterance.pitch = 1.02;
    window.speechSynthesis.speak(utterance);
    state.spoken = true;
    try {
      sessionStorage.setItem('kg_welcome_' + name, '1');
    } catch {
      /* ignore */
    }
  } catch {
    /* speech is optional */
  }
}

function welcomeAlreadyPlayed(name) {
  try {
    return sessionStorage.getItem('kg_welcome_' + name) === '1';
  } catch {
    return false;
  }
}

function renderKeys() {
  const total = state.keys.length;
  const inUse = state.keys.filter((key) => key.state === 'active').length;
  els.keysSummary.textContent = total
    ? `${total} key${total === 1 ? '' : 's'} · ${inUse} in use · ${money(state.spent)} spent`
    : 'No keys yet';

  if (!total) {
    els.keysBody.innerHTML =
      '<tr><td colspan="7" class="empty">No keys yet. Buy your first key from a plan on the left.</td></tr>';
    return;
  }

  els.keysBody.innerHTML = state.keys.map((key) => {
    let device = '<span class="muted">Any device</span>';
    if (key.device_mode === 'single') {
      device = key.hwid
        ? `<span class="mono small" title="${esc(key.hwid)}">${esc(shorten(key.hwid))}</span>`
        : '<span class="muted">Not bound</span>';
    }
    const expires = key.expires_at
      ? fmtDateTime(key.expires_at)
      : (key.duration_minutes === null ? 'Never' : '—');
    return `<tr>
      <td><div class="key-cell"><code>${esc(key.key)}</code><button type="button" class="copy-btn" data-copy="${esc(key.key)}">Copy</button></div></td>
      <td>${badge(key.state)}</td>
      <td>${money(key.price_cents)}</td>
      <td>${device}</td>
      <td>${fmtDuration(key.duration_minutes)}</td>
      <td>${fmtDateTime(key.activated_at)}</td>
      <td>${expires}</td>
    </tr>`;
  }).join('');
}

async function loadKeys() {
  els.refreshBtn.disabled = true;
  try {
    const data = await api('/api/reseller/keys');
    state.keys = data.keys;
    applyAccount(data);
    renderKeys();
    renderPlans();
  } catch (error) {
    handleError(error);
  } finally {
    els.refreshBtn.disabled = false;
  }
}

async function maintenanceBlocked() {
  try {
    const response = await fetch('/api/health');
    if (!response.ok) return null;
    const data = await response.json();
    const maintenance = data.maintenance;
    if (maintenance && maintenance.on && maintenance.block_resellers) return maintenance;
    return null;
  } catch {
    return null;
  }
}

function handleError(error) {
  if (error.status === 401) {
    showLogin();
    return;
  }
  if (error.status === 403) {
    maintenanceBlocked().then((maintenance) => {
      if (maintenance) {
        showMaintenance(error.message || maintenance.message);
      } else {
        showLogin();
        toast(error.message, 'error');
      }
    });
    return;
  }
  toast(error.message || 'Request failed.', 'error');
}

function enterApp(me) {
  applyAccount(me);
  const name = me.reseller.display_name || me.reseller.username;
  els.welcomeName.textContent = name;
  els.welcomeLine.textContent = `Signed in as ${me.reseller.username}. Buy keys from your balance and track how they are used.`;
  els.usernameChip.textContent = me.reseller.username;
  renderBalance();
  renderPlans();
  showApp();
  if (!welcomeAlreadyPlayed(name)) {
    speakWelcome(name);
  }
  els.welcomeSound.addEventListener('click', () => speakWelcome(name));
  document.addEventListener(
    'click',
    () => {
      if (!state.spoken && !welcomeAlreadyPlayed(name)) speakWelcome(name);
    },
    { once: true }
  );
}

async function buyPlan(button) {
  if (state.busy) return;
  const plan = state.plans.find((item) => item.id === Number(button.dataset.buy));
  if (!plan) return;
  els.buyError.textContent = '';
  const quantity = quantityValue();
  const total = plan.price_cents * quantity;
  if (state.balance < total) {
    els.buyError.textContent = `Not enough balance. This order costs ${money(total)}.`;
    return;
  }
  let prefix = '';
  const prefixRaw = els.prefix.value.trim();
  if (prefixRaw !== '') {
    prefix = prefixRaw.toUpperCase().replace(/-/g, '');
    if (!/^[A-Z0-9]{1,12}$/.test(prefix)) {
      els.buyError.textContent = 'Prefix must be 1-12 letters or numbers.';
      return;
    }
  }
  state.busy = true;
  renderPlans();
  try {
    const data = await api('/api/reseller/keys', {
      method: 'POST',
      body: { plan_id: plan.id, quantity, prefix },
    });
    state.balance = data.balance_cents;
    state.spent += data.cost_cents;
    renderBalance();
    els.resultPanel.hidden = false;
    els.resultKeys.value = data.keys.join('\n');
    els.copyAll.dataset.copy = data.keys.join('\n');
    toast(`${data.keys.length} ${plan.label} key${data.keys.length === 1 ? '' : 's'} bought.`, 'success');
    await Promise.all([loadPlans(), loadKeys()]);
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      handleError(error);
    } else {
      els.buyError.textContent = error.message;
    }
    await loadPlans();
  } finally {
    state.busy = false;
    renderPlans();
  }
}

async function boot() {
  bindCopy(document);

  els.loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    els.loginError.textContent = '';
    const username = els.loginUsername.value.trim();
    const password = els.loginPassword.value;
    if (!username || !password) {
      els.loginError.textContent = 'Enter your username and password.';
      return;
    }
    els.loginBtn.disabled = true;
    els.loginBtn.textContent = 'Signing in…';
    try {
      await api('/api/login/reseller', { method: 'POST', body: { username, password } });
      window.location.replace('/reseller');
    } catch (error) {
      const maintenance = error.status === 403 ? await maintenanceBlocked() : null;
      if (maintenance) {
        showMaintenance(error.message || maintenance.message);
        return;
      }
      els.loginError.textContent = error.message;
      els.loginBtn.disabled = false;
      els.loginBtn.textContent = 'Sign in';
    }
  });

  els.logoutBtn.addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST', body: {} });
    } catch {
      /* ignore */
    }
    window.location.replace('/');
  });

  els.quantity.addEventListener('input', renderPlans);
  els.refreshBtn.addEventListener('click', loadKeys);
  els.resultKeys.addEventListener('focus', () => els.resultKeys.select());
  els.plansGrid.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-buy]');
    if (button) buyPlan(button);
  });

  const maintenance = await maintenanceBlocked();
  if (maintenance) {
    showMaintenance(maintenance.message);
    return;
  }

  showLogin();
  try {
    const me = await api('/api/reseller/me');
    enterApp(me);
    await Promise.all([loadPlans(), loadKeys()]);
  } catch (error) {
    if (error.status === 401) {
      showLogin();
    } else {
      handleError(error);
    }
  }
}

boot();
