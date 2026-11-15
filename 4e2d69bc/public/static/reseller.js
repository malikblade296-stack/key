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
  PRICE_CENTS,
} from '/static/common.js';

const $ = (id) => document.getElementById(id);

const state = {
  balance: 0,
  keys: [],
  busy: false,
};

const els = {
  welcomeName: $('welcome-name'),
  usernameChip: $('username-chip'),
  balance: $('balance-amount'),
  form: $('create-form'),
  duration: $('duration'),
  prefix: $('prefix'),
  quantity: $('quantity'),
  createBtn: $('create-btn'),
  createError: $('create-error'),
  costLabel: $('cost-label'),
  costTotal: $('cost-total'),
  resultPanel: $('result-panel'),
  resultKeys: $('result-keys'),
  copyAll: $('copy-all'),
  keysBody: $('keys-body'),
  keysSummary: $('keys-summary'),
  refreshBtn: $('refresh-btn'),
  logoutBtn: $('logout-btn'),
};

function renderBalance() {
  els.balance.textContent = money(state.balance);
}

function currentQuantity() {
  const value = parseInt(els.quantity.value, 10);
  if (!Number.isFinite(value)) return 1;
  return Math.min(100, Math.max(1, value));
}

function updateCost() {
  const quantity = currentQuantity();
  const total = quantity * PRICE_CENTS;
  els.costLabel.textContent = `${money(PRICE_CENTS)} × ${quantity}`;
  els.costTotal.textContent = money(total);
  els.costTotal.classList.toggle('short', state.balance < total);
  els.createBtn.disabled = state.busy || state.balance < total;
}

function handleError(error) {
  if (error.status === 401) {
    window.location.replace('/');
    return;
  }
  if (error.status === 403) {
    toast(error.message, 'error');
    setTimeout(() => window.location.replace('/'), 1600);
    return;
  }
  toast(error.message || 'Request failed.', 'error');
}

function renderKeys() {
  const total = state.keys.length;
  const inUse = state.keys.filter((key) => key.state === 'active').length;
  els.keysSummary.textContent = total
    ? `${total} key${total === 1 ? '' : 's'} · ${inUse} in use`
    : 'No keys generated yet';

  if (!total) {
    els.keysBody.innerHTML = '<tr><td colspan="6" class="empty">No keys yet. Generate your first key on the left.</td></tr>';
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
    state.balance = data.reseller.balance_cents;
    renderBalance();
    renderKeys();
    updateCost();
  } catch (error) {
    handleError(error);
  } finally {
    els.refreshBtn.disabled = false;
  }
}

async function boot() {
  bindCopy(document);
  els.logoutBtn.addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST', body: {} });
    } catch {
      /* ignore */
    }
    window.location.replace('/');
  });

  els.quantity.addEventListener('input', updateCost);
  els.refreshBtn.addEventListener('click', loadKeys);
  els.resultKeys.addEventListener('focus', () => els.resultKeys.select());

  try {
    const me = await api('/api/reseller/me');
    state.balance = me.reseller.balance_cents;
    els.welcomeName.textContent = me.reseller.username;
    els.usernameChip.textContent = me.reseller.username;
    renderBalance();
    updateCost();
    await loadKeys();
  } catch (error) {
    handleError(error);
  }

  els.form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (state.busy) return;
    els.createError.textContent = '';

    let duration = null;
    const durationRaw = els.duration.value.trim();
    if (durationRaw !== '') {
      const parsed = Number(durationRaw);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 10000000) {
        els.createError.textContent = 'Duration must be a whole number of minutes (1 to 10,000,000).';
        return;
      }
      duration = parsed;
    }

    let prefix = '';
    const prefixRaw = els.prefix.value.trim();
    if (prefixRaw !== '') {
      prefix = prefixRaw.toUpperCase().replace(/-/g, '');
      if (!/^[A-Z0-9]{1,12}$/.test(prefix)) {
        els.createError.textContent = 'Prefix must be 1-12 letters or numbers.';
        return;
      }
    }

    const quantity = Number(els.quantity.value);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
      els.createError.textContent = 'Quantity must be a whole number between 1 and 100.';
      return;
    }

    const modeInput = els.form.querySelector('input[name="device_mode"]:checked');
    const deviceMode = modeInput ? modeInput.value : 'single';
    const total = quantity * PRICE_CENTS;
    if (state.balance < total) {
      els.createError.textContent = `Not enough balance. This order costs ${money(total)}.`;
      return;
    }

    state.busy = true;
    els.createBtn.textContent = 'Generating…';
    updateCost();

    try {
      const data = await api('/api/reseller/keys', {
        method: 'POST',
        body: {
          duration_minutes: duration,
          device_mode: deviceMode,
          quantity,
          prefix,
        },
      });
      state.balance = data.balance_cents;
      renderBalance();
      els.resultPanel.hidden = false;
      els.resultKeys.value = data.keys.join('\n');
      els.copyAll.dataset.copy = data.keys.join('\n');
      toast(`${data.keys.length} key${data.keys.length === 1 ? '' : 's'} generated.`, 'success');
      await loadKeys();
    } catch (error) {
      if (error.status === 401 || error.status === 403) {
        handleError(error);
      } else {
        els.createError.textContent = error.message;
      }
    } finally {
      state.busy = false;
      els.createBtn.textContent = 'Generate keys';
      updateCost();
    }
  });
}

boot();
