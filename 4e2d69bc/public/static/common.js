const currency = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
});

const STATE_META = {
  unused: ['Unused', 'unused'],
  active: ['Active', 'active'],
  expired: ['Expired', 'expired'],
  suspended: ['Suspended', 'suspended'],
  revoked: ['Revoked', 'revoked'],
};

export async function api(path, options = {}) {
  const method = options.method || 'GET';
  const init = {
    method,
    credentials: 'same-origin',
    headers: {},
  };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    const error = new Error('Cannot reach the server. Check your connection.');
    error.status = 0;
    throw error;
  }
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  if (!response.ok) {
    const error = new Error((data && data.error) || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}

export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[ch]));
}

export function money(cents) {
  return currency.format((Number(cents) || 0) / 100);
}

export function fmtDateTime(ms) {
  if (!ms) return '—';
  const date = new Date(Number(ms));
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function fmtDuration(minutes) {
  if (minutes === null || minutes === undefined) return 'Lifetime';
  const value = Number(minutes);
  if (!Number.isFinite(value) || value <= 0) return `${minutes} min`;
  if (value % 1440 === 0) {
    const days = value / 1440;
    return `${days} day${days === 1 ? '' : 's'}`;
  }
  if (value % 60 === 0) {
    const hours = value / 60;
    return `${hours} hour${hours === 1 ? '' : 's'}`;
  }
  return `${value} min`;
}

export function badge(state) {
  const meta = STATE_META[state] || ['Unknown', 'expired'];
  return `<span class="badge badge-${meta[1]}">${meta[0]}</span>`;
}

export function shorten(value, max = 20) {
  const text = String(value || '');
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '…';
}

export function debounce(fn, delay = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

let toastStack = null;

export function toast(message, type = 'info') {
  if (!toastStack) {
    toastStack = document.createElement('div');
    toastStack.className = 'toast-stack';
    toastStack.setAttribute('role', 'status');
    toastStack.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastStack);
  }
  const item = document.createElement('div');
  item.className = `toast toast-${type}`;
  item.textContent = message;
  toastStack.appendChild(item);
  setTimeout(() => item.remove(), 4500);
}

function legacyCopy(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.className = 'clipboard-helper';
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  area.remove();
  if (!copied) throw new Error('copy failed');
}

export async function copyText(text, button) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      legacyCopy(text);
    }
    if (button) {
      const original = button.dataset.originalLabel || button.textContent;
      button.dataset.originalLabel = original;
      button.textContent = 'Copied';
      clearTimeout(button._copyTimer);
      button._copyTimer = setTimeout(() => {
        button.textContent = original;
      }, 1200);
    }
  } catch {
    toast('Could not copy to the clipboard.', 'error');
  }
}

export function bindCopy(root = document) {
  root.addEventListener('click', (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) return;
    copyText(button.getAttribute('data-copy') || '', button);
  });
}
