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

const TRACKS = ['/static/phonk-01.wav', '/static/phonk-02.wav', '/static/phonk-03.wav'];
const audio = $('phonk-audio');
const phonkToggle = $('phonk-toggle');
const phonkLabel = $('phonk-label');

let trackIndex = 0;
let phonkArmed = false;
let phonkWanted = true;
let trackFailures = 0;

function renderPhonk() {
  const playing = audio && !audio.paused;
  if (phonkToggle) phonkToggle.setAttribute('aria-pressed', playing ? 'true' : 'false');
  if (phonkLabel) {
    phonkLabel.textContent = playing
      ? `Phonk · ${trackIndex + 1}/${TRACKS.length}`
      : 'Phonk · off';
  }
}

function playPhonk() {
  audio.src = TRACKS[trackIndex];
  audio.volume = 0.32;
  const started = audio.play();
  if (started && started.catch) {
    started.catch(() => renderPhonk());
  }
  renderPhonk();
}

function startPhonk() {
  if (!audio) return;
  phonkArmed = true;
  phonkWanted = true;
  playPhonk();
}

function stopPhonk() {
  if (!audio) return;
  phonkArmed = true;
  phonkWanted = false;
  audio.pause();
  renderPhonk();
}

if (audio && phonkToggle) {
  audio.addEventListener('ended', () => {
    trackIndex = (trackIndex + 1) % TRACKS.length;
    if (phonkWanted) playPhonk();
  });
  audio.addEventListener('playing', renderPhonk);
  audio.addEventListener('pause', renderPhonk);
  audio.addEventListener('canplay', () => {
    trackFailures = 0;
  });
  audio.addEventListener('error', () => {
    trackFailures += 1;
    if (trackFailures >= TRACKS.length) {
      stopPhonk();
      if (phonkLabel) phonkLabel.textContent = 'Phonk · unavailable';
      return;
    }
    trackIndex = (trackIndex + 1) % TRACKS.length;
    if (phonkWanted) playPhonk();
  });

  phonkToggle.addEventListener('click', () => {
    if (audio.paused) startPhonk();
    else stopPhonk();
  });

  const arm = (event) => {
    if (event.target && event.target.closest && event.target.closest('#phonk-toggle')) return;
    document.removeEventListener('pointerdown', arm);
    document.removeEventListener('keydown', arm);
    startPhonk();
  };
  document.addEventListener('pointerdown', arm);
  document.addEventListener('keydown', arm);
  renderPhonk();
}

boot();
