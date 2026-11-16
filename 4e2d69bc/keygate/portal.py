import base64
import os
import re
import uuid
from urllib.parse import quote

from keygate import db, maintenance, security

ACCESS_COOKIE = 'kg_access'
ACCESS_TTL_MS = 12 * 60 * 60 * 1000
MAX_HWID_LENGTH = 256
MAX_KEY_LENGTH = 32
SUB_BASE_SETTING = 'public_base_url'


class PortalError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _mask(display):
    text = str(display or '')
    tail = text[-4:] if len(text) >= 4 else text
    return '••••-••••-••••-••••-{}'.format(tail)


def _find_key(conn, raw):
    normalized = security.normalize_key(raw)
    if not 20 <= len(normalized) <= 20 + 12:
        return None
    return conn.execute('SELECT * FROM keys WHERE key_norm = ?', (normalized,)).fetchone()


def key_state(row, now, paused_since=0):
    if row['status'] == 'revoked':
        return 'revoked'
    if row['status'] == 'suspended':
        return 'suspended'
    if row['expires_at'] is not None and maintenance.effective_expiry(
        row['expires_at'], now, paused_since, row['activated_at']
    ) <= now:
        return 'expired'
    if row['activated_at'] is None:
        return 'unused'
    return 'active'


def minutes_left(expires_at, now):
    if expires_at is None:
        return None
    return max(0, -(-(int(expires_at) - int(now)) // 60000))


def log_attempt(conn, row, ip, hwid, result, source):
    conn.execute(
        'INSERT INTO verify_log (key_id, key_display, ip, hwid, result, source, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (
            row['id'] if row is not None else None,
            row['key_display'] if row is not None else '',
            ip or '',
            (hwid or '')[:MAX_HWID_LENGTH],
            result,
            source,
            security.now_ms(),
        ),
    )


def _ban_row(conn, kind, value):
    if not value:
        return None
    return conn.execute(
        'SELECT id, note FROM bans WHERE kind = ? AND LOWER(value) = LOWER(?)',
        (kind, value),
    ).fetchone()


def banned(conn, ip, hwid=None):
    if ip and _ban_row(conn, 'ip', ip):
        return 'ip'
    if hwid and _ban_row(conn, 'hwid', hwid):
        return 'hwid'
    return None


def _access_cookie(token, ttl_ms):
    parts = [
        '{}={}'.format(ACCESS_COOKIE, token),
        'HttpOnly',
        'SameSite=Lax',
        'Path=/',
        'Max-Age={}'.format(max(1, ttl_ms // 1000)),
    ]
    if os.environ.get('COOKIE_SECURE') == '1':
        parts.append('Secure')
    return '; '.join(parts)


def clear_access_cookie():
    parts = [
        '{}='.format(ACCESS_COOKIE),
        'HttpOnly',
        'SameSite=Lax',
        'Path=/',
        'Max-Age=0',
    ]
    if os.environ.get('COOKIE_SECURE') == '1':
        parts.append('Secure')
    return '; '.join(parts)


def create_access(conn, row, hwid, ip, paused_since=0):
    now = security.now_ms()
    expires = now + ACCESS_TTL_MS
    key_expires = maintenance.effective_expiry(
        row['expires_at'], now, paused_since, row['activated_at']
    )
    if key_expires is not None:
        expires = min(expires, key_expires)
    token = security.random_token()
    conn.execute(
        'DELETE FROM access_sessions WHERE expires_at <= ?', (now,)
    )
    conn.execute(
        'INSERT INTO access_sessions (token_hash, key_id, hwid, ip, created_at, expires_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (security.sha256_hex(token), row['id'], hwid or row['hwid'], ip, now, expires),
    )
    return token, max(1000, expires - now)


def read_access(conn, token, ip):
    if not token or len(token) > 200:
        return None
    if maintenance.block_resellers(conn):
        return None
    token_hash = security.sha256_hex(token)
    access = conn.execute(
        'SELECT * FROM access_sessions WHERE token_hash = ?', (token_hash,)
    ).fetchone()
    if access is None:
        return None
    now = security.now_ms()
    if access['expires_at'] <= now:
        conn.execute('DELETE FROM access_sessions WHERE token_hash = ?', (token_hash,))
        return None
    row = conn.execute('SELECT * FROM keys WHERE id = ?', (access['key_id'],)).fetchone()
    if row is None:
        conn.execute('DELETE FROM access_sessions WHERE token_hash = ?', (token_hash,))
        return None
    if key_state(row, now, maintenance.paused_at(conn)) not in ('unused', 'active'):
        conn.execute('DELETE FROM access_sessions WHERE token_hash = ?', (token_hash,))
        return None
    if banned(conn, ip, access['hwid']):
        conn.execute('DELETE FROM access_sessions WHERE token_hash = ?', (token_hash,))
        return None
    return {'token_hash': token_hash, 'session': dict(access), 'key': row}


def access_token_from(handler):
    header = handler.headers.get('Cookie')
    if not header:
        return None
    from http.cookies import SimpleCookie

    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:
        return None
    if ACCESS_COOKIE not in jar:
        return None
    return jar[ACCESS_COOKIE].value


def public_base_url(conn, ctx):
    stored = db.get_setting(conn, SUB_BASE_SETTING) or ''
    if stored:
        return stored.rstrip('/')
    env = (os.environ.get('PUBLIC_BASE_URL') or '').strip()
    if env:
        return env.rstrip('/')
    return ctx['base_url'].rstrip('/')


def proxy_config(conn):
    mode = db.get_setting(conn, 'happ_mode') or 'test'
    host = (db.get_setting(conn, 'happ_host') or '').strip()
    raw_port = (db.get_setting(conn, 'happ_port') or '443').strip()
    try:
        port = int(raw_port)
    except ValueError:
        port = 443
    if not 1 <= port <= 65535:
        port = 443
    if mode != 'live' or not host:
        host = '127.0.0.1'
        port = 443
        mode = 'test'
    return {
        'mode': mode,
        'host': host,
        'port': port,
        'uuid': (db.get_setting(conn, 'happ_uuid') or '').strip(),
        'sni': (db.get_setting(conn, 'happ_sni') or '').strip() or host,
        'path': (db.get_setting(conn, 'happ_path') or '/inri').strip() or '/inri',
        'remark': (db.get_setting(conn, 'happ_remark') or 'INRI Proxy').strip() or 'INRI Proxy',
    }


def vless_uri(conn, key_norm, label=None):
    cfg = proxy_config(conn)
    node_id = cfg['uuid']
    if not node_id:
        node_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'inri-proxy:' + (key_norm or 'test')))
    path = cfg['path'] if cfg['path'].startswith('/') else '/' + cfg['path']
    remark = label or cfg['remark']
    if cfg['mode'] == 'test':
        remark = '{} TEST'.format(remark)
    query = (
        'encryption=none&security=tls&sni={sni}&fp=chrome&type=ws&host={sni}&path={path}'
    ).format(sni=quote(cfg['sni'], safe=''), path=quote(path, safe=''))
    return 'vless://{}@{}:{}?{}#{}'.format(
        node_id, cfg['host'], cfg['port'], query, quote(remark, safe='')
    )


def subscription_url(conn, ctx, row, hwid=None):
    base = public_base_url(conn, ctx)
    url = '{}/sub/{}'.format(base, quote(row['key_display'], safe=''))
    device = hwid or row['hwid']
    if row['device_mode'] == 'single' and device:
        url += '?hwid=' + quote(device, safe='')
    return url


def happ_link(url):
    encoded = base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')
    return 'happ://add/' + encoded


def _state_payload(conn, ctx, row, access, now):
    paused = maintenance.paused_at(conn)
    expires_at = maintenance.effective_expiry(
        row['expires_at'], now, paused, row['activated_at']
    )
    device = access['session'].get('hwid') or row['hwid']
    sub_url = subscription_url(conn, ctx, row, device)
    cfg = proxy_config(conn)
    return {
        'authenticated': True,
        'key': _mask(row['key_display']),
        'key_full': row['key_display'],
        'device_mode': row['device_mode'],
        'locked_hwid': row['hwid'],
        'session_hwid': device,
        'activated_at': row['activated_at'],
        'expires_at': expires_at,
        'minutes_remaining': minutes_left(expires_at, now),
        'timer_paused': bool(paused),
        'maintenance_on': maintenance.is_on(conn),
        'maintenance_message': maintenance.message(conn),
        'subscription_url': sub_url,
        'happ_link': happ_link(sub_url),
        'config': vless_uri(conn, row['key_norm']),
        'proxy_mode': cfg['mode'],
        'web_proxy': 'offline',
        'local_proxy_hint': (
            'python scripts/dev_proxy.py 8899  (then set your browser HTTP proxy to '
            '127.0.0.1:8899)'
        ),
        'server_time': now,
    }


def verify_portal(ctx):
    conn = ctx['conn']
    ip = ctx['ip']
    now = security.now_ms()
    if maintenance.block_resellers(conn):
        raise PortalError(503, maintenance.message(conn))
    allowed, retry = security.take_rate('portal:{}'.format(ip), 30, 60)
    if not allowed:
        raise PortalError(429, 'Too many attempts. Try again in {} seconds.'.format(retry))

    body = ctx['body']
    raw_key = body.get('key')
    raw_key = raw_key.strip() if isinstance(raw_key, str) else ''
    if not raw_key:
        raise PortalError(400, 'Enter your license key.')
    if len(raw_key) > MAX_KEY_LENGTH + 12:
        raw_key = raw_key[:MAX_KEY_LENGTH + 12]

    hwid_value = body.get('hwid')
    hwid = hwid_value.strip() if isinstance(hwid_value, str) else ''
    if len(hwid) > MAX_HWID_LENGTH:
        log_attempt(conn, None, ip, '', 'invalid_hwid', 'portal')
        return {'valid': False, 'error': 'invalid_hwid', 'message': 'That device id is too long.'}

    row = _find_key(conn, raw_key)
    ban = banned(conn, ip, hwid)
    if ban:
        log_attempt(conn, row, ip, hwid, 'banned_' + ban, 'portal')
        return {
            'valid': False,
            'error': 'banned',
            'message': 'This network or device has been blocked by the administrator.',
        }

    if row is None:
        log_attempt(conn, None, ip, hwid, 'invalid_key', 'portal')
        return {'valid': False, 'error': 'invalid_key', 'message': 'This key does not exist.'}

    state = key_state(row, now, maintenance.paused_at(conn))
    if state in ('revoked', 'suspended', 'expired'):
        log_attempt(conn, row, ip, hwid, state, 'portal')
        messages = {
            'revoked': 'This key has been revoked.',
            'suspended': 'This key is suspended.',
            'expired': 'This key has expired. Get a new key to continue.',
        }
        return {'valid': False, 'error': state, 'message': messages[state]}

    if row['device_mode'] == 'single':
        if hwid and row['hwid'] and row['hwid'] != hwid:
            log_attempt(conn, row, ip, hwid, 'device_mismatch', 'portal')
            return {
                'valid': False,
                'error': 'device_mismatch',
                'message': 'This key is locked to another device.',
            }

    activated_at = row['activated_at']
    expires_at = row['expires_at']
    if activated_at is None:
        activated_at = now
        expires_at = (
            None if row['duration_minutes'] is None else now + row['duration_minutes'] * 60_000
        )
    new_hwid = row['hwid']
    if row['device_mode'] == 'single' and not new_hwid:
        new_hwid = hwid
    conn.execute(
        'UPDATE keys SET hwid = ?, activated_at = ?, expires_at = ?, last_verified_at = ?, '
        'verify_count = verify_count + 1 WHERE id = ?',
        (new_hwid, activated_at, expires_at, now, row['id']),
    )
    log_attempt(conn, row, ip, new_hwid or hwid, 'valid', 'portal')

    refreshed = conn.execute('SELECT * FROM keys WHERE id = ?', (row['id'],)).fetchone()
    token, ttl = create_access(
        conn, refreshed, new_hwid or hwid, ip, maintenance.paused_at(conn)
    )
    ctx['cookies'].append(_access_cookie(token, ttl))
    payload = _state_payload(conn, ctx, refreshed, {'session': {'hwid': new_hwid or hwid}}, now)
    payload.update({'valid': True, 'message': 'Key verified. Welcome to INRI Proxy.'})
    return payload


def session_info(ctx):
    conn = ctx['conn']
    access = read_access(conn, ctx.get('access_token'), ctx['ip'])
    if access is None:
        raise PortalError(401, 'Enter a valid key to open the dashboard.')
    return _state_payload(conn, ctx, access['key'], access, security.now_ms())


def bind_device(ctx):
    conn = ctx['conn']
    access = read_access(conn, ctx.get('access_token'), ctx['ip'])
    if access is None:
        raise PortalError(401, 'Enter a valid key to open the dashboard.')
    row = access['key']
    raw = ctx['body'].get('hwid')
    hwid = raw.strip() if isinstance(raw, str) else ''
    if not hwid:
        raise PortalError(400, 'Paste the device ID shown in Happ.')
    if len(hwid) > MAX_HWID_LENGTH:
        raise PortalError(400, 'That device id is too long.')
    if banned(conn, ctx['ip'], hwid):
        raise PortalError(403, 'This device has been blocked by the administrator.')
    if row['device_mode'] == 'single':
        if row['hwid'] and row['hwid'] != hwid:
            raise PortalError(409, 'This key is already locked to a different device.')
        conn.execute('UPDATE keys SET hwid = ? WHERE id = ?', (hwid, row['id']))
    conn.execute(
        'UPDATE access_sessions SET hwid = ? WHERE token_hash = ?',
        (hwid, access['token_hash']),
    )
    refreshed = conn.execute('SELECT * FROM keys WHERE id = ?', (row['id'],)).fetchone()
    access['session']['hwid'] = hwid
    return _state_payload(conn, ctx, refreshed, access, security.now_ms())


def logout_portal(ctx):
    conn = ctx['conn']
    token = ctx.get('access_token')
    if token:
        conn.execute(
            'DELETE FROM access_sessions WHERE token_hash = ?',
            (security.sha256_hex(token),),
        )
    ctx['cookies'].append(clear_access_cookie())
    return {'ok': True}


def subscription(conn, raw_key, params, ip, user_agent, headers=None):
    """Happ fetches this URL on every refresh. Errors invalidate the profile."""
    now = security.now_ms()
    allowed, _ = security.take_rate('sub:{}'.format(ip), 120, 60)
    if not allowed:
        return 429, {}, 'Too many requests.'
    if maintenance.block_resellers(conn):
        return 503, {}, maintenance.message(conn)
    row = _find_key(conn, raw_key)
    raw_hwid = params.get('hwid')
    hwid = raw_hwid.strip() if isinstance(raw_hwid, str) else ''
    if not hwid and headers is not None:
        for name in ('x-hwid', 'x-device-id', 'x-hwid-id'):
            value = headers.get(name)
            if isinstance(value, str) and value.strip():
                hwid = value.strip()[:MAX_HWID_LENGTH + 1]
                break
    if len(hwid) > MAX_HWID_LENGTH:
        log_attempt(conn, row, ip, '', 'invalid_hwid', 'sub')
        return 400, {}, 'Invalid device id.'
    ban = banned(conn, ip, hwid)
    if ban:
        log_attempt(conn, row, ip, hwid, 'banned_' + ban, 'sub')
        return 403, {}, 'Access blocked.'
    if row is None:
        log_attempt(conn, None, ip, hwid, 'invalid_key', 'sub')
        return 404, {}, 'Unknown key.'
    state = key_state(row, now, maintenance.paused_at(conn))
    if state in ('revoked', 'suspended', 'expired'):
        log_attempt(conn, row, ip, hwid, state, 'sub')
        return 410 if state == 'expired' else 403, {}, 'Key is no longer valid.'
    if row['device_mode'] == 'single':
        if hwid and row['hwid'] and row['hwid'] != hwid:
            log_attempt(conn, row, ip, hwid, 'device_mismatch', 'sub')
            return 403, {}, 'Device does not match this key.'

    activated_at = row['activated_at']
    expires_at = row['expires_at']
    if activated_at is None:
        activated_at = now
        expires_at = (
            None if row['duration_minutes'] is None else now + row['duration_minutes'] * 60_000
        )
    new_hwid = row['hwid']
    if row['device_mode'] == 'single' and not new_hwid:
        new_hwid = hwid or None
    conn.execute(
        'UPDATE keys SET hwid = ?, activated_at = ?, expires_at = ?, last_verified_at = ?, '
        'verify_count = verify_count + 1 WHERE id = ?',
        (new_hwid, activated_at, expires_at, now, row['id']),
    )
    log_attempt(conn, row, ip, new_hwid or hwid, 'valid', 'sub')

    projected_expires = maintenance.effective_expiry(
        expires_at, now, maintenance.paused_at(conn), activated_at
    )
    config = vless_uri(conn, row['key_norm'])
    lines = [
        '#profile-title: INRI Proxy',
        '#profile-update-interval: 6',
        '#subscription-always-hwid-enable: 1',
    ]
    if projected_expires:
        lines.append(
            '#subscription-userinfo: upload=0; download=0; total=0; expire={}'.format(
                int(projected_expires // 1000)
            )
        )
    lines.append(config)
    headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'profile-title': 'INRI Proxy',
        'profile-update-interval': '6',
    }
    if projected_expires:
        headers['subscription-userinfo'] = 'upload=0; download=0; total=0; expire={}'.format(
            int(projected_expires // 1000)
        )
    return 200, headers, '\n'.join(lines) + '\n'


def admin_proxy_state(conn):
    cfg = proxy_config(conn)
    return {
        'mode': cfg['mode'],
        'host': db.get_setting(conn, 'happ_host') or '',
        'port': db.get_setting(conn, 'happ_port') or '443',
        'uuid': db.get_setting(conn, 'happ_uuid') or '',
        'sni': db.get_setting(conn, 'happ_sni') or '',
        'path': db.get_setting(conn, 'happ_path') or '/inri',
        'remark': db.get_setting(conn, 'happ_remark') or 'INRI Proxy',
        'public_base_url': db.get_setting(conn, SUB_BASE_SETTING) or '',
        'test_config': vless_uri(conn, 'test'),
        'local_proxy_hint': (
            'For the local web-proxy test run: python scripts/dev_proxy.py 8899 '
            'then set your browser HTTP proxy to 127.0.0.1:8899'
        ),
    }
