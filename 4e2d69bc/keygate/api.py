import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import threading
import time

from keygate import db, maintenance, portal, security, sessions

MAX_QUANTITY = 100
MAX_DURATION_MINUTES = 10_000_000
MAX_HWID_LENGTH = 256
MAX_PREFIX_LENGTH = 12
HMAC_WINDOW_MS = 300_000

_nonce_lock = threading.Lock()
_nonce_cache = {}

_dummy_hash = None


class ApiError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or []


def init_dummy_hash():
    global _dummy_hash
    _dummy_hash = security.hash_password(secrets.token_hex(16))


def _get_dummy_hash():
    global _dummy_hash
    if _dummy_hash is None:
        init_dummy_hash()
    return _dummy_hash


class Route:
    def __init__(self, method, path, handler, role=None, login=False, verify=False):
        self.method = method
        self.path = path
        self.handler = handler
        self.role = role
        self.login = login
        self.verify = verify
        names = []
        parts = []
        for part in path.strip('/').split('/'):
            if part.startswith(':'):
                names.append(part[1:])
                parts.append('([^/]+)')
            else:
                parts.append(re.escape(part))
        self.regex = re.compile('^/' + '/'.join(parts) + '$')
        self.param_names = names


ROUTES = [
    Route('GET', '/api/health', lambda ctx: health(ctx)),
    Route('POST', '/api/login/admin', lambda ctx: login_admin(ctx), login=True),
    Route('POST', '/api/login/reseller', lambda ctx: login_reseller(ctx), login=True),
    Route('POST', '/api/logout', lambda ctx: logout(ctx)),
    Route('POST', '/api/verify', lambda ctx: verify_key(ctx), verify=True),
    Route('GET', '/api.php', lambda ctx: verify_php(ctx), verify=True),
    Route('POST', '/api.php', lambda ctx: verify_php(ctx), verify=True),

    Route('POST', '/api/portal/verify', lambda ctx: portal.verify_portal(ctx)),
    Route('GET', '/api/portal/session', lambda ctx: portal.session_info(ctx)),
    Route('POST', '/api/portal/bind', lambda ctx: portal.bind_device(ctx)),
    Route('POST', '/api/portal/logout', lambda ctx: portal.logout_portal(ctx)),

    Route('GET', '/api/reseller/me', lambda ctx: reseller_me(ctx), role='reseller'),
    Route('GET', '/api/reseller/keys', lambda ctx: reseller_keys(ctx), role='reseller'),
    Route('GET', '/api/reseller/plans', lambda ctx: reseller_plans(ctx), role='reseller'),
    Route('POST', '/api/reseller/keys', lambda ctx: reseller_create_keys(ctx), role='reseller'),

    Route('GET', '/api/admin/plans', lambda ctx: admin_plans(ctx), role='admin'),
    Route('POST', '/api/admin/plans', lambda ctx: admin_plan_save(ctx), role='admin'),
    Route('POST', '/api/admin/plans/:id', lambda ctx: admin_plan_save(ctx), role='admin'),
    Route('POST', '/api/admin/plans/:id/delete', lambda ctx: admin_plan_delete(ctx), role='admin'),
    Route('GET', '/api/admin/maintenance', lambda ctx: admin_maintenance(ctx), role='admin'),
    Route('POST', '/api/admin/maintenance', lambda ctx: admin_maintenance_save(ctx), role='admin'),

    Route('GET', '/api/admin/overview', lambda ctx: admin_overview(ctx), role='admin'),
    Route('GET', '/api/admin/keys', lambda ctx: admin_keys(ctx), role='admin'),
    Route('POST', '/api/admin/keys', lambda ctx: admin_create_keys(ctx), role='admin'),
    Route('POST', '/api/admin/keys/:id/suspend', lambda ctx: admin_suspend_key(ctx), role='admin'),
    Route('POST', '/api/admin/keys/:id/unsuspend', lambda ctx: admin_unsuspend_key(ctx), role='admin'),
    Route('POST', '/api/admin/keys/:id/revoke', lambda ctx: admin_revoke_key(ctx), role='admin'),
    Route('POST', '/api/admin/keys/:id/reset-device', lambda ctx: admin_reset_device(ctx), role='admin'),
    Route('DELETE', '/api/admin/keys/:id', lambda ctx: admin_delete_key(ctx), role='admin'),

    Route('GET', '/api/admin/resellers', lambda ctx: admin_resellers(ctx), role='admin'),
    Route('POST', '/api/admin/resellers', lambda ctx: admin_create_reseller(ctx), role='admin'),
    Route('POST', '/api/admin/resellers/:id/balance', lambda ctx: admin_adjust_balance(ctx), role='admin'),
    Route('POST', '/api/admin/resellers/:id/toggle', lambda ctx: admin_toggle_reseller(ctx), role='admin'),
    Route('POST', '/api/admin/resellers/:id/password', lambda ctx: admin_set_reseller_password(ctx), role='admin'),
    Route('POST', '/api/admin/resellers/:id/policy', lambda ctx: admin_reseller_policy(ctx), role='admin'),
    Route('GET', '/api/admin/access', lambda ctx: admin_access(ctx), role='admin'),
    Route('POST', '/api/admin/bans', lambda ctx: admin_ban(ctx), role='admin'),
    Route('DELETE', '/api/admin/bans/:id', lambda ctx: admin_unban(ctx), role='admin'),
    Route('GET', '/api/admin/proxy', lambda ctx: portal.admin_proxy_state(ctx['conn']), role='admin'),
    Route('POST', '/api/admin/proxy', lambda ctx: admin_proxy_save(ctx), role='admin'),
    Route('POST', '/api/admin/password', lambda ctx: admin_change_password(ctx), role='admin'),
    Route('GET', '/api/admin/integration', lambda ctx: admin_integration(ctx), role='admin'),
    Route('POST', '/api/admin/integration', lambda ctx: admin_integration_save(ctx), role='admin'),
    Route(
        'POST',
        '/api/admin/integration/credentials',
        lambda ctx: admin_integration_credentials(ctx),
        role='admin',
    ),
]


def match_route(method, path):
    path_matched = False
    for route in ROUTES:
        match = route.regex.match(path)
        if not match:
            continue
        if route.method != method:
            path_matched = True
            continue
        params = dict(zip(route.param_names, match.groups()))
        return route, params
    return None, path_matched


def parse_username(body):
    raw = body.get('username')
    if not isinstance(raw, str):
        raise ApiError(400, 'Username is required.')
    username = raw.strip().lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,32}', username):
        raise ApiError(400, 'Username must be 3-32 characters: letters, numbers, dot, dash, underscore.')
    return username


def parse_new_password(body):
    password = body.get('password')
    if not isinstance(password, str) or not (8 <= len(password) <= 200):
        raise ApiError(400, 'Password must be between 8 and 200 characters.')
    return password


def parse_duration(body):
    value = body.get('duration_minutes')
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        raise ApiError(400, 'Duration must be a whole number of minutes.')
    try:
        if isinstance(value, float):
            if not value.is_integer():
                raise ValueError
            number = int(value)
        else:
            text = str(value).strip()
            if not re.fullmatch(r'\d+', text):
                raise ValueError
            number = int(text)
    except (TypeError, ValueError):
        raise ApiError(400, 'Duration must be a whole number of minutes, or blank for a lifetime key.')
    if not 1 <= number <= MAX_DURATION_MINUTES:
        raise ApiError(400, 'Duration must be between 1 and 10,000,000 minutes.')
    return number


def parse_quantity(body):
    value = body.get('quantity')
    if value is None or value == '':
        return 1
    if isinstance(value, bool):
        raise ApiError(400, 'Quantity must be a whole number between 1 and 100.')
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, 'Quantity must be a whole number between 1 and 100.')
    if not 1 <= number <= MAX_QUANTITY:
        raise ApiError(400, 'Quantity must be between 1 and 100 keys per request.')
    return number


def parse_device_mode(body):
    mode = body.get('device_mode')
    if mode not in ('single', 'unlimited'):
        raise ApiError(400, 'Device mode must be "single" or "unlimited".')
    return mode


def parse_prefix(body):
    raw = body.get('prefix')
    if raw is None:
        return ''
    if not isinstance(raw, str):
        raise ApiError(400, 'Key prefix must be text.')
    text = raw.strip().upper().replace('-', '')
    if not text:
        return ''
    if not re.fullmatch(r'[A-Z0-9]{1,%d}' % MAX_PREFIX_LENGTH, text):
        raise ApiError(
            400,
            'Key prefix must be 1-{0} letters or numbers.'.format(MAX_PREFIX_LENGTH),
        )
    return text


def _parse_ip_networks(raw):
    networks = []
    for part in str(raw).replace(',', ' ').split():
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ApiError(400, 'Invalid IP address or range: {}'.format(part))
    return networks


def _ip_allowed(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in network for network in networks)


def _bool_setting(conn, key):
    return db.get_setting(conn, key) == '1'


def _remember_nonce(nonce, now):
    with _nonce_lock:
        expired = [item for item, expiry in _nonce_cache.items() if expiry <= now]
        for item in expired:
            del _nonce_cache[item]
        if nonce in _nonce_cache:
            return False
        if len(_nonce_cache) > 20000:
            _nonce_cache.clear()
        _nonce_cache[nonce] = now + HMAC_WINDOW_MS * 2
        return True


def _enforce_verify_auth(ctx):
    try:
        _check_verify_auth(ctx)
    except ApiError as err:
        if err.status == 401 and _bool_setting(ctx['conn'], 'verify_require_basic'):
            if not any(name.lower() == 'www-authenticate' for name, _ in err.headers):
                err.headers = list(err.headers) + [
                    ('WWW-Authenticate', 'Basic realm="KeyGate", charset="UTF-8"')
                ]
        if err.status in (401, 403):
            allowed, _ = security.take_rate('verify-auth-fail:{}'.format(ctx['ip']), 25, 60)
            if not allowed:
                raise ApiError(429, 'Too many failed authentication attempts. Slow down.')
        raise


def _check_verify_auth(ctx):
    conn = ctx['conn']
    headers = ctx['headers']

    allowed_raw = db.get_setting(conn, 'verify_allowed_ips') or ''
    if allowed_raw:
        networks = _parse_ip_networks(allowed_raw)
        if not _ip_allowed(ctx['ip'], networks):
            raise ApiError(403, 'This IP address is not allowed to verify keys.')

    if _bool_setting(conn, 'verify_require_api_key'):
        stored = db.get_setting(conn, 'verify_api_key_hash') or ''
        supplied = (headers.get('X-API-Key') or '').strip()
        if not supplied:
            auth_header = (headers.get('Authorization') or '').strip()
            if auth_header.lower().startswith('bearer '):
                supplied = auth_header[7:].strip()
        if not stored or not supplied or not hmac.compare_digest(
            security.sha256_hex(supplied), stored
        ):
            raise ApiError(401, 'A valid API key is required.')

    if _bool_setting(conn, 'verify_require_hmac'):
        secret = db.get_setting(conn, 'verify_hmac_secret') or ''
        timestamp = (headers.get('X-Timestamp') or '').strip()
        nonce = (headers.get('X-Nonce') or '').strip()
        signature = (headers.get('X-Signature') or '').strip()
        if not secret:
            raise ApiError(401, 'HMAC signing is enabled but no secret is configured.')
        if not re.fullmatch(r'\d{10,16}', timestamp):
            raise ApiError(401, 'Missing or invalid X-Timestamp header.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', nonce):
            raise ApiError(401, 'Missing or invalid X-Nonce header.')
        if not re.fullmatch(r'[0-9a-fA-F]{64}', signature):
            raise ApiError(401, 'Missing or invalid X-Signature header.')
        request_time = int(timestamp)
        now = security.now_ms()
        if abs(now - request_time) > HMAC_WINDOW_MS:
            raise ApiError(401, 'Signature timestamp is outside the allowed window.')
        raw_body = ctx.get('raw_body') or b''
        canonical = timestamp.encode('utf-8') + b'.' + nonce.encode('utf-8') + b'.' + raw_body
        expected = hmac.new(secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.lower()):
            raise ApiError(401, 'Invalid request signature.')
        if not _remember_nonce(nonce, now):
            raise ApiError(401, 'This request nonce was already used.')

    if _bool_setting(conn, 'verify_require_basic'):
        stored_user = db.get_setting(conn, 'verify_basic_username') or ''
        stored_hash = db.get_setting(conn, 'verify_basic_hash') or ''
        header = (headers.get('Authorization') or '').strip()
        challenge = [('WWW-Authenticate', 'Basic realm="KeyGate", charset="UTF-8"')]
        if not stored_hash or not header.lower().startswith('basic '):
            raise ApiError(
                401, 'HTTP Basic authentication is required.', headers=challenge
            )
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            raise ApiError(
                401, 'HTTP Basic authentication is required.', headers=challenge
            )
        username, separator, password = decoded.partition(':')
        valid_user = hmac.compare_digest(
            username.strip().lower().encode('utf-8'), stored_user.encode('utf-8')
        )
        if not separator or not valid_user or not security.verify_password(password, stored_hash):
            raise ApiError(401, 'Invalid HTTP Basic credentials.', headers=challenge)


def parse_id(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(404, 'Not found.')
    if number < 1:
        raise ApiError(404, 'Not found.')
    return number


def _login_user_key(ip, username):
    return 'login-user:{}:{}'.format(ip, username)


def _check_login_limits(ip, username):
    allowed, _ = security.take_rate('login-ip:{}'.format(ip), 30, 600)
    if not allowed:
        raise ApiError(429, 'Too many sign-in attempts. Try again in a few minutes.')
    allowed, _ = security.take_rate(_login_user_key(ip, username), 8, 600)
    if not allowed:
        raise ApiError(429, 'Too many sign-in attempts for this account. Try again in a few minutes.')


def health(ctx):
    state = maintenance.state(ctx['conn'])
    return {
        'ok': True,
        'service': 'KeyGate',
        'time': security.now_ms(),
        'maintenance': {
            'on': state['maintenance'],
            'block_resellers': state['block_resellers'],
            'pause_keys': state['pause_keys'],
            'message': state['message'],
        },
    }


def login_admin(ctx):
    body = ctx['body']
    raw_username = body.get('username')
    password = body.get('password')
    if (
        not isinstance(raw_username, str)
        or not raw_username.strip()
        or not isinstance(password, str)
        or not password
        or len(password) > 200
    ):
        raise ApiError(400, 'Enter your username and password.')
    username = raw_username.strip().lower()
    _check_login_limits(ctx['ip'], username)
    conn = ctx['conn']
    admin = conn.execute(
        'SELECT * FROM admins WHERE username = ? COLLATE NOCASE', (username,)
    ).fetchone()
    stored = admin['pass_hash'] if admin else _get_dummy_hash()
    password_ok = security.verify_password(password, stored)
    if admin is None or not password_ok:
        raise ApiError(401, 'Invalid username or password.')
    security.reset_rate(_login_user_key(ctx['ip'], username))
    token, ttl = sessions.create(conn, 'admin', admin['id'])
    ctx['cookies'].append(sessions.session_cookie(token, ttl))
    sessions.purge_expired(conn)
    return {'ok': True}


def login_reseller(ctx):
    body = ctx['body']
    raw_username = body.get('username')
    password = body.get('password')
    if (
        not isinstance(raw_username, str)
        or not raw_username.strip()
        or not isinstance(password, str)
        or not password
        or len(password) > 200
    ):
        raise ApiError(400, 'Enter your username and password.')
    username = raw_username.strip().lower()
    _check_login_limits(ctx['ip'], username)
    conn = ctx['conn']
    if maintenance.block_resellers(conn):
        raise ApiError(403, maintenance.message(conn))
    reseller = conn.execute(
        'SELECT * FROM resellers WHERE username = ?', (username,)
    ).fetchone()
    stored = reseller['pass_hash'] if reseller else _get_dummy_hash()
    password_ok = security.verify_password(password, stored)
    if reseller is None or not password_ok:
        raise ApiError(401, 'Invalid username or password.')
    if not reseller['active']:
        raise ApiError(403, 'This reseller account is disabled.')
    security.reset_rate(_login_user_key(ctx['ip'], username))
    token, ttl = sessions.create(conn, 'reseller', reseller['id'])
    ctx['cookies'].append(sessions.session_cookie(token, ttl))
    sessions.purge_expired(conn)
    return {
        'ok': True,
        'balance_cents': reseller['balance_cents'],
        'display_name': reseller['display_name'] or reseller['username'],
    }


def logout(ctx):
    session = ctx['session']
    if session:
        sessions.destroy(ctx['conn'], session['token_hash'])
    ctx['cookies'].append(sessions.clear_cookie())
    return {'ok': True}


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


def serialize_key(row, now=None, paused_since=0):
    if now is None:
        now = security.now_ms()
    keys = row.keys()
    creator = row['created_by_name'] if 'created_by_name' in keys else None
    if creator is None:
        creator = 'admin' if row['created_by_role'] == 'admin' else 'deleted reseller'
    expires_at = maintenance.effective_expiry(
        row['expires_at'], now, paused_since, row['activated_at']
    )
    return {
        'id': row['id'],
        'key': row['key_display'],
        'status': row['status'],
        'state': key_state(row, now, paused_since),
        'device_mode': row['device_mode'],
        'duration_minutes': row['duration_minutes'],
        'price_cents': row['price_cents'] if 'price_cents' in keys else 0,
        'hwid': row['hwid'],
        'activated_at': row['activated_at'],
        'expires_at': expires_at,
        'last_verified_at': row['last_verified_at'],
        'verify_count': row['verify_count'],
        'created_at': row['created_at'],
        'created_by_role': row['created_by_role'],
        'created_by': creator,
    }


def _generate_unique_key(conn, prefix=''):
    for _ in range(25):
        base = security.generate_key()
        display = '{}-{}'.format(prefix, base) if prefix else base
        normalized = security.normalize_key(display)
        exists = conn.execute(
            'SELECT 1 FROM keys WHERE key_norm = ?', (normalized,)
        ).fetchone()
        if exists is None:
            return display, normalized
    raise ApiError(500, 'Could not generate a unique key. Please try again.')


def _insert_keys(
    conn, quantity, duration, mode, role, user_id, created_at, prefix='', price_cents=0
):
    created = []
    for _ in range(quantity):
        display, normalized = _generate_unique_key(conn, prefix)
        conn.execute(
            'INSERT INTO keys (key_display, key_norm, duration_minutes, price_cents, '
            'device_mode, status, created_by_role, created_by_id, created_at) '
            "VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)",
            (display, normalized, duration, price_cents, mode, role, user_id, created_at),
        )
        created.append(display)
    return created


def _rollback(conn):
    if conn.in_transaction:
        conn.execute('ROLLBACK')


def _reseller_policy(row):
    raw = row['allowed_durations'] if 'allowed_durations' in row.keys() else ''
    durations = []
    for part in str(raw or '').split(','):
        part = part.strip()
        if part.isdigit() and int(part) > 0:
            durations.append(int(part))
    return {
        'allow_single': bool(row['allow_single']) if 'allow_single' in row.keys() else True,
        'allow_unlimited': bool(row['allow_unlimited']) if 'allow_unlimited' in row.keys() else True,
        'allow_lifetime': bool(row['allow_lifetime']) if 'allow_lifetime' in row.keys() else True,
        'allowed_durations': durations,
    }


def _reseller_payload(row):
    return {
        'id': row['id'],
        'username': row['username'],
        'display_name': (row['display_name'] or row['username']) if 'display_name' in row.keys() else row['username'],
        'balance_cents': row['balance_cents'],
        'policy': _reseller_policy(row),
    }


def _check_reseller_policy(policy, mode, duration):
    if mode == 'single' and not policy['allow_single']:
        raise ApiError(400, 'This reseller account may not create single-device keys.')
    if mode == 'unlimited' and not policy['allow_unlimited']:
        raise ApiError(400, 'This reseller account may not create unlimited-device keys.')
    if duration is None:
        if not policy['allow_lifetime']:
            raise ApiError(400, 'This reseller account may not create lifetime keys.')
        return
    allowed = policy['allowed_durations']
    if allowed and duration not in allowed:
        raise ApiError(
            400,
            'Duration must be one of: {}.'.format(
                ', '.join(str(value) for value in allowed)
            ),
        )


def _reseller_spent(conn, reseller_id):
    row = conn.execute(
        "SELECT COALESCE(SUM(price_cents), 0) AS spent FROM keys "
        "WHERE created_by_role = 'reseller' AND created_by_id = ?",
        (reseller_id,),
    ).fetchone()
    return row['spent']


def serialize_plan(row):
    return {
        'id': row['id'],
        'label': row['label'],
        'duration_minutes': row['duration_minutes'],
        'price_cents': row['price_cents'],
        'device_mode': row['device_mode'],
        'active': bool(row['active']),
        'created_at': row['created_at'],
    }


def reseller_me(ctx):
    reseller = ctx['reseller']
    return {
        'reseller': _reseller_payload(reseller),
        'spent_cents': _reseller_spent(ctx['conn'], reseller['id']),
    }


def reseller_plans(ctx):
    conn = ctx['conn']
    reseller = ctx['reseller']
    rows = conn.execute(
        'SELECT * FROM plans WHERE active = 1 '
        'ORDER BY price_cents ASC, duration_minutes IS NULL, duration_minutes ASC, id ASC'
    ).fetchall()
    return {
        'plans': [serialize_plan(row) for row in rows],
        'reseller': _reseller_payload(reseller),
        'spent_cents': _reseller_spent(conn, reseller['id']),
    }


def reseller_keys(ctx):
    reseller = ctx['reseller']
    conn = ctx['conn']
    rows = conn.execute(
        "SELECT k.*, r.username AS created_by_name FROM keys k "
        "LEFT JOIN resellers r ON k.created_by_role = 'reseller' AND r.id = k.created_by_id "
        "WHERE k.created_by_role = 'reseller' AND k.created_by_id = ? "
        "ORDER BY k.id DESC LIMIT 500",
        (reseller['id'],),
    ).fetchall()
    now = security.now_ms()
    paused = maintenance.paused_at(conn)
    return {
        'keys': [serialize_key(row, now, paused) for row in rows],
        'reseller': _reseller_payload(reseller),
        'spent_cents': _reseller_spent(conn, reseller['id']),
    }


def reseller_create_keys(ctx):
    body = ctx['body']
    raw_plan = body.get('plan_id')
    try:
        plan_id = int(raw_plan)
    except (TypeError, ValueError):
        raise ApiError(400, 'Choose a plan to buy.')
    if plan_id < 1:
        raise ApiError(400, 'Choose a plan to buy.')
    quantity = parse_quantity(body)
    prefix = parse_prefix(body)
    reseller = ctx['reseller']
    conn = ctx['conn']
    now = security.now_ms()
    try:
        conn.execute('BEGIN IMMEDIATE')
        plan = conn.execute('SELECT * FROM plans WHERE id = ?', (plan_id,)).fetchone()
        if plan is None or not plan['active']:
            raise ApiError(400, 'That plan is no longer available. Refresh the page.')
        _check_reseller_policy(
            _reseller_policy(reseller), plan['device_mode'], plan['duration_minutes']
        )
        cost = plan['price_cents'] * quantity
        current = conn.execute(
            'SELECT balance_cents, active FROM resellers WHERE id = ?',
            (reseller['id'],),
        ).fetchone()
        if current is None or not current['active']:
            raise ApiError(403, 'This reseller account is disabled.')
        if current['balance_cents'] < cost:
            raise ApiError(
                400,
                'Insufficient balance. This order costs ${:.2f}.'.format(cost / 100),
            )
        conn.execute(
            'UPDATE resellers SET balance_cents = balance_cents - ? WHERE id = ?',
            (cost, reseller['id']),
        )
        created = _insert_keys(
            conn,
            quantity,
            plan['duration_minutes'],
            plan['device_mode'],
            'reseller',
            reseller['id'],
            now,
            prefix,
            plan['price_cents'],
        )
        conn.execute('COMMIT')
    except Exception:
        _rollback(conn)
        raise
    return {
        'keys': created,
        'balance_cents': current['balance_cents'] - cost,
        'cost_cents': cost,
        'plan': serialize_plan(plan),
    }


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ('', '0', 'false', 'off', 'no')
    return bool(value)


def _parse_price_cents(body):
    value = body.get('price_cents')
    if isinstance(value, bool) or value in (None, ''):
        raise ApiError(400, 'Set a price for this plan.')
    if isinstance(value, float) and not value.is_integer():
        raise ApiError(400, 'Price must be a whole number of cents.')
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, 'Price must be a whole number of cents.')
    if not 0 <= number <= 100_000_000:
        raise ApiError(400, 'Price must be between $0 and $1,000,000.')
    return number


def _parse_plan_payload(body):
    label = body.get('label')
    if not isinstance(label, str) or not label.strip():
        raise ApiError(400, 'Add a name for the plan (for example: 1 day).')
    return {
        'label': label.strip()[:48],
        'duration_minutes': parse_duration(body),
        'price_cents': _parse_price_cents(body),
        'device_mode': parse_device_mode(body),
        'active': _as_bool(body.get('active'), True),
    }


def admin_plans(ctx):
    rows = ctx['conn'].execute(
        'SELECT * FROM plans ORDER BY active DESC, price_cents ASC, '
        'duration_minutes IS NULL, duration_minutes ASC, id ASC'
    ).fetchall()
    return {'plans': [serialize_plan(row) for row in rows]}


def admin_plan_save(ctx):
    fields = _parse_plan_payload(ctx['body'])
    conn = ctx['conn']
    plan_id = ctx['params'].get('id')
    if plan_id is None:
        cursor = conn.execute(
            'INSERT INTO plans (label, duration_minutes, price_cents, device_mode, active, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (
                fields['label'],
                fields['duration_minutes'],
                fields['price_cents'],
                fields['device_mode'],
                1 if fields['active'] else 0,
                security.now_ms(),
            ),
        )
        target = cursor.lastrowid
        message = 'Plan added.'
    else:
        target = parse_id(plan_id)
        row = conn.execute('SELECT id FROM plans WHERE id = ?', (target,)).fetchone()
        if row is None:
            raise ApiError(404, 'Plan not found.')
        conn.execute(
            'UPDATE plans SET label = ?, duration_minutes = ?, price_cents = ?, '
            'device_mode = ?, active = ? WHERE id = ?',
            (
                fields['label'],
                fields['duration_minutes'],
                fields['price_cents'],
                fields['device_mode'],
                1 if fields['active'] else 0,
                target,
            ),
        )
        message = 'Plan updated.'
    row = conn.execute('SELECT * FROM plans WHERE id = ?', (target,)).fetchone()
    return {'plan': serialize_plan(row), 'message': message}


def admin_plan_delete(ctx):
    conn = ctx['conn']
    plan_id = parse_id(ctx['params']['id'])
    row = conn.execute('SELECT id FROM plans WHERE id = ?', (plan_id,)).fetchone()
    if row is None:
        raise ApiError(404, 'Plan not found.')
    conn.execute('DELETE FROM plans WHERE id = ?', (plan_id,))
    return {'ok': True}


def admin_maintenance(ctx):
    return {'maintenance': maintenance.state(ctx['conn'])}


def admin_maintenance_save(ctx):
    body = ctx['body']
    raw_message = body.get('message')
    text = raw_message.strip()[:160] if isinstance(raw_message, str) else ''
    state = maintenance.save(
        ctx['conn'],
        _as_bool(body.get('on'), False),
        _as_bool(body.get('pause_keys'), False),
        _as_bool(body.get('block_resellers'), False),
        text,
    )
    return {'maintenance': state}


STATS_SQL = """
SELECT
    (SELECT COUNT(*) FROM keys) AS total_keys,
    (SELECT COUNT(*) FROM keys WHERE status = 'active' AND activated_at IS NULL) AS unused,
    (SELECT COUNT(*) FROM keys WHERE status = 'active' AND activated_at IS NOT NULL
        AND (expires_at IS NULL OR expires_at > ?)) AS in_use,
    (SELECT COUNT(*) FROM keys WHERE status = 'active' AND expires_at IS NOT NULL
        AND expires_at <= ?) AS expired,
    (SELECT COUNT(*) FROM keys WHERE status = 'suspended') AS suspended,
    (SELECT COUNT(*) FROM keys WHERE status = 'revoked') AS revoked,
    (SELECT COUNT(*) FROM resellers) AS resellers,
    (SELECT COUNT(*) FROM keys WHERE created_by_role = 'reseller') AS reseller_keys,
    (SELECT COALESCE(SUM(balance_cents), 0) FROM resellers) AS reseller_balances_cents
"""


def admin_overview(ctx):
    now = security.now_ms()
    paused = maintenance.paused_at(ctx['conn'])
    cutoff = paused or now
    stats = dict(ctx['conn'].execute(STATS_SQL, (cutoff, cutoff)).fetchone())
    return {
        'admin': {'username': ctx['admin']['username']},
        'stats': stats,
        'maintenance': maintenance.state(ctx['conn']),
    }


def admin_keys(ctx):
    conn = ctx['conn']
    query = ctx['query']
    search = (query.get('search') or '').strip()[:100]
    status_filter = query.get('status') or 'all'
    now = security.now_ms()
    paused = maintenance.paused_at(conn)
    cutoff = paused or now
    conditions = []
    params = []
    if search:
        like = '%{}%'.format(search)
        normalized_like = '%{}%'.format(security.normalize_key(search) or search)
        conditions.append('(k.key_norm LIKE ? OR k.key_display LIKE ? OR k.hwid LIKE ?)')
        params.extend([normalized_like, like.upper(), like])
    if status_filter == 'unused':
        conditions.append("k.status = 'active' AND k.activated_at IS NULL")
    elif status_filter == 'active':
        conditions.append(
            "k.status = 'active' AND k.activated_at IS NOT NULL "
            "AND (k.expires_at IS NULL OR k.expires_at > ?)"
        )
        params.append(cutoff)
    elif status_filter == 'expired':
        conditions.append(
            "k.status = 'active' AND k.expires_at IS NOT NULL AND k.expires_at <= ?"
        )
        params.append(cutoff)
    elif status_filter == 'suspended':
        conditions.append("k.status = 'suspended'")
    elif status_filter == 'revoked':
        conditions.append("k.status = 'revoked'")
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    sql = (
        "SELECT k.*, r.username AS created_by_name FROM keys k "
        "LEFT JOIN resellers r ON k.created_by_role = 'reseller' AND r.id = k.created_by_id "
        "{} ORDER BY k.id DESC LIMIT 500"
    ).format(where)
    rows = conn.execute(sql, params).fetchall()
    return {
        'keys': [serialize_key(row, now, paused) for row in rows],
        'maintenance': maintenance.state(conn),
    }


def admin_create_keys(ctx):
    quantity = parse_quantity(ctx['body'])
    duration = parse_duration(ctx['body'])
    mode = parse_device_mode(ctx['body'])
    admin = ctx['admin']
    conn = ctx['conn']
    now = security.now_ms()
    try:
        conn.execute('BEGIN IMMEDIATE')
        created = _insert_keys(conn, quantity, duration, mode, 'admin', admin['id'], now)
        conn.execute('COMMIT')
    except Exception:
        _rollback(conn)
        raise
    return {'keys': created}


def _load_key(conn, raw_id):
    key_id = parse_id(raw_id)
    row = conn.execute('SELECT * FROM keys WHERE id = ?', (key_id,)).fetchone()
    if row is None:
        raise ApiError(404, 'Key not found.')
    return row


def admin_suspend_key(ctx):
    conn = ctx['conn']
    row = _load_key(conn, ctx['params']['id'])
    if row['status'] != 'active':
        raise ApiError(400, 'Only active keys can be suspended.')
    conn.execute("UPDATE keys SET status = 'suspended' WHERE id = ?", (row['id'],))
    return {'ok': True}


def admin_unsuspend_key(ctx):
    conn = ctx['conn']
    row = _load_key(conn, ctx['params']['id'])
    if row['status'] != 'suspended':
        raise ApiError(400, 'Only suspended keys can be unsuspended.')
    conn.execute("UPDATE keys SET status = 'active' WHERE id = ?", (row['id'],))
    return {'ok': True}


def admin_revoke_key(ctx):
    conn = ctx['conn']
    row = _load_key(conn, ctx['params']['id'])
    if row['status'] != 'revoked':
        conn.execute("UPDATE keys SET status = 'revoked' WHERE id = ?", (row['id'],))
    return {'ok': True}


def admin_reset_device(ctx):
    conn = ctx['conn']
    row = _load_key(conn, ctx['params']['id'])
    if row['device_mode'] != 'single':
        raise ApiError(400, 'Unlimited keys have no bound device to reset.')
    if not row['hwid']:
        raise ApiError(400, 'This key has no bound device yet.')
    conn.execute('UPDATE keys SET hwid = NULL WHERE id = ?', (row['id'],))
    return {'ok': True}


def admin_delete_key(ctx):
    conn = ctx['conn']
    row = _load_key(conn, ctx['params']['id'])
    conn.execute('DELETE FROM keys WHERE id = ?', (row['id'],))
    return {'ok': True}


def admin_resellers(ctx):
    rows = ctx['conn'].execute(
        'SELECT r.id, r.username, r.display_name, r.balance_cents, r.active, '
        'r.allow_single, r.allow_unlimited, r.allow_lifetime, r.allowed_durations, '
        'r.created_at, '
        '(SELECT COUNT(*) FROM keys k WHERE k.created_by_role = \'reseller\' '
        'AND k.created_by_id = r.id) AS key_count '
        'FROM resellers r ORDER BY r.id DESC LIMIT 500'
    ).fetchall()
    resellers = []
    for row in rows:
        item = dict(row)
        item['policy'] = _reseller_policy(row)
        resellers.append(item)
    return {'resellers': resellers}


def _parse_display_name(body):
    raw = body.get('display_name', body.get('name'))
    if not isinstance(raw, str) or not raw.strip():
        raise ApiError(400, 'Add a name for the reseller.')
    name = raw.strip()
    if not 2 <= len(name) <= 48:
        raise ApiError(400, 'Reseller name must be between 2 and 48 characters.')
    return name


def admin_create_reseller(ctx):
    body = ctx['body']
    username = parse_username(body)
    password = parse_new_password(body)
    display_name = _parse_display_name(body)
    balance = body.get('balance_cents', 0)
    if isinstance(balance, bool) or not isinstance(balance, int):
        raise ApiError(400, 'Starting balance must be a whole number of cents.')
    if not 0 <= balance <= 100_000_000:
        raise ApiError(400, 'Starting balance is out of range.')
    password_hash = security.hash_password(password)
    try:
        ctx['conn'].execute(
            'INSERT INTO resellers (username, pass_hash, display_name, balance_cents, active, '
            'created_at) VALUES (?, ?, ?, ?, 1, ?)',
            (username, password_hash, display_name, balance, security.now_ms()),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, 'That username is already taken.')
    return {'ok': True}


def _load_reseller(conn, raw_id):
    reseller_id = parse_id(raw_id)
    row = conn.execute('SELECT * FROM resellers WHERE id = ?', (reseller_id,)).fetchone()
    if row is None:
        raise ApiError(404, 'Reseller not found.')
    return row


def admin_adjust_balance(ctx):
    delta = ctx['body'].get('delta_cents')
    if isinstance(delta, bool) or not isinstance(delta, int) or delta == 0:
        raise ApiError(400, 'Enter a non-zero whole number of cents.')
    if abs(delta) > 100_000_000:
        raise ApiError(400, 'Balance adjustment is out of range.')
    conn = ctx['conn']
    reseller = _load_reseller(conn, ctx['params']['id'])
    new_balance = reseller['balance_cents'] + delta
    if new_balance < 0:
        raise ApiError(400, 'Balance cannot go below $0.00.')
    conn.execute(
        'UPDATE resellers SET balance_cents = ? WHERE id = ?',
        (new_balance, reseller['id']),
    )
    return {'balance_cents': new_balance}


def admin_toggle_reseller(ctx):
    active = ctx['body'].get('active')
    if not isinstance(active, bool):
        raise ApiError(400, 'Active must be true or false.')
    conn = ctx['conn']
    reseller = _load_reseller(conn, ctx['params']['id'])
    conn.execute(
        'UPDATE resellers SET active = ? WHERE id = ?',
        (1 if active else 0, reseller['id']),
    )
    if not active:
        sessions.destroy_user(conn, 'reseller', reseller['id'])
    return {'active': active}


def admin_set_reseller_password(ctx):
    password = parse_new_password(ctx['body'])
    conn = ctx['conn']
    reseller = _load_reseller(conn, ctx['params']['id'])
    password_hash = security.hash_password(password)
    conn.execute(
        'UPDATE resellers SET pass_hash = ? WHERE id = ?',
        (password_hash, reseller['id']),
    )
    sessions.destroy_user(conn, 'reseller', reseller['id'])
    return {'ok': True}


def _parse_duration_allowlist(body):
    raw = body.get('allowed_durations')
    if raw is None:
        return None
    if isinstance(raw, str):
        parts = re.split(r'[\s,]+', raw.strip())
    elif isinstance(raw, list):
        parts = raw
    else:
        raise ApiError(400, 'Allowed durations must be a list of minutes.')
    values = []
    for part in parts:
        if isinstance(part, bool):
            raise ApiError(400, 'Allowed durations must be whole minutes.')
        try:
            number = int(str(part).strip())
        except (TypeError, ValueError):
            raise ApiError(400, 'Allowed durations must be whole minutes.')
        if not 1 <= number <= MAX_DURATION_MINUTES:
            raise ApiError(400, 'Allowed durations must be between 1 and 10,000,000 minutes.')
        if number not in values:
            values.append(number)
    if len(values) > 16:
        raise ApiError(400, 'Keep the duration list to 16 entries or fewer.')
    return values


def admin_reseller_policy(ctx):
    conn = ctx['conn']
    reseller = _load_reseller(conn, ctx['params']['id'])
    body = ctx['body']
    current = _reseller_policy(reseller)
    flags = {}
    for field in ('allow_single', 'allow_unlimited', 'allow_lifetime'):
        if field in body:
            value = body[field]
            if not isinstance(value, bool):
                raise ApiError(400, '{} must be true or false.'.format(field))
            flags[field] = value
        else:
            flags[field] = current[field]
    if not flags['allow_single'] and not flags['allow_unlimited']:
        raise ApiError(400, 'Allow at least one device policy.')
    durations = _parse_duration_allowlist(body)
    if durations is None:
        durations = current['allowed_durations']
    conn.execute(
        'UPDATE resellers SET allow_single = ?, allow_unlimited = ?, allow_lifetime = ?, '
        'allowed_durations = ? WHERE id = ?',
        (
            1 if flags['allow_single'] else 0,
            1 if flags['allow_unlimited'] else 0,
            1 if flags['allow_lifetime'] else 0,
            ','.join(str(value) for value in durations),
            reseller['id'],
        ),
    )
    updated = conn.execute('SELECT * FROM resellers WHERE id = ?', (reseller['id'],)).fetchone()
    return {'ok': True, 'policy': _reseller_policy(updated)}


def admin_access(ctx):
    conn = ctx['conn']
    try:
        limit = int(ctx['query'].get('limit') or 200)
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(500, limit))
    now = security.now_ms()
    events = conn.execute(
        'SELECT id, key_display, ip, hwid, result, source, created_at '
        'FROM verify_log ORDER BY id DESC LIMIT ?',
        (limit,),
    ).fetchall()
    bans = conn.execute(
        'SELECT id, kind, value, note, created_at FROM bans ORDER BY id DESC LIMIT 200'
    ).fetchall()
    day_ago = now - 24 * 60 * 60 * 1000
    summary = conn.execute(
        'SELECT COUNT(*) AS total, '
        "SUM(CASE WHEN result = 'valid' THEN 1 ELSE 0 END) AS ok "
        'FROM verify_log WHERE created_at >= ?',
        (day_ago,),
    ).fetchone()
    return {
        'events': [dict(row) for row in events],
        'bans': [dict(row) for row in bans],
        'summary': {
            'last_24h': summary['total'] or 0,
            'last_24h_valid': summary['ok'] or 0,
            'bans': len(bans),
        },
        'server_time': now,
    }


def admin_ban(ctx):
    body = ctx['body']
    kind = body.get('kind')
    value = body.get('value')
    note = body.get('note')
    if kind not in ('ip', 'hwid'):
        raise ApiError(400, 'Ban type must be "ip" or "hwid".')
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, 'Enter the IP address or device id to ban.')
    value = value.strip()
    if len(value) > 256:
        raise ApiError(400, 'That value is too long.')
    if kind == 'ip':
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise ApiError(400, 'Enter a valid IP address.')
    if not isinstance(note, str):
        note = ''
    note = note.strip()[:140]
    conn = ctx['conn']
    try:
        conn.execute(
            'INSERT INTO bans (kind, value, note, created_at) VALUES (?, ?, ?, ?)',
            (kind, value, note, security.now_ms()),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, 'That {} is already banned.'.format(kind.upper()))
    return {'ok': True}


def admin_unban(ctx):
    conn = ctx['conn']
    ban_id = parse_id(ctx['params']['id'])
    row = conn.execute('SELECT id FROM bans WHERE id = ?', (ban_id,)).fetchone()
    if row is None:
        raise ApiError(404, 'Ban not found.')
    conn.execute('DELETE FROM bans WHERE id = ?', (ban_id,))
    return {'ok': True}


def _proxy_host(value, label, allow_empty=True):
    value = (value or '').strip()
    if not value and allow_empty:
        return ''
    if not re.fullmatch(r'[A-Za-z0-9._:-]{1,255}', value):
        raise ApiError(400, '{} is not a valid host.'.format(label))
    return value


def admin_proxy_save(ctx):
    conn = ctx['conn']
    body = ctx['body']
    mode = body.get('mode', 'test')
    if mode not in ('test', 'live'):
        raise ApiError(400, 'Mode must be "test" or "live".')
    host = _proxy_host(body.get('host'), 'Proxy host')
    if mode == 'live' and not host:
        raise ApiError(400, 'A proxy host is required for live mode.')
    try:
        port = int(str(body.get('port') or '443').strip())
    except (TypeError, ValueError):
        raise ApiError(400, 'Proxy port must be a number.')
    if not 1 <= port <= 65535:
        raise ApiError(400, 'Proxy port must be between 1 and 65535.')
    node_id = (body.get('uuid') or '').strip()
    if node_id:
        import uuid as uuid_module

        try:
            uuid_module.UUID(node_id)
        except ValueError:
            raise ApiError(400, 'Node id must be a valid UUID.')
    sni = _proxy_host(body.get('sni'), 'SNI')
    path = (body.get('path') or '/inri').strip() or '/inri'
    if not path.startswith('/') or len(path) > 80 or not re.fullmatch(r'/[A-Za-z0-9._~/-]*', path):
        raise ApiError(400, 'Path must start with "/" and use simple characters only.')
    remark = (body.get('remark') or 'INRI Proxy').strip()[:40] or 'INRI Proxy'
    base = (body.get('public_base_url') or '').strip().rstrip('/')
    if base and not re.fullmatch(r'https?://[^\s]+', base):
        raise ApiError(400, 'Public base URL must start with http:// or https://.')
    db.set_setting(conn, 'happ_mode', mode)
    db.set_setting(conn, 'happ_host', host)
    db.set_setting(conn, 'happ_port', str(port))
    db.set_setting(conn, 'happ_uuid', node_id)
    db.set_setting(conn, 'happ_sni', sni)
    db.set_setting(conn, 'happ_path', path)
    db.set_setting(conn, 'happ_remark', remark)
    db.set_setting(conn, portal.SUB_BASE_SETTING, base)
    return portal.admin_proxy_state(conn)


def admin_change_password(ctx):
    body = ctx['body']
    current = body.get('current_password')
    new_password = body.get('new_password')
    if not isinstance(current, str) or not isinstance(new_password, str):
        raise ApiError(400, 'Enter your current and new password.')
    if not 8 <= len(new_password) <= 200:
        raise ApiError(400, 'New password must be between 8 and 200 characters.')
    allowed, _ = security.take_rate('admin-pw:{}'.format(ctx['ip']), 20, 600)
    if not allowed:
        raise ApiError(429, 'Too many attempts. Try again later.')
    admin = ctx['admin']
    if not security.verify_password(current, admin['pass_hash']):
        raise ApiError(400, 'Current password is incorrect.')
    password_hash = security.hash_password(new_password)
    conn = ctx['conn']
    conn.execute(
        'UPDATE admins SET pass_hash = ? WHERE id = ?',
        (password_hash, admin['id']),
    )
    sessions.destroy_other_admins(conn, admin['id'], ctx['session']['token_hash'])
    return {'ok': True}


def _integration_state(conn):
    return {
        'require_api_key': _bool_setting(conn, 'verify_require_api_key'),
        'require_hmac': _bool_setting(conn, 'verify_require_hmac'),
        'require_basic': _bool_setting(conn, 'verify_require_basic'),
        'allowed_ips': db.get_setting(conn, 'verify_allowed_ips') or '',
        'api_key_set': bool(db.get_setting(conn, 'verify_api_key_hash')),
        'hmac_set': bool(db.get_setting(conn, 'verify_hmac_secret')),
        'basic_set': bool(db.get_setting(conn, 'verify_basic_hash')),
        'basic_username': db.get_setting(conn, 'verify_basic_username') or '',
    }


def admin_integration(ctx):
    return _integration_state(ctx['conn'])


def admin_integration_save(ctx):
    conn = ctx['conn']
    body = ctx['body']
    flags = (
        ('require_api_key', 'verify_require_api_key', 'verify_api_key_hash',
         'Generate an API key before requiring it.'),
        ('require_hmac', 'verify_require_hmac', 'verify_hmac_secret',
         'Generate an HMAC secret before requiring signatures.'),
        ('require_basic', 'verify_require_basic', 'verify_basic_hash',
         'Set Basic credentials before requiring them.'),
    )
    for field, setting, credential, message in flags:
        if field not in body:
            continue
        value = body[field]
        if not isinstance(value, bool):
            raise ApiError(400, '{} must be true or false.'.format(field))
        if value and not db.get_setting(conn, credential):
            raise ApiError(400, message)
        db.set_setting(conn, setting, '1' if value else '0')
    if 'allowed_ips' in body:
        raw = body['allowed_ips']
        if not isinstance(raw, str):
            raise ApiError(400, 'IP allowlist must be text.')
        networks = _parse_ip_networks(raw)
        db.set_setting(
            conn, 'verify_allowed_ips', ', '.join(str(network) for network in networks)
        )
    return _integration_state(conn)


def admin_integration_credentials(ctx):
    conn = ctx['conn']
    body = ctx['body']
    credential_type = body.get('type')
    if credential_type == 'api_key':
        key = security.random_token()
        db.set_setting(conn, 'verify_api_key_hash', security.sha256_hex(key))
        return {'api_key': key}
    if credential_type == 'hmac':
        secret = security.random_token()
        db.set_setting(conn, 'verify_hmac_secret', secret)
        return {'hmac_secret': secret}
    if credential_type == 'basic':
        username = body.get('username')
        password = body.get('password')
        if not isinstance(username, str) or not re.fullmatch(
            r'[A-Za-z0-9_.-]{3,32}', username.strip()
        ):
            raise ApiError(
                400,
                'Basic username must be 3-32 characters: letters, numbers, dot, dash, underscore.',
            )
        if not isinstance(password, str) or not (8 <= len(password) <= 200):
            raise ApiError(400, 'Basic password must be between 8 and 200 characters.')
        db.set_setting(conn, 'verify_basic_username', username.strip().lower())
        db.set_setting(conn, 'verify_basic_hash', security.hash_password(password))
        return {'ok': True, 'username': username.strip().lower()}
    raise ApiError(400, 'Credential type must be "api_key", "hmac", or "basic".')


def verify_php(ctx):
    if ctx['method'] in ('GET', 'HEAD'):
        params = dict(ctx['query'])
    else:
        params = {**ctx['query'], **ctx['body']}
    ctx['body'] = params
    if 'action' in params:
        return php_action(ctx)
    return verify_key(ctx)


PHP_STATUSES = [
    'valid', 'no_key', 'not_found', 'expired',
    'revoked', 'suspended', 'device_mismatch', 'missing_hwid',
]

PHP_REASONS = {
    'invalid_key': ('INVALID_KEY', 'not_found', 'This key does not exist.'),
    'invalid_hwid': ('INVALID_HWID', None, 'The device id is not valid.'),
    'revoked': ('KEY_REVOKED', 'revoked', 'This key has been revoked.'),
    'suspended': ('KEY_SUSPENDED', 'suspended', 'This key is suspended.'),
    'expired': ('KEY_EXPIRED', 'expired', 'This key has expired.'),
    'device_required': (
        'MISSING_HWID', 'missing_hwid', 'This key is locked to a device. Send the hwid.'
    ),
    'device_mismatch': (
        'DEVICE_MISMATCH', 'device_mismatch', 'This key is locked to a different device.'
    ),
}


def php_time(ms=None):
    if ms is None:
        ms = security.now_ms()
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(int(ms) // 1000))
    return '{}.{:03d}Z'.format(stamp, int(ms) % 1000)


def php_minutes_left(expires_at, now):
    if expires_at is None:
        return None
    return max(0, -(-(int(expires_at) - int(now)) // 60000))


def php_error(code, message, **extra):
    payload = {'success': False, 'error': code, 'message': message}
    payload.update(extra)
    payload['server_time'] = php_time()
    return payload


def _php_key_param(params):
    raw = params.get('key')
    if not isinstance(raw, str):
        return ''
    return raw.strip()


def _php_find_key(conn, raw):
    normalized = security.normalize_key(raw)
    if not 20 <= len(normalized) <= 20 + MAX_PREFIX_LENGTH:
        return None
    return conn.execute('SELECT * FROM keys WHERE key_norm = ?', (normalized,)).fetchone()


def _php_management_auth(ctx):
    conn = ctx['conn']
    configured = (
        _bool_setting(conn, 'verify_require_api_key')
        or _bool_setting(conn, 'verify_require_hmac')
        or _bool_setting(conn, 'verify_require_basic')
    )
    if configured:
        _enforce_verify_auth(ctx)
        return True
    stored = db.get_setting(conn, 'verify_api_key_hash') or ''
    if not stored:
        return False
    if db.get_setting(conn, 'verify_allowed_ips'):
        _enforce_verify_auth(ctx)
    headers = ctx['headers']
    supplied = (headers.get('X-API-Key') or '').strip()
    if not supplied:
        auth_header = (headers.get('Authorization') or '').strip()
        if auth_header.lower().startswith('bearer '):
            supplied = auth_header[7:].strip()
    return bool(supplied) and hmac.compare_digest(security.sha256_hex(supplied), stored)


def _php_validate(ctx, params):
    raw_key = _php_key_param(params)
    if not raw_key:
        return php_error(
            'MISSING_KEY', 'No license key was provided.',
            valid=False, key='', status='no_key',
        )
    try:
        result = verify_key(ctx)
    except ApiError as err:
        if err.status in (401, 403):
            return php_error('UNAUTHORIZED', err.message, valid=False, key=raw_key, status='no_key')
        if err.status == 429:
            return php_error('RATE_LIMITED', err.message, valid=False, key=raw_key, status='no_key')
        raise
    if not result.get('valid'):
        if result.get('reason') == 'maintenance':
            return php_error(
                'MAINTENANCE',
                result.get('message') or maintenance.message(ctx['conn']),
                valid=False,
                key=raw_key,
                status='no_key',
            )
        code, status, message = PHP_REASONS.get(
            result.get('reason'), ('INVALID_KEY', 'not_found', 'This key is not valid.')
        )
        return php_error(code, message, valid=False, key=raw_key, status=status)
    now = result['server_time']
    expires_at = result.get('expires_at')
    hwid_value = params.get('hwid')
    hwid = hwid_value.strip() if isinstance(hwid_value, str) else ''
    return {
        'success': True,
        'valid': True,
        'status': 'valid',
        'key': raw_key,
        'hwid': hwid,
        'minutes_remaining': php_minutes_left(expires_at, now),
        'expires_at': php_time(expires_at) if expires_at is not None else None,
        'single_device': result.get('device_mode') == 'single',
        'server_time': php_time(now),
    }


def _php_info(ctx, params):
    raw_key = _php_key_param(params)
    if not raw_key:
        return php_error('MISSING_KEY', 'Send a key.')
    row = _php_find_key(ctx['conn'], raw_key)
    if row is None:
        return php_error('INVALID_KEY', 'This key does not exist.', key=raw_key)
    now = security.now_ms()
    paused = maintenance.paused_at(ctx['conn'])
    state = key_state(row, now, paused)
    status = 'valid' if state in ('unused', 'active') else state
    expires_at = maintenance.effective_expiry(
        row['expires_at'], now, paused, row['activated_at']
    )
    minutes_left = php_minutes_left(expires_at, now)
    if state == 'unused':
        minutes_left = row['duration_minutes']
    return {
        'success': True,
        'data': {
            'key': row['key_display'],
            'status': status,
            'valid': state in ('unused', 'active'),
            'device_mode': row['device_mode'],
            'single_device': row['device_mode'] == 'single',
            'hwid': row['hwid'],
            'activated_at': php_time(row['activated_at']) if row['activated_at'] else None,
            'expires_at': php_time(expires_at) if expires_at is not None else None,
            'minutes_remaining': minutes_left,
            'verify_count': row['verify_count'],
            'server_time': php_time(now),
        },
    }


def _php_generate(ctx, params):
    if not _php_management_auth(ctx):
        return php_error('UNAUTHORIZED', 'A valid API token is required.')
    duration_value = params.get('duration_minutes')
    if duration_value in (None, ''):
        duration_value = params.get('duration')
    if isinstance(duration_value, str):
        marker = duration_value.strip().lower()
        if marker in ('lifetime', 'forever', 'never'):
            duration_value = None
        elif marker == '':
            duration_value = ''
    try:
        duration = parse_duration({'duration_minutes': duration_value})
        quantity = parse_quantity(params)
    except ApiError as err:
        return php_error('INVALID_REQUEST', err.message)
    mode_raw = params.get('mode')
    if mode_raw in (None, ''):
        mode_raw = params.get('device_mode')
    mode_raw = str(mode_raw or 'single').strip().lower()
    if mode_raw in ('single', 'device', 'locked', '1', 'true'):
        mode = 'single'
    elif mode_raw in ('unlimited', 'multi', '0', 'false'):
        mode = 'unlimited'
    else:
        return php_error('INVALID_REQUEST', 'mode must be "single" or "unlimited".')
    conn = ctx['conn']
    admin_row = conn.execute('SELECT id FROM admins ORDER BY id LIMIT 1').fetchone()
    if admin_row is None:
        return php_error('SERVER_ERROR', 'No administrator account exists.')
    now = security.now_ms()
    try:
        conn.execute('BEGIN IMMEDIATE')
        created = _insert_keys(conn, quantity, duration, mode, 'admin', admin_row['id'], now)
        conn.execute('COMMIT')
    except Exception:
        _rollback(conn)
        raise
    return {
        'success': True,
        'data': {
            'keys': created,
            'quantity': len(created),
            'duration_minutes': duration,
            'device_mode': mode,
        },
    }


def _php_reset_hwid(ctx, params):
    if not _php_management_auth(ctx):
        return php_error('UNAUTHORIZED', 'A valid API token is required.')
    raw_key = _php_key_param(params)
    if not raw_key:
        return php_error('MISSING_KEY', 'Send a key.')
    conn = ctx['conn']
    row = _php_find_key(conn, raw_key)
    if row is None:
        return php_error('INVALID_KEY', 'This key does not exist.')
    if row['status'] == 'revoked':
        return php_error('KEY_REVOKED', 'This key has been revoked.')
    if row['device_mode'] != 'single':
        return php_error('NOT_SUPPORTED', 'Only single-device keys can be reset.')
    conn.execute(
        'UPDATE keys SET hwid = NULL, activated_at = NULL, expires_at = NULL WHERE id = ?',
        (row['id'],),
    )
    return {
        'success': True,
        'message': 'Device lock cleared. The timer restarts on the next verification.',
        'data': {'key': row['key_display'], 'status': 'valid'},
    }


def _php_revoke(ctx, params):
    if not _php_management_auth(ctx):
        return php_error('UNAUTHORIZED', 'A valid API token is required.')
    raw_key = _php_key_param(params)
    if not raw_key:
        return php_error('MISSING_KEY', 'Send a key.')
    conn = ctx['conn']
    row = _php_find_key(conn, raw_key)
    if row is None:
        return php_error('INVALID_KEY', 'This key does not exist.')
    conn.execute("UPDATE keys SET status = 'revoked' WHERE id = ?", (row['id'],))
    return {
        'success': True,
        'message': 'This key has been revoked.',
        'data': {'key': row['key_display'], 'status': 'revoked'},
    }


def php_action(ctx):
    params = ctx['body']
    action = params.get('action')
    action = action.strip().lower() if isinstance(action, str) else ''
    if action == 'health':
        return {'success': True, 'data': {'status': 'ok', 'server_time': php_time()}}
    if action == 'config':
        return {
            'success': True,
            'data': {
                'app_name': 'KeyGate',
                'key_prefix': '',
                'api_version': '1',
                'maintenance': False,
                'statuses': PHP_STATUSES,
                'server_time': php_time(),
            },
        }
    if action == 'validate':
        return _php_validate(ctx, params)
    if action == 'info':
        return _php_info(ctx, params)
    if action == 'generate':
        return _php_generate(ctx, params)
    if action in ('reset_hwid', 'reset-hwid', 'reset_device'):
        return _php_reset_hwid(ctx, params)
    if action == 'revoke':
        return _php_revoke(ctx, params)
    return {'success': False, 'error': 'Invalid action'}


def verify_key(ctx):
    body = ctx['body']
    now = security.now_ms()
    allowed, _ = security.take_rate('verify:{}'.format(ctx['ip']), 120, 60)
    if not allowed:
        raise ApiError(429, 'Too many verification attempts. Slow down.')
    _enforce_verify_auth(ctx)

    conn = ctx['conn']
    if maintenance.block_resellers(conn):
        return {
            'valid': False,
            'reason': 'maintenance',
            'message': maintenance.message(conn),
            'server_time': now,
        }

    def invalid(reason):
        return {'valid': False, 'reason': reason, 'server_time': now}

    raw_key = body.get('key')
    if not isinstance(raw_key, str):
        return invalid('invalid_key')
    normalized = security.normalize_key(raw_key)
    if not 20 <= len(normalized) <= 20 + MAX_PREFIX_LENGTH:
        return invalid('invalid_key')

    hwid_value = body.get('hwid')
    if hwid_value is None:
        hwid = ''
    elif isinstance(hwid_value, str):
        hwid = hwid_value.strip()
        if len(hwid) > MAX_HWID_LENGTH:
            return invalid('invalid_hwid')
    else:
        return invalid('invalid_hwid')

    conn = ctx['conn']
    row = conn.execute('SELECT * FROM keys WHERE key_norm = ?', (normalized,)).fetchone()
    if row is None:
        return invalid('invalid_key')
    if row['status'] == 'revoked':
        return invalid('revoked')
    if row['status'] == 'suspended':
        return invalid('suspended')
    paused = maintenance.paused_at(conn)
    if row['expires_at'] is not None and maintenance.effective_expiry(
        row['expires_at'], now, paused, row['activated_at']
    ) <= now:
        return invalid('expired')
    if row['device_mode'] == 'single':
        if not hwid:
            return invalid('device_required')
        if row['hwid'] and row['hwid'] != hwid:
            return invalid('device_mismatch')

    activated_at = row['activated_at']
    expires_at = row['expires_at']
    if activated_at is None:
        activated_at = now
        expires_at = None if row['duration_minutes'] is None else now + row['duration_minutes'] * 60_000

    new_hwid = row['hwid']
    if row['device_mode'] == 'single' and not new_hwid:
        new_hwid = hwid

    conn.execute(
        'UPDATE keys SET hwid = ?, activated_at = ?, expires_at = ?, '
        'last_verified_at = ?, verify_count = verify_count + 1 WHERE id = ?',
        (new_hwid, activated_at, expires_at, now, row['id']),
    )
    return {
        'valid': True,
        'device_mode': row['device_mode'],
        'activated_at': activated_at,
        'expires_at': maintenance.effective_expiry(
            expires_at, now, paused, activated_at
        ),
        'server_time': now,
    }
