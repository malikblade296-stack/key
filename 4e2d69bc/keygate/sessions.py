import os

from keygate import security

COOKIE_NAME = 'kg_session'
TTL_MS = {
    'admin': 8 * 60 * 60 * 1000,
    'reseller': 48 * 60 * 60 * 1000,
}


def create(conn, role, user_id):
    token = security.random_token()
    ttl = TTL_MS[role]
    now = security.now_ms()
    conn.execute(
        'INSERT INTO sessions (token_hash, role, user_id, created_at, expires_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (security.sha256_hex(token), role, user_id, now, now + ttl),
    )
    return token, ttl


def lookup(conn, token):
    if not token or len(token) > 200:
        return None
    token_hash = security.sha256_hex(token)
    row = conn.execute(
        'SELECT * FROM sessions WHERE token_hash = ?', (token_hash,)
    ).fetchone()
    if row is None:
        return None
    if row['expires_at'] <= security.now_ms():
        conn.execute('DELETE FROM sessions WHERE token_hash = ?', (token_hash,))
        return None
    data = dict(row)
    data['token_hash'] = token_hash
    return data


def destroy(conn, token_hash):
    conn.execute('DELETE FROM sessions WHERE token_hash = ?', (token_hash,))


def destroy_user(conn, role, user_id):
    conn.execute(
        'DELETE FROM sessions WHERE role = ? AND user_id = ?', (role, user_id)
    )


def destroy_role(conn, role):
    conn.execute('DELETE FROM sessions WHERE role = ?', (role,))


def destroy_other_admins(conn, user_id, keep_token_hash):
    conn.execute(
        'DELETE FROM sessions WHERE role = ? AND user_id = ? AND token_hash != ?',
        ('admin', user_id, keep_token_hash),
    )


def purge_expired(conn):
    conn.execute('DELETE FROM sessions WHERE expires_at <= ?', (security.now_ms(),))


def session_cookie(token, ttl_ms):
    parts = [
        '{}={}'.format(COOKIE_NAME, token),
        'HttpOnly',
        'SameSite=Strict',
        'Path=/',
        'Max-Age={}'.format(max(1, ttl_ms // 1000)),
    ]
    if os.environ.get('COOKIE_SECURE') == '1':
        parts.append('Secure')
    return '; '.join(parts)


def clear_cookie():
    parts = [
        '{}='.format(COOKIE_NAME),
        'HttpOnly',
        'SameSite=Strict',
        'Path=/',
        'Max-Age=0',
    ]
    if os.environ.get('COOKIE_SECURE') == '1':
        parts.append('Secure')
    return '; '.join(parts)
