from keygate import db, security

DEFAULT_MESSAGE = 'INRI PROXY ON MAINTENANCE — COME BACK LATER'

SETTING_ON = 'maintenance'
SETTING_PAUSE = 'maintenance_pause_keys'
SETTING_BLOCK_RESELLERS = 'maintenance_block_resellers'
SETTING_MESSAGE = 'maintenance_message'
SETTING_PAUSE_STARTED = 'maintenance_pause_started_at'


def is_on(conn):
    return db.get_setting(conn, SETTING_ON) == '1'


def block_resellers(conn):
    return is_on(conn) and db.get_setting(conn, SETTING_BLOCK_RESELLERS) == '1'


def message(conn):
    return (db.get_setting(conn, SETTING_MESSAGE) or '').strip() or DEFAULT_MESSAGE


def paused_at(conn):
    if not is_on(conn) or db.get_setting(conn, SETTING_PAUSE) != '1':
        return 0
    try:
        return int(db.get_setting(conn, SETTING_PAUSE_STARTED) or 0)
    except (TypeError, ValueError):
        return 0


def effective_expiry(expires_at, now, paused_since, activated_at=None):
    """Project a paused key's expiry forward so no time is spent.

    A key that was already expired when maintenance/pause began stays expired.
    Keys activated during the pause only freeze from their activation moment.
    """
    if expires_at is None or not paused_since:
        return expires_at
    anchor = max(int(paused_since), int(activated_at or 0))
    if expires_at <= anchor:
        return expires_at
    return expires_at + max(0, int(now) - anchor)


def resume(conn):
    """Give paused keys back the time that passed during maintenance."""
    raw = db.get_setting(conn, SETTING_PAUSE_STARTED) or '0'
    try:
        paused_since = int(raw)
    except (TypeError, ValueError):
        paused_since = 0
    if paused_since:
        now = security.now_ms()
        conn.execute(
            'UPDATE keys SET expires_at = expires_at + (? - MAX(?, activated_at)) '
            'WHERE expires_at IS NOT NULL AND activated_at IS NOT NULL '
            'AND activated_at < ? AND expires_at > MAX(?, activated_at)',
            (now, paused_since, now, paused_since),
        )
    db.set_setting(conn, SETTING_PAUSE_STARTED, '0')


def state(conn):
    return {
        'maintenance': is_on(conn),
        'pause_keys': is_on(conn) and db.get_setting(conn, SETTING_PAUSE) == '1',
        'block_resellers': block_resellers(conn),
        'message': message(conn),
        'paused_since': paused_at(conn),
        'server_time': security.now_ms(),
    }


def save(conn, on, pause_keys, block_resellers_flag, message_text):
    was_paused = bool(paused_at(conn))
    if was_paused and (not on or not pause_keys):
        resume(conn)
    db.set_setting(conn, SETTING_ON, '1' if on else '0')
    db.set_setting(conn, SETTING_PAUSE, '1' if on and pause_keys else '0')
    db.set_setting(
        conn, SETTING_BLOCK_RESELLERS, '1' if on and block_resellers_flag else '0'
    )
    db.set_setting(conn, SETTING_MESSAGE, message_text or DEFAULT_MESSAGE)
    if on and pause_keys and not was_paused:
        db.set_setting(conn, SETTING_PAUSE_STARTED, str(security.now_ms()))
    return state(conn)
