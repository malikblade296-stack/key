import hashlib
import hmac
import secrets
import threading
import time

KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
KEY_LENGTH = 20
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

_rate_lock = threading.Lock()
_rate_buckets = {}


def now_ms():
    return int(time.time() * 1000)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=64,
        maxmem=SCRYPT_MAXMEM,
    )
    return 'scrypt${}${}${}${}${}'.format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), digest.hex()
    )


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt_hex, digest_hex = str(stored).split('$')
        if scheme != 'scrypt':
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        digest = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def generate_key():
    chars = [secrets.choice(KEY_ALPHABET) for _ in range(KEY_LENGTH)]
    return '-'.join(''.join(chars[i:i + 4]) for i in range(0, KEY_LENGTH, 4))


def normalize_key(value):
    if not isinstance(value, str):
        return ''
    value = value.upper()
    return ''.join(ch for ch in value if 'A' <= ch <= 'Z' or '0' <= ch <= '9')


def random_token():
    return secrets.token_urlsafe(32)


def sha256_hex(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def take_rate(key, limit, window_seconds):
    """Fixed-window limiter. Returns (allowed, retry_after_seconds)."""
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_buckets) > 5000:
            for bucket_key, (_, reset_at) in list(_rate_buckets.items()):
                if reset_at <= now:
                    del _rate_buckets[bucket_key]
        count, reset_at = _rate_buckets.get(key, (0, 0.0))
        if reset_at <= now:
            count, reset_at = 0, now + window_seconds
        count += 1
        _rate_buckets[key] = (count, reset_at)
        return count <= limit, max(1, int(reset_at - now))


def reset_rate(key):
    with _rate_lock:
        _rate_buckets.pop(key, None)
