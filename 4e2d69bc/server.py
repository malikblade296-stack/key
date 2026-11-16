import json
import os
import re
import secrets
import signal
import sys
import threading
import time
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from keygate import api, db, maintenance, portal, security, sessions

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / 'public'

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)

ASSETS = {
    'style.css': 'text/css; charset=utf-8',
    'common.js': 'text/javascript; charset=utf-8',
    'index.js': 'text/javascript; charset=utf-8',
    'reseller.js': 'text/javascript; charset=utf-8',
    'admin.js': 'text/javascript; charset=utf-8',
    'dashboard.js': 'text/javascript; charset=utf-8',
}

ADMIN_PATH = '/admin'


def _validate_admin_path(value):
    value = (value or '').strip()
    if not value.startswith('/'):
        raise SystemExit('ADMIN_PATH must start with "/".')
    value = value.rstrip('/') or '/'
    if value == '/':
        raise SystemExit('ADMIN_PATH cannot be the site root.')
    if len(value) > 80:
        raise SystemExit('ADMIN_PATH is too long (max 80 characters).')
    if not re.fullmatch(r'/[A-Za-z0-9._~/-]+', value) or '//' in value:
        raise SystemExit('ADMIN_PATH may only contain letters, numbers, ".", "_", "~", "-", "/".')
    reserved = ('/api', '/static', '/reseller', '/favicon.ico')
    if value.startswith('/api/') or value.startswith('/static/') or value in reserved:
        raise SystemExit('ADMIN_PATH cannot use a reserved path.')
    return value


def resolve_admin_path(conn):
    env_path = os.environ.get('ADMIN_PATH')
    if env_path:
        path = _validate_admin_path(env_path)
        db.set_setting(conn, 'admin_path', path)
        return path
    stored = db.get_setting(conn, 'admin_path')
    if stored:
        return stored
    generated = '/control-' + secrets.token_hex(6)
    db.set_setting(conn, 'admin_path', generated)
    return generated


def admin_username():
    username = (os.environ.get('ADMIN_USERNAME') or 'admin').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', username):
        raise SystemExit(
            'ADMIN_USERNAME must be 3-32 characters: letters, numbers, dot, dash, underscore.'
        )
    return username


def ensure_admin(conn):
    count = conn.execute('SELECT COUNT(*) AS c FROM admins').fetchone()['c']
    if count:
        return None
    username = admin_username()
    env_password = os.environ.get('ADMIN_PASSWORD')
    password = env_password or security.generate_key()
    if len(password) < 8:
        raise SystemExit('ADMIN_PASSWORD must be at least 8 characters.')
    password_hash = security.hash_password(password)
    conn.execute(
        'INSERT INTO admins (username, pass_hash, created_at) VALUES (?, ?, ?)',
        (username, password_hash, security.now_ms()),
    )
    return {
        'username': username,
        'generated_password': password if not env_password else None,
        'used_env': bool(env_password),
    }


def client_ip(handler):
    if os.environ.get('TRUST_PROXY') == '1':
        forwarded = handler.headers.get('X-Forwarded-For')
        if forwarded:
            # Proxies append the peer they saw last, so the rightmost entry is
            # the one the trusted proxy observed; anything before it is spoofable.
            return forwarded.split(',')[-1].strip()
    return handler.client_address[0]


def session_cleanup_loop():
    while True:
        time.sleep(1800)
        try:
            conn = db.connect()
            try:
                sessions.purge_expired(conn)
            finally:
                conn.close()
        except Exception:
            traceback.print_exc()


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'KeyGate'
    sys_version = ''
    timeout = 30

    def do_GET(self):
        self._handle('GET')

    def do_HEAD(self):
        self._handle('HEAD')

    def do_POST(self):
        self._handle('POST')

    def do_DELETE(self):
        self._handle('DELETE')

    def do_OPTIONS(self):
        self._handle('OPTIONS')

    def log_message(self, fmt, *args):
        sys.stderr.write(
            '{} [{}] {}\n'.format(
                time.strftime('%Y-%m-%d %H:%M:%S'),
                self.client_address[0],
                fmt % args,
            )
        )

    def _handle(self, method):
        try:
            url = urlsplit(self.path)
            path = url.path
            query = {
                key: values[0]
                for key, values in parse_qs(url.query, keep_blank_values=True).items()
            }
            if method == 'OPTIONS':
                self._empty(204, cors=(path in ('/api/verify', '/api.php')), allow=True)
                return
            if path.startswith('/sub/'):
                if method not in ('GET', 'HEAD'):
                    self._text(405, 'Method not allowed.')
                    return
                self._handle_subscription(path, query)
                return
            if path.startswith('/api/') or path == '/api.php':
                self._handle_api(method, path, query)
                return
            if method in ('GET', 'HEAD'):
                if self._serve_public(path, head=(method == 'HEAD')):
                    return
                self._text(404, 'Not found.')
                return
            self._text(405, 'Method not allowed.')
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self._text(500, 'Internal server error.')
            except Exception:
                pass

    def _serve_public(self, path, head=False):
        pages = {'/': 'index.html', '/reseller': 'reseller.html'}
        if path in pages:
            self._file(pages[path], 'text/html; charset=utf-8', 'no-store', head)
            return True
        if path in (ADMIN_PATH, ADMIN_PATH + '/'):
            self._file('admin.html', 'text/html; charset=utf-8', 'no-store', head)
            return True
        if path in ('/dashboard', '/dashboard/'):
            self._serve_dashboard(head)
            return True
        if path == '/favicon.ico':
            self._empty(204)
            return True
        prefix = '/static/'
        if path.startswith(prefix):
            name = path[len(prefix):]
            mime = ASSETS.get(name)
            if mime and '/' not in name and '\\' not in name and '..' not in name:
                self._file('static/' + name, mime, 'public, max-age=300', head)
                return True
        return False

    def _serve_dashboard(self, head=False):
        conn = None
        allowed = False
        try:
            conn = db.connect()
            token = portal.access_token_from(self)
            access = portal.read_access(conn, token, client_ip(self))
            allowed = access is not None
        except Exception:
            traceback.print_exc()
        finally:
            if conn is not None:
                conn.close()
        if not allowed:
            self.send_response(302)
            self._security_headers()
            self.send_header('Location', '/')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._file('dashboard.html', 'text/html; charset=utf-8', 'no-store', head)

    def _base_url(self):
        proto = (self.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip()
        if proto not in ('http', 'https'):
            proto = 'https' if os.environ.get('COOKIE_SECURE') == '1' else 'http'
        host = (
            self.headers.get('X-Forwarded-Host')
            or self.headers.get('Host')
            or 'localhost'
        ).split(',')[0].strip()
        return '{}://{}'.format(proto, host)

    def _handle_subscription(self, path, query):
        conn = None
        try:
            raw_key = path[len('/sub/'):].strip('/')
            ip = client_ip(self)
            conn = db.connect()
            status, headers, body = portal.subscription(
                conn, raw_key, query, ip, self.headers.get('User-Agent'), self.headers
            )
            self._raw(status, body, headers)
        except Exception:
            traceback.print_exc()
            self._text(500, 'Internal server error.')
        finally:
            if conn is not None:
                conn.close()

    def _raw(self, status, text, headers):
        body = text.encode('utf-8')
        self.send_response(status)
        self._security_headers()
        for name, value in headers.items():
            self.send_header(name, value)
        if 'Cache-Control' not in headers:
            self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _file(self, name, content_type, cache, head=False):
        try:
            data = (PUBLIC_DIR / name).read_bytes()
        except OSError:
            self._text(404, 'Not found.')
            return
        self.send_response(200)
        self._security_headers()
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', cache)
        self.end_headers()
        if not head:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _handle_api(self, method, path, query):
        cors = path in ('/api/verify', '/api.php')
        conn = None
        try:
            ip = client_ip(self)
            allowed, _ = security.take_rate('api:{}'.format(ip), 1200, 60)
            if not allowed:
                raise api.ApiError(429, 'Too many requests. Slow down.')
            if method not in ('GET', 'HEAD') and not cors:
                self._check_origin()
            route, path_matched = api.match_route(method, path)
            if route is None:
                if path_matched:
                    raise api.ApiError(405, 'Method not allowed.')
                raise api.ApiError(404, 'Unknown API endpoint.')
            body, raw_body = ({}, b'')
            if method in ('POST', 'DELETE'):
                content_type = (
                    (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
                )
                if path == '/api.php' and content_type == 'application/x-www-form-urlencoded':
                    body, raw_body = self._read_form()
                else:
                    body, raw_body = self._read_json()
            conn = db.connect()
            session = self._session(conn)
            ctx = {
                'conn': conn,
                'body': body,
                'raw_body': raw_body,
                'headers': self.headers,
                'query': query,
                'params': dict(zip(route.param_names, route.regex.match(path).groups())),
                'session': session,
                'admin': None,
                'reseller': None,
                'ip': ip,
                'cookies': [],
                'method': method,
                'path': path,
                'access_token': portal.access_token_from(self),
                'base_url': self._base_url(),
            }
            self._authorize(route, ctx)
            result = route.handler(ctx)
            self._json(200, result, cookies=ctx['cookies'], cors=cors)
        except api.ApiError as err:
            self._json(
                err.status, {'error': err.message}, cors=cors, extra_headers=err.headers
            )
        except portal.PortalError as err:
            self._json(err.status, {'error': err.message}, cors=cors)
        except Exception:
            traceback.print_exc()
            self._json(500, {'error': 'Internal server error.'}, cors=cors)
        finally:
            if conn is not None:
                conn.close()

    def _check_origin(self):
        origin = self.headers.get('Origin')
        if not origin:
            return
        try:
            parts = urlsplit(origin)
        except ValueError:
            raise api.ApiError(403, 'Cross-origin request blocked.')
        host = self.headers.get('Host', '')
        if parts.scheme not in ('http', 'https') or parts.netloc != host:
            raise api.ApiError(403, 'Cross-origin request blocked.')

    def _read_raw(self):
        raw_length = self.headers.get('Content-Length')
        if raw_length is None:
            return b''
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise api.ApiError(400, 'Invalid Content-Length header.')
        if length == 0:
            return b''
        if length > 65536:
            raise api.ApiError(413, 'Request body is too large.')
        return self.rfile.read(length)

    def _read_json(self):
        raw = self._read_raw()
        if not raw:
            return {}, b''
        content_type = (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
        if content_type != 'application/json':
            raise api.ApiError(415, 'Content-Type must be application/json.')
        try:
            data = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise api.ApiError(400, 'Request body must be valid JSON.')
        if not isinstance(data, dict):
            raise api.ApiError(400, 'JSON body must be an object.')
        return data, raw

    def _read_form(self):
        raw = self._read_raw()
        if not raw:
            return {}, b''
        try:
            values = parse_qs(raw.decode('utf-8'), keep_blank_values=True)
        except UnicodeDecodeError:
            raise api.ApiError(400, 'Request body must be valid UTF-8.')
        return {key: items[0] for key, items in values.items()}, raw

    def _session(self, conn):
        token = None
        header = self.headers.get('Cookie')
        if header:
            jar = SimpleCookie()
            try:
                jar.load(header)
            except Exception:
                jar = SimpleCookie()
            if sessions.COOKIE_NAME in jar:
                token = jar[sessions.COOKIE_NAME].value
        if not token:
            return None
        return sessions.lookup(conn, token)

    def _authorize(self, route, ctx):
        if route.role == 'admin':
            session = ctx['session']
            if not session or session['role'] != 'admin':
                raise api.ApiError(401, 'Administrator sign-in required.')
            admin = ctx['conn'].execute(
                'SELECT id, username, pass_hash FROM admins WHERE id = ?',
                (session['user_id'],),
            ).fetchone()
            if admin is None:
                sessions.destroy(ctx['conn'], session['token_hash'])
                raise api.ApiError(401, 'Session is no longer valid. Sign in again.')
            ctx['admin'] = dict(admin)
        elif route.role == 'reseller':
            session = ctx['session']
            if not session or session['role'] != 'reseller':
                raise api.ApiError(401, 'Reseller sign-in required.')
            reseller = ctx['conn'].execute(
                'SELECT id, username, display_name, balance_cents, active, '
                'allow_single, allow_unlimited, allow_lifetime, allowed_durations '
                'FROM resellers WHERE id = ?',
                (session['user_id'],),
            ).fetchone()
            if reseller is None:
                sessions.destroy(ctx['conn'], session['token_hash'])
                raise api.ApiError(401, 'Session is no longer valid. Sign in again.')
            if not reseller['active']:
                sessions.destroy_user(ctx['conn'], 'reseller', reseller['id'])
                raise api.ApiError(403, 'This reseller account is disabled.')
            if maintenance.block_resellers(ctx['conn']):
                raise api.ApiError(403, maintenance.message(ctx['conn']))
            ctx['reseller'] = dict(reseller)

    def _security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy', CSP)

    def _cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header(
            'Access-Control-Allow-Headers',
            'Content-Type, Authorization, X-API-Key, X-Timestamp, X-Nonce, X-Signature',
        )
        self.send_header('Access-Control-Max-Age', '600')

    def _json(self, status, payload, cookies=None, cors=False, extra_headers=None):
        body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self._security_headers()
        if cors:
            self._cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for name, value in extra_headers or ():
            self.send_header(name, value)
        for cookie in cookies or ():
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _text(self, status, text):
        body = text.encode('utf-8')
        self.send_response(status)
        self._security_headers()
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _empty(self, status, cors=False, allow=False):
        self.send_response(status)
        self._security_headers()
        if cors:
            self._cors_headers()
        elif allow:
            self.send_header('Allow', 'GET, HEAD, POST, DELETE, OPTIONS')
        self.send_header('Content-Length', '0')
        self.end_headers()


def print_banner(host, port, admin_path, admin_info, admin_username):
    local = 'http://localhost:{}'.format(port)
    print()
    print('  KeyGate - private license server')
    print('  ' + '-' * 52)
    print('  Reseller portal : {}/'.format(local))
    print('  Secret console  : {}{}'.format(local, admin_path))
    print('  Admin username  : {}'.format(admin_username))
    if admin_info and admin_info['generated_password']:
        print()
        print('  FIRST-RUN ADMIN PASSWORD: {}'.format(admin_info['generated_password']))
        print('  Save this now. It will not be printed again.')
        print('  Change it in the admin console under Settings.')
    elif admin_info and admin_info['used_env']:
        print()
        print('  Admin account created from the ADMIN_PASSWORD environment variable.')
    print()
    print('  Press Ctrl+C to stop.')
    print()


def main():
    global ADMIN_PATH
    host = os.environ.get('HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('PORT', '3000'))
    except ValueError:
        raise SystemExit('PORT must be a number.')
    if not 1 <= port <= 65535:
        raise SystemExit('PORT must be between 1 and 65535.')

    db.init()
    conn = db.connect()
    try:
        admin_info = ensure_admin(conn)
        admin_row = conn.execute(
            'SELECT username FROM admins ORDER BY id LIMIT 1'
        ).fetchone()
        ADMIN_PATH = resolve_admin_path(conn)
    finally:
        conn.close()

    api.init_dummy_hash()
    threading.Thread(target=session_cleanup_loop, daemon=True).start()

    print_banner(host, port, ADMIN_PATH, admin_info, admin_row['username'])
    if host == '0.0.0.0':
        print('  Listening on all interfaces. Use this machine\'s LAN IP from phones.')
        print('  For production, put this behind HTTPS and set COOKIE_SECURE=1.')
        print()

    try:
        server = ThreadingHTTPServer((host, port), RequestHandler)
    except OSError as exc:
        raise SystemExit('Could not start server on {}:{} - {}'.format(host, port, exc))
    server.daemon_threads = True

    def request_shutdown(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    sigterm = getattr(signal, 'SIGTERM', None)
    if sigterm is not None:
        try:
            signal.signal(sigterm, request_shutdown)
        except (ValueError, OSError):
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
    finally:
        server.server_close()
        print('Server stopped.')


if __name__ == '__main__':
    main()
