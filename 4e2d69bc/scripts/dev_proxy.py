"""Local HTTP/HTTPS test proxy for the INRI Proxy dashboard.

This is a plain forwarding proxy, not a VPN. It exists so you can click
through the dashboard's "Web proxy" panel on your own machine before you
own a real proxy server.

    python scripts/dev_proxy.py 8899

Then set your browser's HTTP and HTTPS proxy to 127.0.0.1:8899.
By default it only listens on loopback.
"""

import argparse
import select
import socket
import socketserver
import sys
from urllib.parse import urlsplit

BUFFER = 65536
HEAD_LIMIT = 65536


def read_head(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(8192)
        if not chunk:
            return None
        data += chunk
        if len(data) > HEAD_LIMIT:
            return None
    return data


def header_value(head, name):
    for line in head.split(b'\r\n')[1:]:
        if b':' not in line:
            continue
        key, value = line.split(b':', 1)
        if key.strip().lower() == name:
            return value.strip().decode('latin-1')
    return ''


def split_host_port(value, default_port):
    if value.startswith('['):
        end = value.find(']')
        host = value[1:end]
        rest = value[end + 1:]
        port = int(rest[1:]) if rest.startswith(':') and rest[1:] else default_port
        return host, port
    if value.count(':') == 1:
        host, raw_port = value.split(':', 1)
        return host, int(raw_port) if raw_port else default_port
    return value, default_port


def relay(left, right):
    peers = {left: right, right: left}
    while True:
        try:
            readable, _, _ = select.select([left, right], [], [], 120)
        except OSError:
            return
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(BUFFER)
            except OSError:
                return
            if not data:
                return
            try:
                peers[source].sendall(data)
            except OSError:
                return


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(30)
        head = read_head(client)
        if not head:
            return
        line = head.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        parts = line.split()
        if len(parts) != 3:
            self.respond(400, 'Bad request')
            return
        method, target, version = parts

        if method.upper() == 'CONNECT':
            host, port = split_host_port(target, 443)
            upstream = self.connect(host, port)
            if upstream is None:
                return
            client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.log('CONNECT', target)
            relay(client, upstream)
            upstream.close()
            return

        if target.lower().startswith(('http://', 'https://')):
            parsed = urlsplit(target)
            host = parsed.hostname or ''
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if parsed.scheme != 'http':
                self.respond(400, 'Only plain HTTP is forwarded; use CONNECT for HTTPS.')
                return
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            rewritten = '{} {} {}\r\n'.format(method, path, version).encode('latin-1')
            forwarded = [rewritten]
            for raw in head.split(b'\r\n')[1:]:
                if not raw:
                    continue
                name = raw.split(b':', 1)[0].strip().lower()
                if name in (b'proxy-connection', b'proxy-authorization'):
                    continue
                forwarded.append(raw + b'\r\n')
            forwarded.append(b'\r\n')
            upstream = self.connect(host, port)
            if upstream is None:
                return
            upstream.sendall(b''.join(forwarded))
            self.log(method, target)
            relay(client, upstream)
            upstream.close()
            return

        self.respond(400, 'Unsupported request. Configure your browser proxy, not a direct request.')

    def connect(self, host, port):
        try:
            upstream = socket.create_connection((host, port), timeout=20)
        except OSError as error:
            self.respond(502, 'Could not reach {}:{} ({})'.format(host, port, error))
            return None
        upstream.settimeout(None)
        return upstream

    def respond(self, status, text):
        reason = {400: 'Bad Request', 502: 'Bad Gateway'}.get(status, 'Error')
        body = text.encode('utf-8')
        head = (
            'HTTP/1.1 {} {}\r\n'
            'Content-Type: text/plain; charset=utf-8\r\n'
            'Content-Length: {}\r\n'
            'Connection: close\r\n\r\n'
        ).format(status, reason, len(body)).encode('ascii')
        try:
            self.request.sendall(head + body)
        except OSError:
            pass

    def log(self, method, target):
        print('[proxy] {} {}'.format(method, target), flush=True)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description='Local test proxy for INRI Proxy.')
    parser.add_argument('port', nargs='?', type=int, default=8899)
    parser.add_argument('--bind', default='127.0.0.1',
                        help='Interface to listen on (default: 127.0.0.1)')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535.')

    with ProxyServer((args.bind, args.port), ProxyHandler) as server:
        print('INRI Proxy local test proxy', flush=True)
        print('  Listening on {}:{}'.format(args.bind, args.port), flush=True)
        print('  Set your browser HTTP and HTTPS proxy to {}:{}'.format(args.bind, args.port), flush=True)
        print('  This is a forwarding proxy, not a VPN. Press Ctrl+C to stop.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nStopped.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except OSError as error:
        print('Could not start proxy: {}'.format(error), file=sys.stderr)
        sys.exit(1)
