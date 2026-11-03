#!/usr/bin/env python3
"""Downlink-only, unprivileged request ingress. No administrative operations."""
import ipaddress
import json
import socket
from http_limits import DeadlineHandler

from console import ConsoleServer
from control import request_control
from domain_requests import REQUEST_PORT, REQUEST_SOCKET, RequestLimit
from settings import SETTINGS


def make_handler(config=SETTINGS, callback=None):
    address = str(ipaddress.IPv4Interface(config['ai_cidr']).ip)
    callback = callback or (lambda action, payload: request_control(action, path=REQUEST_SOCKET, payload=payload))

    class Handler(DeadlineHandler):
        server_version = 'RabbitWall-Requests'

        def log_message(self, *_):
            pass

        def reply(self, code, data):
            self.connection.settimeout(5)
            body = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            if code == 429: self.send_header('Retry-After', '10')
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self, submit=False, revoke=False):
            # This endpoint is for local agents, not browser cross-origin access.
            if (self.headers.get('Host') != f'{address}:{REQUEST_PORT}'
                    or self.headers.get('Origin') is not None
                    or self.headers.get('Sec-Fetch-Site') not in (None, 'none')
                    or ipaddress.ip_address(self.client_address[0]) not in ipaddress.ip_interface(config['ai_cidr']).network):
                self.reply(403, {'error':'Downlink agent access required'})
                return
            try:
                if submit:
                    if self.path != '/api/domain-requests':
                        self.reply(404, {'error':'Not found'}); return
                    size = int(self.headers.get('Content-Length', '0'))
                    if (not 0 < size <= 12288 or self.headers.get_content_type() != 'application/json'
                            or self.headers.get('Transfer-Encoding')):
                        raise ValueError('Expected bounded JSON body')
                    payload = json.loads(self.rfile.read(size))
                    action = 'submit_domain_request'
                else:
                    prefix = '/api/domain-requests/'
                    path = self.path
                    if revoke:
                        if not path.endswith('/revoke'):
                            self.reply(404, {'error':'Not found'}); return
                        path = path[:-len('/revoke')]
                        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
                            raise ValueError('Expected empty body')
                    identity = path[len(prefix):] if path.startswith(prefix) else ''
                    if len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
                        self.reply(404, {'error':'Not found'}); return
                    payload = {'id':identity}
                    action = 'revoke_domain_request' if revoke else 'domain_request_status'
                result = callback(action, payload={'source':self.client_address[0], 'request':payload})
                self.reply(201 if submit else 200, {'request':result})
            except (TimeoutError, socket.timeout): self.reply(408, {'error':'HTTP receive deadline exceeded'})
            except RequestLimit as exc: self.reply(429, {'error':str(exc)})
            except ValueError as exc: self.reply(400, {'error':str(exc)})
            except Exception: self.reply(503, {'error':'Request service unavailable; do not assume approval'})

        def do_POST(self): self.dispatch(submit=self.path == '/api/domain-requests', revoke=self.path != '/api/domain-requests')
        def do_GET(self): self.dispatch()

    return Handler


if __name__ == '__main__':
    address = str(ipaddress.IPv4Interface(SETTINGS['ai_cidr']).ip)
    with ConsoleServer((address, REQUEST_PORT), make_handler()) as server:
        server.serve_forever()
