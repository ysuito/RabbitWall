"""Absolute HTTP receive deadlines, including clients that keep trickling bytes."""
import io
import socket
import time
from http.server import BaseHTTPRequestHandler


class DeadlineReader(io.RawIOBase):
    def __init__(self, source, connection):
        self.source = source
        self.connection = connection
        self.deadline = 0
        self.timeout = 0

    def start(self, timeout):
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('HTTP receive deadline exceeded')
        self.connection.settimeout(min(self.timeout, remaining))
        return self.source.readinto(buffer)

    def close(self):
        try:
            self.source.close()
        finally:
            super().close()


class DeadlineHandler(BaseHTTPRequestHandler):
    """Use separate total header/body budgets; leave controller work outside them."""
    def setup(self):
        super().setup()
        self._original_rfile = self.rfile
        self._reader = DeadlineReader(getattr(self.rfile, 'raw', self.rfile), self.connection)
        self.rfile = io.BufferedReader(self._reader)

    def handle_one_request(self):
        self._reader.start(getattr(self.server, 'header_timeout', 5))
        try:
            return super().handle_one_request()
        except (TimeoutError, socket.timeout):
            self.close_connection = True

    def parse_request(self):
        valid = super().parse_request()
        if valid:
            self._reader.start(getattr(self.server, 'body_timeout', 3))
        return valid

    def finish(self):
        try:
            super().finish()
        finally:
            self._original_rfile.close()
