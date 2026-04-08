#!/usr/bin/env python3
"""
Simple HTTP echo server for CamoStream test environment.
Listens on port 8080, returns request headers and body as response.
"""

import json
import sys
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("echo-server")


class EchoHandler(BaseHTTPRequestHandler):
    """Echo back request details as JSON response."""

    def _build_response(self, body: bytes = b"") -> bytes:
        response = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body.decode("utf-8", errors="replace"),
            "client": f"{self.client_address[0]}:{self.client_address[1]}",
        }
        return json.dumps(response, indent=2).encode("utf-8")

    def _handle_request(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        logger.info(
            "%s %s from %s:%d (%d bytes)",
            self.command,
            self.path,
            self.client_address[0],
            self.client_address[1],
            len(body),
        )

        response_body = self._build_response(body)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Echo-Server", "camostream-test")
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_HEAD(self):
        response_body = self._build_response()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Echo-Server", "camostream-test")
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress default BaseHTTPRequestHandler logging; we use our own logger
        pass


def main():
    host = "0.0.0.0"
    port = 8080
    server = HTTPServer((host, port), EchoHandler)
    logger.info("Echo server listening on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
