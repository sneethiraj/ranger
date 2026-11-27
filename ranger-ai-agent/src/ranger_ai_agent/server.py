# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Read-only JSON endpoint that Ranger Admin proxies to.

    GET /api/v1/insights      Authorization: Bearer <RANGER_AI_SERVE_TOKEN>

This server is not meant to be reached by browsers. Ranger Admin calls it after
checking that the signed-in user is a system administrator. It therefore:

  * has exactly one route and no write routes
  * opens the store read-only for each request
  * requires a bearer token (compared in constant time)
  * binds to loopback unless the operator explicitly allows otherwise
  * has no TLS of its own; use loopback or a private network, or put TLS in front
"""

from __future__ import annotations

import hmac
import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.models import UTC
from ranger_ai_agent.report import build_insights
from ranger_ai_agent.suggestions.store import SuggestionStore

LOG = logging.getLogger(__name__)

INSIGHTS_PATH = "/api/v1/insights"
TOKEN_ENV = "RANGER_AI_SERVE_TOKEN"
MIN_TOKEN_LENGTH = 32
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})  # IPv4 only: the server binds an IPv4 socket
DEFAULT_PORT = 6090


def validate_serve_settings(token: Optional[str], host: str, allow_non_loopback: bool) -> str:
    """Return the token if the settings are acceptable, otherwise raise ValueError."""
    if not token or len(token) < MIN_TOKEN_LENGTH:
        raise ValueError("%s must be set to a secret of at least %d characters" % (TOKEN_ENV, MIN_TOKEN_LENGTH))
    if host not in LOOPBACK_HOSTS and not allow_non_loopback:
        raise ValueError(
            "refusing to listen on %r: this server has no TLS. Use a loopback address, or pass --allow-non-loopback "
            "and protect the connection another way" % host
        )
    return token


def make_server(
    host: str, port: int, store_path: str, token: str, safety: SafetyConfig, log_key: Optional[bytes] = None
) -> ThreadingHTTPServer:
    """`log_key` lets the page report a signed action log as verified; without it, it shows as not verified."""
    expected = token.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "RangerAIAgent"
        sys_version = ""

        def _send(self, status: int, body: bytes, content_type: str = "application/json", extra=None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, message: str, extra=None) -> None:
            self._send(status, json.dumps({"error": message}).encode("utf-8"), extra=extra)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            scheme, _, supplied = header.partition(" ")
            if scheme.lower() != "bearer" or not supplied:
                return False
            return hmac.compare_digest(supplied.strip().encode("utf-8"), expected)

        def do_GET(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
            if self.path.split("?", 1)[0] != INSIGHTS_PATH:
                self._error(404, "not found")
                return
            if not self._authorized():
                self._error(401, "unauthorized", extra={"WWW-Authenticate": "Bearer"})
                return
            try:
                store = SuggestionStore(store_path, read_only=True, log_key=log_key)
                try:
                    payload = build_insights(store, safety, datetime.now(UTC))
                finally:
                    store.close()
            except Exception:  # noqa: BLE001 - never leak internals to the caller
                LOG.exception("failed to build insights")
                self._error(500, "internal error")
                return
            self._send(200, json.dumps(payload).encode("utf-8"))

        def _method_not_allowed(self) -> None:
            self._error(405, "method not allowed", extra={"Allow": "GET"})

        do_POST = do_PUT = do_DELETE = do_PATCH = _method_not_allowed  # noqa: N815

        def log_message(self, fmt: str, *args) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

    return ThreadingHTTPServer((host, port), Handler)
