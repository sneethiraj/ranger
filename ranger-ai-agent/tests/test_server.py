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

import http.client
import json
import os
import sqlite3
import threading

import pytest

from ranger_ai_agent import cli
from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.server import INSIGHTS_PATH, MIN_TOKEN_LENGTH, TOKEN_ENV, make_server, validate_serve_settings
from ranger_ai_agent.suggestions.store import SuggestionStore

TOKEN = "s3cret-" + "x" * 40


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("RANGER_AI_"):
            monkeypatch.delenv(name)


@pytest.fixture
def store_path(tmp_path):
    path = str(tmp_path / "suggestions.db")
    assert cli.main(["--store", path, "suggest", "--synthetic"]) == 0
    return path


def start(store_path, token=TOKEN, safety=None):
    server = make_server("127.0.0.1", 0, store_path, token, safety or SafetyConfig())
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def port(store_path):
    server, thread = start(store_path)
    yield server.server_port
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def request(port, path=INSIGHTS_PATH, token=TOKEN, method="GET", authorization=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    if authorization is not None:
        headers["Authorization"] = authorization
    elif token is not None:
        headers["Authorization"] = "Bearer " + token
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response, body


def test_authorized_request_returns_insights_json(port):
    response, body = request(port)
    assert response.status == 200
    assert response.getheader("Content-Type") == "application/json"
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    data = json.loads(body)
    assert data["schema"] == 1
    assert data["counts"]["PENDING"] == 3
    assert len(data["suggestions"]) == 3
    assert data["action_log"]["intact"] is True
    assert data["mode"] == {"dry_run": True, "kill_switch": False, "max_changes_per_day": 5}


def test_payload_excludes_raw_policy_bodies(port):
    _, body = request(port)
    assert b"policyItems" not in body
    assert all("proposal" not in s for s in json.loads(body)["suggestions"])
    kinds = {s["kind"]: s["change"] for s in json.loads(body)["suggestions"]}
    assert kinds["OVER_PRIVILEGED"] == "remove carol from policy 1"


def test_query_string_is_ignored_but_path_must_match(port):
    assert request(port, INSIGHTS_PATH + "?x=1")[0].status == 200
    assert request(port, "/")[0].status == 404
    assert request(port, INSIGHTS_PATH + "/extra")[0].status == 404


@pytest.mark.parametrize(
    "token,authorization",
    [
        (None, None),
        ("wrong-token-" + "y" * 30, None),
        (TOKEN + "x", None),
        (TOKEN[:-1], None),
        (None, "Basic " + TOKEN),
        (None, "Bearer"),
        (None, "Bearer "),
        (None, TOKEN),
    ],
)
def test_missing_or_wrong_credentials_are_rejected(port, token, authorization):
    response, body = request(port, token=token, authorization=authorization)
    assert response.status == 401
    assert response.getheader("WWW-Authenticate") == "Bearer"
    assert json.loads(body) == {"error": "unauthorized"}


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_write_methods_are_not_allowed_even_with_a_valid_token(port, method):
    response, body = request(port, method=method)
    assert response.status == 405
    assert response.getheader("Allow") == "GET"


def test_internal_errors_do_not_leak_details(tmp_path):
    missing = str(tmp_path / "missing.db")
    server, thread = start(missing)
    try:
        response, body = request(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert response.status == 500
    assert json.loads(body) == {"error": "internal error"}
    assert b"missing.db" not in body
    assert not os.path.exists(missing)  # the read-only open must not create the file


def test_kill_switch_state_is_reported(store_path):
    server, thread = start(store_path, safety=SafetyConfig(kill_switch=True, dry_run=False, max_changes_per_day=2))
    try:
        _, body = request(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert json.loads(body)["mode"] == {"dry_run": False, "kill_switch": True, "max_changes_per_day": 2}


def test_validate_serve_settings():
    assert validate_serve_settings(TOKEN, "127.0.0.1", False) == TOKEN
    assert validate_serve_settings(TOKEN, "localhost", False) == TOKEN
    for bad in (None, "", "short", "x" * (MIN_TOKEN_LENGTH - 1)):
        with pytest.raises(ValueError, match=TOKEN_ENV):
            validate_serve_settings(bad, "127.0.0.1", False)
    with pytest.raises(ValueError, match="no TLS"):
        validate_serve_settings(TOKEN, "0.0.0.0", False)
    assert validate_serve_settings(TOKEN, "10.0.0.5", True) == TOKEN


def test_read_only_store_cannot_write_or_create(store_path, tmp_path):
    with SuggestionStore(store_path, read_only=True) as store:
        assert len(store.list()) == 3
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            store.log("2026-06-01T00:00:00Z", "agent", "X", None, {})
    missing = tmp_path / "nope.db"
    with pytest.raises(sqlite3.OperationalError):
        SuggestionStore(str(missing), read_only=True)
    assert not missing.exists()


def test_serve_command_refuses_unsafe_settings(store_path, tmp_path, capsys, monkeypatch):
    assert cli.main(["--store", store_path, "serve"]) == 1
    assert TOKEN_ENV in capsys.readouterr().err

    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    assert cli.main(["--store", store_path, "serve", "--host", "0.0.0.0"]) == 1
    assert "no TLS" in capsys.readouterr().err

    missing = str(tmp_path / "absent.db")
    assert cli.main(["--store", missing, "serve"]) == 1
    assert "store file not found" in capsys.readouterr().err
    assert not os.path.exists(missing)  # serve must not create the store


@pytest.mark.parametrize("serve_key, state, intact", [(None, "unverified", False), (b"s" * 32, "intact", True)])
def test_signed_log_is_verified_only_with_the_key(tmp_path, monkeypatch, serve_key, state, intact):
    path = str(tmp_path / "signed.db")
    monkeypatch.setenv("RANGER_AI_LOG_KEY", "s" * 32)
    assert cli.main(["--store", path, "suggest", "--synthetic"]) == 0
    monkeypatch.delenv("RANGER_AI_LOG_KEY")
    server = make_server("127.0.0.1", 0, path, TOKEN, SafetyConfig(), log_key=serve_key)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        _, body = request(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    log = json.loads(body)["action_log"]
    assert (log["state"], log["intact"], log["signed"]) == (state, intact, True)
