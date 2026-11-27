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

"""The signed action log: forging, relabelling, missing and wrong keys, and upgrades."""

import hashlib
import hmac
import json
import sqlite3

import pytest

from ranger_ai_agent.suggestions import store as st
from ranger_ai_agent.suggestions.store import (
    LOG_BROKEN,
    LOG_INTACT,
    LOG_KEY_ENABLED,
    LOG_UNVERIFIED,
    LogKeyRequired,
    SuggestionStore,
    log_key_from_env,
)

NOW = "2026-06-01T00:00:00Z"
KEY = b"k" * 32
OTHER_KEY = b"o" * 32


def _fill(store, n=3):
    for i in range(n):
        store.log(NOW, "agent", "EVENT", "s%d" % i, {"i": i})


def _tamper(store, sql, *params):
    """Edit the log around the append-only triggers, as someone with write access to the file could."""
    store._conn.execute("DROP TRIGGER IF EXISTS action_log_no_update")
    store._conn.execute("DROP TRIGGER IF EXISTS action_log_no_delete")
    store._conn.execute(sql, params)


def _rehash_plain(store):
    """Recompute every hash with plain SHA-256: defeats an unsigned log."""
    prev = st.GENESIS
    for e in store.log_entries():
        h = st._entry_hash(prev, e["ts"], e["actor"], e["action"], e["suggestion_id"] or "", st._canonical(e["details"]))
        store._conn.execute(
            "UPDATE action_log SET prev_hash = ?, entry_hash = ?, hash_alg = 'sha256' WHERE log_id = ?", (prev, h, e["log_id"])
        )
        prev = h


def test_signed_log_starts_with_a_key_marker_and_verifies():
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        entries = store.log_entries()
        assert entries[0]["action"] == LOG_KEY_ENABLED
        assert entries[0]["details"]["key_id"] == st.key_id(KEY)
        assert {e["hash_alg"] for e in entries} == {st.ALG_HMAC}
        check = store.check_log()
        assert check.state == LOG_INTACT and check.keyed and check.signed_entries == 4
        assert check.head == entries[-1]["entry_hash"]
        assert KEY.decode() not in json.dumps(entries)  # the key itself is never stored


def test_unsigned_log_can_be_rewritten_undetected_which_is_why_the_key_exists():
    with SuggestionStore() as store:
        _fill(store)
        _tamper(store, "UPDATE action_log SET actor = 'mallory' WHERE log_id = 2")
        assert store.verify_log() is False
        _rehash_plain(store)
        assert store.verify_log() is True
        assert store.check_log().keyed is False


def test_rewriting_a_whole_signed_log_as_unsigned_shows_as_not_signed():
    # A complete unsigned rewrite cannot be told from a log that was never signed.
    # It is visible as "not signed" (and approvals in it are not accepted for writes);
    # comparing the head hash with a copy kept elsewhere detects it outright.
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        head = store.check_log().head
        _tamper(store, "UPDATE action_log SET actor = 'mallory' WHERE log_id = 3")
        _rehash_plain(store)
        check = store.check_log()
        assert check.keyed is False
        assert check.head != head


def test_re_signing_with_a_guessed_key_is_detected():
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        prev = st.GENESIS
        for e in store.log_entries():
            details = dict(e["details"], key_id=st.key_id(OTHER_KEY)) if e["action"] == LOG_KEY_ENABLED else e["details"]
            h = st._signed_hash(OTHER_KEY, prev, e["ts"], e["actor"], e["action"], e["suggestion_id"] or "", st._canonical(details))
            _tamper(
                store,
                "UPDATE action_log SET prev_hash = ?, entry_hash = ?, details = ? WHERE log_id = ?",
                prev,
                h,
                st._canonical(details),
                e["log_id"],
            )
            prev = h
        check = store.check_log()
        assert check.state == LOG_BROKEN and "different key" in check.reason


def test_editing_one_signed_entry_is_detected():
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        _tamper(store, "UPDATE action_log SET details = '{\"i\":9}' WHERE log_id = 3")
        check = store.check_log()
        assert check.state == LOG_BROKEN and "entry 3" in check.reason


def test_relabelling_a_signed_entry_as_unsigned_is_detected():
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        last = store.log_entries()[-1]
        prev = last["prev_hash"]
        h = st._entry_hash(prev, last["ts"], "mallory", last["action"], last["suggestion_id"], st._canonical(last["details"]))
        _tamper(
            store, "UPDATE action_log SET actor = 'mallory', entry_hash = ?, hash_alg = 'sha256' WHERE log_id = ?", h, last["log_id"]
        )
        check = store.check_log()
        assert check.state == LOG_BROKEN and "unsigned" in check.reason


def test_without_the_key_a_signed_log_is_unverified_and_read_only(tmp_path):
    path = str(tmp_path / "s.db")
    with SuggestionStore(path, log_key=KEY) as store:
        _fill(store)
    with SuggestionStore(path) as store:
        check = store.check_log()
        assert check.state == LOG_UNVERIFIED and "RANGER_AI_LOG_KEY" in check.reason
        assert store.verify_log() is False
        with pytest.raises(LogKeyRequired):
            store.log(NOW, "agent", "EVENT", None, {})
        assert len(store.log_entries()) == 4
    with SuggestionStore(path, read_only=True, log_key=KEY) as store:
        assert store.check_log().state == LOG_INTACT


def test_an_unsigned_log_becomes_signed_once_a_key_is_set(tmp_path):
    path = str(tmp_path / "s.db")
    with SuggestionStore(path) as store:
        _fill(store, 2)
    with SuggestionStore(path, log_key=KEY) as store:
        _fill(store, 2)
        algs = [(e["action"], e["hash_alg"]) for e in store.log_entries()]
        assert algs == [
            ("EVENT", "sha256"),
            ("EVENT", "sha256"),
            (LOG_KEY_ENABLED, "hmac-sha256"),
            ("EVENT", "hmac-sha256"),
            ("EVENT", "hmac-sha256"),
        ]
        check = store.check_log()
        assert check.state == LOG_INTACT and check.signed_entries == 3


def test_a_signed_entry_before_the_marker_is_rejected():
    with SuggestionStore(log_key=KEY) as store:
        _fill(store)
        _tamper(store, "DELETE FROM action_log WHERE log_id = 1")
        # The chain is broken as well, but the first problem reported is the missing marker.
        assert store.check_log().state == LOG_BROKEN


def test_v2_store_gains_hash_alg_and_old_entries_still_verify(tmp_path):
    path = str(tmp_path / "v2.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE action_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, "
        "action TEXT NOT NULL, suggestion_id TEXT, details TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);"
    )
    h = st._entry_hash(st.GENESIS, NOW, "agent", "EVENT", "", "{}")
    conn.execute(
        "INSERT INTO action_log (ts, actor, action, suggestion_id, details, prev_hash, entry_hash) VALUES (?, ?, ?, NULL, '{}', ?, ?)",
        (NOW, "agent", "EVENT", st.GENESIS, h),
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()
    with SuggestionStore(path, log_key=KEY) as store:
        assert store.log_entries()[0]["hash_alg"] == "sha256"
        assert store.verify_log() is True
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == st.SCHEMA_VERSION


def test_short_keys_are_refused(monkeypatch):
    with pytest.raises(ValueError):
        SuggestionStore(log_key=b"short")
    monkeypatch.setenv("RANGER_AI_LOG_KEY", "short")
    with pytest.raises(ValueError, match="at least 32"):
        log_key_from_env()
    monkeypatch.delenv("RANGER_AI_LOG_KEY")
    assert log_key_from_env() is None


def test_key_id_does_not_reveal_the_key():
    assert st.key_id(KEY) != hashlib.sha256(KEY).hexdigest()[:16]
    assert st.key_id(KEY) == hmac.new(KEY, b"ranger-ai-agent action log key id", hashlib.sha256).hexdigest()[:16]
