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

"""SQLite store for suggestions and the append-only action log.

The action log is hash-chained: each entry includes the hash of the previous
entry, so editing or removing an entry breaks verify_log(). Triggers also
reject UPDATE and DELETE on the log table.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from typing import Any, Dict, List, Optional

from ranger_ai_agent.suggestions.models import STATUS_APPROVED, STATUS_PENDING, STATUS_REJECTED, Suggestion

GENESIS = "GENESIS"
_VALID_TRANSITIONS = {
    STATUS_PENDING: frozenset({STATUS_APPROVED, STATUS_REJECTED}),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS suggestions (
    suggestion_id TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    status        TEXT NOT NULL,
    confidence    REAL NOT NULL,
    payload       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    suggestion_id TEXT,
    details       TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS action_log_no_update BEFORE UPDATE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS action_log_no_delete BEFORE DELETE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
"""


class InvalidTransition(ValueError):
    """Raised when a review is attempted on a suggestion that is not pending."""


def _canonical(details: Dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _entry_hash(prev: str, ts: str, actor: str, action: str, suggestion_id: str, details_json: str) -> str:
    material = "\x1f".join([prev, ts, actor, action, suggestion_id, details_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class SuggestionStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.executescript(SCHEMA)

    def __enter__(self) -> "SuggestionStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def get(self, suggestion_id: str) -> Optional[Suggestion]:
        row = self._conn.execute("SELECT payload FROM suggestions WHERE suggestion_id = ?", (suggestion_id,)).fetchone()
        return Suggestion.from_dict(json.loads(row[0])) if row else None

    def list(self, status: Optional[str] = None) -> List[Suggestion]:
        if status is None:
            rows = self._conn.execute("SELECT payload FROM suggestions ORDER BY suggestion_id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT payload FROM suggestions WHERE status = ? ORDER BY suggestion_id", (status,)
            ).fetchall()
        return [Suggestion.from_dict(json.loads(r[0])) for r in rows]

    def upsert_pending(self, suggestion: Suggestion, now: str, actor: str) -> str:
        """Insert, or refresh a pending suggestion. Reviewed suggestions are never changed.

        Returns CREATED, REFRESHED, or SKIPPED_REVIEWED. Each outcome is written to the action log in the same transaction.
        """
        with self._conn:
            row = self._conn.execute(
                "SELECT status FROM suggestions WHERE suggestion_id = ?", (suggestion.suggestion_id,)
            ).fetchone()
            payload = json.dumps(suggestion.to_dict(), sort_keys=True)
            if row is None:
                self._conn.execute(
                    "INSERT INTO suggestions (suggestion_id, kind, status, confidence, payload, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (suggestion.suggestion_id, suggestion.kind, suggestion.status, suggestion.confidence, payload, now, now),
                )
                outcome = "CREATED"
            elif row[0] != STATUS_PENDING:
                outcome = "SKIPPED_REVIEWED"
            else:
                self._conn.execute(
                    "UPDATE suggestions SET confidence = ?, payload = ?, updated_at = ? WHERE suggestion_id = ?",
                    (suggestion.confidence, payload, now, suggestion.suggestion_id),
                )
                outcome = "REFRESHED"
            self._append(actor, outcome, suggestion.suggestion_id, {"confidence": suggestion.confidence}, now)
        return outcome

    def transition(self, suggestion_id: str, new_status: str, reviewer: str, now: str) -> Suggestion:
        with self._conn:
            row = self._conn.execute("SELECT payload FROM suggestions WHERE suggestion_id = ?", (suggestion_id,)).fetchone()
            if row is None:
                raise KeyError("no suggestion with id %s" % suggestion_id)
            current = Suggestion.from_dict(json.loads(row[0]))
            if new_status not in _VALID_TRANSITIONS.get(current.status, frozenset()):
                raise InvalidTransition("cannot move suggestion from %s to %s" % (current.status, new_status))

            updated = replace(current, status=new_status, reviewed_by=reviewer, reviewed_at=now)
            self._conn.execute(
                "UPDATE suggestions SET status = ?, payload = ?, updated_at = ? WHERE suggestion_id = ?",
                (new_status, json.dumps(updated.to_dict(), sort_keys=True), now, suggestion_id),
            )
            self._append(reviewer, new_status, suggestion_id, {}, now)
        return updated

    def log(self, now: str, actor: str, action: str, suggestion_id: Optional[str], details: Dict[str, Any]) -> None:
        with self._conn:
            self._append(actor, action, suggestion_id, details, now)

    def log_entries(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT log_id, ts, actor, action, suggestion_id, details, prev_hash, entry_hash FROM action_log ORDER BY log_id"
        ).fetchall()
        return [
            {
                "log_id": r[0],
                "ts": r[1],
                "actor": r[2],
                "action": r[3],
                "suggestion_id": r[4],
                "details": json.loads(r[5]),
                "prev_hash": r[6],
                "entry_hash": r[7],
            }
            for r in rows
        ]

    def verify_log(self) -> bool:
        prev = GENESIS
        for entry in self.log_entries():
            if entry["prev_hash"] != prev:
                return False
            expected = _entry_hash(
                prev,
                entry["ts"],
                entry["actor"],
                entry["action"],
                entry["suggestion_id"] or "",
                _canonical(entry["details"]),
            )
            if entry["entry_hash"] != expected:
                return False
            prev = entry["entry_hash"]
        return True

    def _append(self, actor: str, action: str, suggestion_id: Optional[str], details: Dict[str, Any], now: str) -> None:
        row = self._conn.execute("SELECT entry_hash FROM action_log ORDER BY log_id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        details_json = _canonical(details)
        entry_hash = _entry_hash(prev, now, actor, action, suggestion_id or "", details_json)
        self._conn.execute(
            "INSERT INTO action_log (ts, actor, action, suggestion_id, details, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, actor, action, suggestion_id, details_json, prev, entry_hash),
        )
