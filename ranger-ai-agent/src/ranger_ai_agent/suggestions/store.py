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

"""SQLite store for suggestions, applied changes, and the append-only action log.

The action log is hash-chained: each entry includes the hash of the previous
entry, so editing or removing an entry breaks verify_log(). Triggers also
reject UPDATE and DELETE on the log table.

Suggestions carry last_seen_at: the last time a detection run found them. It
is kept outside the payload so it can be updated for reviewed suggestions too.

Status changes that accompany a Ranger write (apply, rollback) are committed in
the same transaction as their log entry, so the store never shows an applied
change without a record of it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ranger_ai_agent.suggestions.models import (
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_ROLLED_BACK,
    Suggestion,
)

GENESIS = "GENESIS"
# Bump when the schema changes, and add a step to _MIGRATIONS.
SCHEMA_VERSION = 1
# EXPIRED -> PENDING happens only in upsert_pending, when a finding is detected again.
_VALID_TRANSITIONS = {
    STATUS_PENDING: frozenset({STATUS_APPROVED, STATUS_REJECTED, STATUS_EXPIRED}),
    STATUS_APPROVED: frozenset({STATUS_APPLIED, STATUS_EXPIRED}),
    STATUS_APPLIED: frozenset({STATUS_ROLLED_BACK}),
}
# Statuses that expire_missing() may close.
_EXPIRABLE = (STATUS_PENDING, STATUS_APPROVED)
_HUMAN_REVIEW_STATUSES = frozenset({STATUS_APPROVED, STATUS_REJECTED})

SCHEMA = """
CREATE TABLE IF NOT EXISTS suggestions (
    suggestion_id TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    status        TEXT NOT NULL,
    confidence    REAL NOT NULL,
    payload       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_seen_at  TEXT
);
CREATE TABLE IF NOT EXISTS applications (
    application_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    suggestion_id   TEXT NOT NULL,
    policy_id       INTEGER NOT NULL,
    applied_at      TEXT NOT NULL,
    applied_by      TEXT NOT NULL,
    version_before  INTEGER,
    version_after   INTEGER NOT NULL,
    rolled_back_at  TEXT,
    rolled_back_by  TEXT
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
    """Raised when a status change is not allowed from the current status."""


class SchemaTooOld(RuntimeError):
    """A read-only store was opened on a file written by an older version of the agent."""


def _columns(conn: sqlite3.Connection, table: str) -> List[str]:
    return [row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)]


def _migrate_v1(conn: sqlite3.Connection) -> None:
    """Add suggestions.last_seen_at. Existing rows count as seen when last updated."""
    if "last_seen_at" not in _columns(conn, "suggestions"):
        conn.execute("ALTER TABLE suggestions ADD COLUMN last_seen_at TEXT")
        conn.execute("UPDATE suggestions SET last_seen_at = updated_at")


# Each step must be safe on a fresh database, where SCHEMA already has the new shape.
_MIGRATIONS = {1: _migrate_v1}


def _canonical(details: Dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _entry_hash(prev: str, ts: str, actor: str, action: str, suggestion_id: str, details_json: str) -> str:
    material = "\x1f".join([prev, ts, actor, action, suggestion_id, details_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class SuggestionStore:
    def __init__(self, path: str = ":memory:", read_only: bool = False) -> None:
        """Open the store. A read-only store never creates or changes the file.

        Read-only mode requires the file to exist already, and any write fails at the database.
        """
        if read_only:
            uri = Path(path).resolve().as_uri() + "?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True)
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version < SCHEMA_VERSION:
                self._conn.close()
                raise SchemaTooOld(
                    "store schema version %d is older than %d; run any command that opens it for writing, "
                    "such as `list`, to upgrade it" % (version, SCHEMA_VERSION)
                )
        else:
            self._conn = sqlite3.connect(path)
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        for target in range(version + 1, SCHEMA_VERSION + 1):
            with self._conn:
                _MIGRATIONS[target](self._conn)
                self._conn.execute("PRAGMA user_version = %d" % target)

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

        An EXPIRED suggestion whose finding is detected again is reopened as PENDING,
        without its earlier review: an old approval never carries over.

        Returns CREATED, REFRESHED, REOPENED, or SKIPPED_REVIEWED. Each outcome is written
        to the action log in the same transaction.
        """
        with self._conn:
            row = self._conn.execute(
                "SELECT status FROM suggestions WHERE suggestion_id = ?", (suggestion.suggestion_id,)
            ).fetchone()
            payload = json.dumps(suggestion.to_dict(), sort_keys=True)
            if row is None:
                self._conn.execute(
                    "INSERT INTO suggestions "
                    "(suggestion_id, kind, status, confidence, payload, created_at, updated_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (suggestion.suggestion_id, suggestion.kind, suggestion.status, suggestion.confidence, payload, now, now, now),
                )
                outcome = "CREATED"
            elif row[0] == STATUS_EXPIRED:
                reopened = replace(suggestion, status=STATUS_PENDING, reviewed_by=None, reviewed_at=None)
                self._conn.execute(
                    "UPDATE suggestions SET status = ?, confidence = ?, payload = ?, updated_at = ?, last_seen_at = ? "
                    "WHERE suggestion_id = ?",
                    (
                        STATUS_PENDING,
                        reopened.confidence,
                        json.dumps(reopened.to_dict(), sort_keys=True),
                        now,
                        now,
                        suggestion.suggestion_id,
                    ),
                )
                outcome = "REOPENED"
            elif row[0] != STATUS_PENDING:
                outcome = "SKIPPED_REVIEWED"
            else:
                self._conn.execute(
                    "UPDATE suggestions SET confidence = ?, payload = ?, updated_at = ?, last_seen_at = ? WHERE suggestion_id = ?",
                    (suggestion.confidence, payload, now, now, suggestion.suggestion_id),
                )
                outcome = "REFRESHED"
            self._append(actor, outcome, suggestion.suggestion_id, {"confidence": suggestion.confidence}, now)
        return outcome

    def transition(
        self, suggestion_id: str, new_status: str, actor: str, now: str, details: Optional[Dict[str, Any]] = None
    ) -> Suggestion:
        """Human review (APPROVED or REJECTED), expiry, or a status change tied to a write."""
        with self._conn:
            return self._set_status(suggestion_id, new_status, actor, now, details or {})

    def mark_seen(self, suggestion_id: str, now: str) -> None:
        """Record that a detection run found this suggestion's finding again."""
        with self._conn:
            self._conn.execute("UPDATE suggestions SET last_seen_at = ? WHERE suggestion_id = ?", (now, suggestion_id))

    def last_seen(self, suggestion_id: str) -> Optional[str]:
        row = self._conn.execute("SELECT last_seen_at FROM suggestions WHERE suggestion_id = ?", (suggestion_id,)).fetchone()
        return row[0] if row else None

    def expire_missing(self, still_detected: Iterable[str], now: str, actor: str) -> List[str]:
        """Expire every PENDING or APPROVED suggestion that is not in still_detected.

        Runs in one transaction. Returns the expired ids.
        """
        keep = set(still_detected)
        expired: List[str] = []
        with self._conn:
            rows = self._conn.execute(
                "SELECT suggestion_id, status FROM suggestions WHERE status IN (?, ?) ORDER BY suggestion_id", _EXPIRABLE
            ).fetchall()
            for suggestion_id, status in rows:
                if suggestion_id in keep:
                    continue
                self._set_status(
                    suggestion_id,
                    STATUS_EXPIRED,
                    actor,
                    now,
                    {"reason": "finding no longer detected", "previous_status": status},
                )
                expired.append(suggestion_id)
        return expired

    def commit_application(
        self,
        suggestion_id: str,
        policy_id: int,
        now: str,
        actor: str,
        version_before: Optional[int],
        version_after: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Record a successful policy write and move the suggestion to APPLIED, atomically.

        The single action-log entry for the status change carries `details`.
        """
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO applications (suggestion_id, policy_id, applied_at, applied_by, version_before, version_after) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (suggestion_id, policy_id, now, actor, version_before, version_after),
            )
            entry = {"policy_id": policy_id, "version_before": version_before, "version_after": version_after}
            entry.update(details or {})
            self._set_status(suggestion_id, STATUS_APPLIED, actor, now, entry)
            return int(cursor.lastrowid)

    def commit_rollback(
        self,
        application_id: int,
        suggestion_id: str,
        now: str,
        actor: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a successful rollback and move the suggestion to ROLLED_BACK, atomically."""
        with self._conn:
            self._conn.execute(
                "UPDATE applications SET rolled_back_at = ?, rolled_back_by = ? WHERE application_id = ? AND rolled_back_at IS NULL",
                (now, actor, application_id),
            )
            entry = {"application_id": application_id}
            entry.update(details or {})
            self._set_status(suggestion_id, STATUS_ROLLED_BACK, actor, now, entry)

    def active_application(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        """The most recent application that has not been rolled back."""
        row = self._conn.execute(
            "SELECT application_id, policy_id, applied_at, applied_by, version_before, version_after "
            "FROM applications WHERE suggestion_id = ? AND rolled_back_at IS NULL "
            "ORDER BY application_id DESC LIMIT 1",
            (suggestion_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "application_id": row[0],
            "policy_id": row[1],
            "applied_at": row[2],
            "applied_by": row[3],
            "version_before": row[4],
            "version_after": row[5],
        }

    def list_applications(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT application_id, suggestion_id, policy_id, applied_at, applied_by, version_before, version_after, "
            "rolled_back_at, rolled_back_by FROM applications ORDER BY application_id"
        ).fetchall()
        keys = (
            "application_id",
            "suggestion_id",
            "policy_id",
            "applied_at",
            "applied_by",
            "version_before",
            "version_after",
            "rolled_back_at",
            "rolled_back_by",
        )
        return [dict(zip(keys, row)) for row in rows]

    def count_applications_since(self, since: str) -> int:
        """Applications made at or after `since` (ISO-8601 UTC). Rolled-back changes still count."""
        row = self._conn.execute("SELECT COUNT(*) FROM applications WHERE applied_at >= ?", (since,)).fetchone()
        return int(row[0])

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

    def _set_status(
        self,
        suggestion_id: str,
        new_status: str,
        actor: str,
        now: str,
        details: Dict[str, Any],
    ) -> Suggestion:
        """Change status, validate the move, and log it. Runs inside the caller's transaction."""
        row = self._conn.execute("SELECT payload FROM suggestions WHERE suggestion_id = ?", (suggestion_id,)).fetchone()
        if row is None:
            raise KeyError("no suggestion with id %s" % suggestion_id)
        current = Suggestion.from_dict(json.loads(row[0]))
        if new_status not in _VALID_TRANSITIONS.get(current.status, frozenset()):
            raise InvalidTransition("cannot move suggestion from %s to %s" % (current.status, new_status))

        changes: Dict[str, Any] = {"status": new_status}
        if new_status in _HUMAN_REVIEW_STATUSES:
            changes.update(reviewed_by=actor, reviewed_at=now)
        updated = replace(current, **changes)
        self._conn.execute(
            "UPDATE suggestions SET status = ?, payload = ?, updated_at = ? WHERE suggestion_id = ?",
            (new_status, json.dumps(updated.to_dict(), sort_keys=True), now, suggestion_id),
        )
        self._append(actor, new_status, suggestion_id, details, now)
        return updated

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
