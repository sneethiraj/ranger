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

A plain hash chain can be recomputed by anyone who can write the file. When a
log key is configured (RANGER_AI_LOG_KEY), entries are signed with HMAC-SHA256
instead, so a forged or edited entry fails verification without the key. The
first signed entry is LOG_KEY_ENABLED; after it, unsigned entries are rejected,
and a store without the key refuses to append. Older unsigned entries are
still checked with plain SHA-256.

Suggestions carry last_seen_at: the last time a detection run found them. It
is kept outside the payload so it can be updated for reviewed suggestions too.

Every write to Ranger is recorded as an IN_FLIGHT application before it is
sent, then settled as APPLIED, ABORTED or UNCERTAIN. So a write is never made
without a row that rollback, the daily cap, and crash recovery can find.
Status changes that accompany a write are committed in the same transaction as
their log entry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Optional

from ranger_ai_agent.suggestions.models import (
    APP_ABORTED,
    APP_APPLIED,
    APP_IN_FLIGHT,
    APP_ROLLED_BACK,
    APP_UNCERTAIN,
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_NEEDS_ATTENTION,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_ROLLED_BACK,
    Suggestion,
)

GENESIS = "GENESIS"
# Bump when the schema changes, and add a step to _MIGRATIONS.
SCHEMA_VERSION = 3

LOG_KEY_ENV = "RANGER_AI_LOG_KEY"
MIN_LOG_KEY_LENGTH = 32
LOG_KEY_ENABLED = "LOG_KEY_ENABLED"
ALG_SHA256 = "sha256"  # unkeyed: detects careless edits, not deliberate ones
ALG_HMAC = "hmac-sha256"

LOG_INTACT = "intact"
LOG_UNVERIFIED = "unverified"  # signed entries exist, but no key was given to check them
LOG_BROKEN = "broken"
# EXPIRED -> PENDING happens only in upsert_pending, when a finding is detected again.
# NEEDS_ATTENTION is never expired: the policy may already have been changed.
_VALID_TRANSITIONS = {
    STATUS_PENDING: frozenset({STATUS_APPROVED, STATUS_REJECTED, STATUS_EXPIRED}),
    STATUS_APPROVED: frozenset({STATUS_APPLIED, STATUS_EXPIRED, STATUS_NEEDS_ATTENTION}),
    STATUS_APPLIED: frozenset({STATUS_ROLLED_BACK}),
    STATUS_NEEDS_ATTENTION: frozenset({STATUS_APPLIED, STATUS_APPROVED, STATUS_ROLLED_BACK}),
}
_APPLICATION_COLUMNS = (
    "application_id",
    "suggestion_id",
    "policy_id",
    "state",
    "applied_at",
    "applied_by",
    "version_before",
    "version_after",
    "before_sha256",
    "after_sha256",
    "rolled_back_at",
    "rolled_back_by",
)
# Statuses that expire_missing() may close.
_EXPIRABLE = (STATUS_PENDING, STATUS_APPROVED)
_HUMAN_REVIEW_STATUSES = frozenset({STATUS_APPROVED, STATUS_REJECTED})

# applied_at is when the attempt started. version_after is unknown until the write is confirmed.
_APPLICATIONS_DDL = """
    application_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    suggestion_id   TEXT NOT NULL,
    policy_id       INTEGER NOT NULL,
    state           TEXT NOT NULL DEFAULT 'APPLIED',
    applied_at      TEXT NOT NULL,
    applied_by      TEXT NOT NULL,
    version_before  INTEGER,
    version_after   INTEGER,
    before_sha256   TEXT,
    after_sha256    TEXT,
    rolled_back_at  TEXT,
    rolled_back_by  TEXT
"""

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
CREATE TABLE IF NOT EXISTS applications (%s);
CREATE TABLE IF NOT EXISTS action_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    suggestion_id TEXT,
    details       TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL,
    hash_alg      TEXT NOT NULL DEFAULT 'sha256'
);
CREATE TRIGGER IF NOT EXISTS action_log_no_update BEFORE UPDATE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS action_log_no_delete BEFORE DELETE ON action_log
BEGIN
    SELECT RAISE(ABORT, 'action_log is append-only');
END;
""" % _APPLICATIONS_DDL


class InvalidTransition(ValueError):
    """Raised when a status change is not allowed from the current status."""


class SchemaTooOld(RuntimeError):
    """A read-only store was opened on a file written by an older version of the agent."""


class LogKeyRequired(RuntimeError):
    """The action log is signed, and this store was opened without the key."""


class LogCheck(NamedTuple):
    state: str  # LOG_INTACT, LOG_UNVERIFIED or LOG_BROKEN
    entries: int
    signed_entries: int
    head: str  # hash of the last entry; record it elsewhere to detect a truncated log
    reason: str = ""

    @property
    def keyed(self) -> bool:
        return self.signed_entries > 0


def log_key_from_env() -> Optional[bytes]:
    """Read the action log key. Returns None if unset; raises ValueError if too short."""
    value = os.environ.get(LOG_KEY_ENV)
    if not value:
        return None
    if len(value) < MIN_LOG_KEY_LENGTH:
        raise ValueError("%s must be at least %d characters" % (LOG_KEY_ENV, MIN_LOG_KEY_LENGTH))
    return value.encode("utf-8")


def key_id(key: bytes) -> str:
    """A short identifier for a key that does not reveal it, recorded in LOG_KEY_ENABLED."""
    return hmac.new(key, b"ranger-ai-agent action log key id", hashlib.sha256).hexdigest()[:16]


def _columns(conn: sqlite3.Connection, table: str) -> List[str]:
    return [row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)]


def _migrate_v1(conn: sqlite3.Connection) -> None:
    """Add suggestions.last_seen_at. Existing rows count as seen when last updated."""
    if "last_seen_at" not in _columns(conn, "suggestions"):
        conn.execute("ALTER TABLE suggestions ADD COLUMN last_seen_at TEXT")
        conn.execute("UPDATE suggestions SET last_seen_at = updated_at")


def _migrate_v2(conn: sqlite3.Connection) -> None:
    """Add applications.state and the digests, and allow an unknown version_after.

    SQLite cannot drop NOT NULL in place, so the table is rebuilt. Every old row
    was a confirmed write, so it becomes APPLIED, or ROLLED_BACK if it was undone.
    """
    if "state" in _columns(conn, "applications"):
        return
    conn.execute("CREATE TABLE applications_v2 (%s)" % _APPLICATIONS_DDL)
    conn.execute(
        "INSERT INTO applications_v2 (application_id, suggestion_id, policy_id, state, applied_at, applied_by, "
        "version_before, version_after, rolled_back_at, rolled_back_by) "
        "SELECT application_id, suggestion_id, policy_id, "
        "CASE WHEN rolled_back_at IS NULL THEN 'APPLIED' ELSE 'ROLLED_BACK' END, "
        "applied_at, applied_by, version_before, version_after, rolled_back_at, rolled_back_by FROM applications"
    )
    conn.execute("DROP TABLE applications")
    conn.execute("ALTER TABLE applications_v2 RENAME TO applications")


def _migrate_v3(conn: sqlite3.Connection) -> None:
    """Add action_log.hash_alg. Every existing entry was hashed with plain SHA-256.

    ALTER TABLE does not fire the append-only triggers.
    """
    if "hash_alg" not in _columns(conn, "action_log"):
        conn.execute("ALTER TABLE action_log ADD COLUMN hash_alg TEXT NOT NULL DEFAULT 'sha256'")


# Each step must be safe on a fresh database, where SCHEMA already has the new shape.
_MIGRATIONS = {1: _migrate_v1, 2: _migrate_v2, 3: _migrate_v3}


def _canonical(details: Dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _entry_hash(prev: str, ts: str, actor: str, action: str, suggestion_id: str, details_json: str) -> str:
    material = "\x1f".join([prev, ts, actor, action, suggestion_id, details_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _signed_hash(key: bytes, prev: str, ts: str, actor: str, action: str, suggestion_id: str, details_json: str) -> str:
    # The algorithm name is part of the signed material, so an entry cannot be relabelled.
    material = "\x1f".join([ALG_HMAC, prev, ts, actor, action, suggestion_id, details_json])
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


class SuggestionStore:
    def __init__(self, path: str = ":memory:", read_only: bool = False, log_key: Optional[bytes] = None) -> None:
        """Open the store. A read-only store never creates or changes the file.

        Read-only mode requires the file to exist already, and any write fails at the database.
        With `log_key`, new log entries are signed and signed entries can be verified.
        """
        if log_key is not None and len(log_key) < MIN_LOG_KEY_LENGTH:
            raise ValueError("the action log key must be at least %d bytes" % MIN_LOG_KEY_LENGTH)
        self._key = log_key
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

    @property
    def keyed(self) -> bool:
        """True when this store signs new log entries."""
        return self._key is not None

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

    def begin_application(
        self,
        suggestion_id: str,
        policy_id: int,
        now: str,
        actor: str,
        version_before: Optional[int],
        before_sha256: str,
        after_sha256: str,
    ) -> int:
        """Record a write attempt as IN_FLIGHT before it is sent. Returns the application id.

        Committed on its own, so the attempt is on record even if the process dies mid-write.
        """
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO applications (suggestion_id, policy_id, state, applied_at, applied_by, version_before, "
                "before_sha256, after_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (suggestion_id, policy_id, APP_IN_FLIGHT, now, actor, version_before, before_sha256, after_sha256),
            )
            application_id = int(cursor.lastrowid)
            self._append(
                actor,
                "WRITE_STARTED",
                suggestion_id,
                {
                    "application_id": application_id,
                    "policy_id": policy_id,
                    "version_before": version_before,
                    "before_sha256": before_sha256,
                    "after_sha256": after_sha256,
                },
                now,
            )
        return application_id

    def commit_application(
        self,
        application_id: int,
        suggestion_id: str,
        now: str,
        actor: str,
        version_after: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Mark a write as confirmed and move the suggestion to APPLIED, atomically.

        The single action-log entry for the status change carries `details`.
        """
        with self._conn:
            row = self._require_application(application_id, suggestion_id, (APP_IN_FLIGHT, APP_UNCERTAIN))
            self._conn.execute(
                "UPDATE applications SET state = ?, version_after = ? WHERE application_id = ?",
                (APP_APPLIED, version_after, application_id),
            )
            entry = {
                "application_id": application_id,
                "policy_id": row["policy_id"],
                "version_before": row["version_before"],
                "version_after": version_after,
                "before_sha256": row["before_sha256"],
                "after_sha256": row["after_sha256"],
            }
            entry.update(details or {})
            self._set_status(suggestion_id, STATUS_APPLIED, actor, now, entry)

    def abort_application(
        self,
        application_id: int,
        suggestion_id: str,
        now: str,
        actor: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
        reopen: bool = False,
    ) -> None:
        """Mark a write as not having taken effect. With reopen, move NEEDS_ATTENTION back to APPROVED."""
        with self._conn:
            self._require_application(application_id, suggestion_id, (APP_IN_FLIGHT, APP_UNCERTAIN))
            self._conn.execute("UPDATE applications SET state = ? WHERE application_id = ?", (APP_ABORTED, application_id))
            entry = {"application_id": application_id, "outcome": outcome}
            entry.update(details or {})
            if reopen:
                self._set_status(suggestion_id, STATUS_APPROVED, actor, now, entry)
            else:
                self._append(actor, outcome, suggestion_id, entry, now)

    def mark_uncertain(
        self,
        application_id: int,
        suggestion_id: str,
        now: str,
        actor: str,
        version_after: Optional[int],
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Mark a write whose effect could not be confirmed, and move the suggestion to NEEDS_ATTENTION."""
        with self._conn:
            self._require_application(application_id, suggestion_id, (APP_IN_FLIGHT, APP_UNCERTAIN))
            self._conn.execute(
                "UPDATE applications SET state = ?, version_after = ? WHERE application_id = ?",
                (APP_UNCERTAIN, version_after, application_id),
            )
            entry = {"application_id": application_id, "version_after": version_after}
            entry.update(details or {})
            current = self._conn.execute("SELECT status FROM suggestions WHERE suggestion_id = ?", (suggestion_id,)).fetchone()
            if current is not None and current[0] == STATUS_NEEDS_ATTENTION:
                self._append(actor, APP_UNCERTAIN, suggestion_id, entry, now)
            else:
                self._set_status(suggestion_id, STATUS_NEEDS_ATTENTION, actor, now, entry)

    def application(self, application_id: int) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT %s FROM applications WHERE application_id = ?" % ", ".join(_APPLICATION_COLUMNS), (application_id,)
        ).fetchone()
        return dict(zip(_APPLICATION_COLUMNS, row)) if row else None

    def in_flight_applications(self) -> List[Dict[str, Any]]:
        """Write attempts whose outcome was never recorded, oldest first."""
        rows = self._conn.execute(
            "SELECT %s FROM applications WHERE state = ? ORDER BY application_id" % ", ".join(_APPLICATION_COLUMNS),
            (APP_IN_FLIGHT,),
        ).fetchall()
        return [dict(zip(_APPLICATION_COLUMNS, row)) for row in rows]

    def _require_application(self, application_id: int, suggestion_id: str, states) -> Dict[str, Any]:
        row = self.application(application_id)
        if row is None or row["suggestion_id"] != suggestion_id:
            raise KeyError("no application %s for suggestion %s" % (application_id, suggestion_id))
        if row["state"] not in states:
            raise InvalidTransition("application %s is %s, expected one of %s" % (application_id, row["state"], ", ".join(states)))
        return row

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
                "UPDATE applications SET state = ?, rolled_back_at = ?, rolled_back_by = ? "
                "WHERE application_id = ? AND rolled_back_at IS NULL",
                (APP_ROLLED_BACK, now, actor, application_id),
            )
            entry = {"application_id": application_id}
            entry.update(details or {})
            self._set_status(suggestion_id, STATUS_ROLLED_BACK, actor, now, entry)

    def active_application(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        """The most recent confirmed application that has not been rolled back."""
        return self._latest_application(suggestion_id, (APP_APPLIED,))

    def open_application(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        """The most recent application that may have changed the policy: APPLIED or UNCERTAIN."""
        return self._latest_application(suggestion_id, (APP_APPLIED, APP_UNCERTAIN))

    def _latest_application(self, suggestion_id: str, states) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT %s FROM applications WHERE suggestion_id = ? AND rolled_back_at IS NULL AND state IN (%s) "
            "ORDER BY application_id DESC LIMIT 1" % (", ".join(_APPLICATION_COLUMNS), ", ".join("?" * len(states))),
            (suggestion_id, *states),
        ).fetchone()
        return dict(zip(_APPLICATION_COLUMNS, row)) if row else None

    def record_version_after(self, application_id: int, version_after: int, now: str, actor: str) -> None:
        """Set the live version of an UNCERTAIN application after a person inspected it, so rollback can proceed."""
        with self._conn:
            row = self.application(application_id)
            if row is None or row["state"] != APP_UNCERTAIN:
                raise InvalidTransition("application %s is not UNCERTAIN" % application_id)
            self._conn.execute("UPDATE applications SET version_after = ? WHERE application_id = ?", (version_after, application_id))
            self._append(
                actor,
                "VERSION_RECORDED",
                row["suggestion_id"],
                {"application_id": application_id, "version_after": version_after},
                now,
            )

    def list_applications(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT %s FROM applications ORDER BY application_id" % ", ".join(_APPLICATION_COLUMNS)
        ).fetchall()
        return [dict(zip(_APPLICATION_COLUMNS, row)) for row in rows]

    def count_applications_since(self, since: str) -> int:
        """Write attempts started at or after `since` (ISO-8601 UTC), in any state.

        Aborted, uncertain and rolled-back attempts count too, so a failing write
        cannot be retried without limit.
        """
        row = self._conn.execute("SELECT COUNT(*) FROM applications WHERE applied_at >= ?", (since,)).fetchone()
        return int(row[0])

    def log(self, now: str, actor: str, action: str, suggestion_id: Optional[str], details: Dict[str, Any]) -> None:
        with self._conn:
            self._append(actor, action, suggestion_id, details, now)

    def log_entries(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT log_id, ts, actor, action, suggestion_id, details, prev_hash, entry_hash, hash_alg "
            "FROM action_log ORDER BY log_id"
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
                "hash_alg": r[8],
            }
            for r in rows
        ]

    def verify_log(self) -> bool:
        """True only if every entry, signed or not, checks out."""
        return self.check_log().state == LOG_INTACT

    def check_log(self) -> LogCheck:
        entries = self.log_entries()
        prev = GENESIS
        signed = 0
        unverified = False

        def result(state: str, reason: str = "") -> LogCheck:
            return LogCheck(state, len(entries), signed, prev, reason)

        for entry in entries:
            n = entry["log_id"]
            if entry["prev_hash"] != prev:
                return result(LOG_BROKEN, "entry %d does not follow the one before it" % n)
            fields = (prev, entry["ts"], entry["actor"], entry["action"], entry["suggestion_id"] or "", _canonical(entry["details"]))
            alg = entry["hash_alg"]
            if alg == ALG_SHA256:
                if signed:
                    return result(LOG_BROKEN, "entry %d is unsigned, after the log became signed" % n)
                ok = entry["entry_hash"] == _entry_hash(*fields)
            elif alg == ALG_HMAC:
                if not signed and entry["action"] != LOG_KEY_ENABLED:
                    return result(LOG_BROKEN, "entry %d is signed, but signing was never enabled" % n)
                signed += 1
                if self._key is None:
                    unverified = True
                    ok = True
                else:
                    if entry["action"] == LOG_KEY_ENABLED and entry["details"].get("key_id") != key_id(self._key):
                        return result(LOG_BROKEN, "entry %d was signed with a different key" % n)
                    ok = hmac.compare_digest(entry["entry_hash"], _signed_hash(self._key, *fields))
            else:
                return result(LOG_BROKEN, "entry %d has unknown hash algorithm %r" % (n, alg))
            if not ok:
                return result(LOG_BROKEN, "entry %d does not match its hash" % n)
            prev = entry["entry_hash"]

        if unverified:
            return result(LOG_UNVERIFIED, "the log is signed; set %s to verify it" % LOG_KEY_ENV)
        return result(LOG_INTACT)

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
        signed_log = self._conn.execute("SELECT 1 FROM action_log WHERE hash_alg = ? LIMIT 1", (ALG_HMAC,)).fetchone()
        if self._key is None:
            if signed_log:
                raise LogKeyRequired("the action log is signed; set %s to write to this store" % LOG_KEY_ENV)
        elif not signed_log:
            self._insert_entry("agent", LOG_KEY_ENABLED, None, {"key_id": key_id(self._key)}, now)
        self._insert_entry(actor, action, suggestion_id, details, now)

    def _insert_entry(self, actor: str, action: str, suggestion_id: Optional[str], details: Dict[str, Any], now: str) -> None:
        row = self._conn.execute("SELECT entry_hash FROM action_log ORDER BY log_id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        details_json = _canonical(details)
        fields = (prev, now, actor, action, suggestion_id or "", details_json)
        if self._key is None:
            alg, entry_hash = ALG_SHA256, _entry_hash(*fields)
        else:
            alg, entry_hash = ALG_HMAC, _signed_hash(self._key, *fields)
        self._conn.execute(
            "INSERT INTO action_log (ts, actor, action, suggestion_id, details, prev_hash, entry_hash, hash_alg) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now, actor, action, suggestion_id, details_json, prev, entry_hash, alg),
        )
