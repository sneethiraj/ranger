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

import sqlite3

import pytest

from ranger_ai_agent.suggestions.models import (
    ACTION_REVIEW_ONLY,
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    Suggestion,
)
from ranger_ai_agent.suggestions.store import InvalidTransition, SuggestionStore

NOW = "2026-06-01T00:00:00Z"


def make_suggestion(sid="abc", confidence=0.7, summary="s"):
    return Suggestion(
        suggestion_id=sid,
        kind="ABNORMAL_ACCESS_TIME",
        as_of=NOW,
        summary=summary,
        rationale="r",
        recommended_action=ACTION_REVIEW_ONLY,
        caveats=("c",),
        evidence=("e",),
        detector_confidence=0.7,
        llm_confidence=None,
        confidence=confidence,
        proposal=Proposal(action=ACTION_REVIEW_ONLY),
        llm_provider="none",
        user="dave",
    )


def test_insert_then_refresh_pending_then_skip_reviewed():
    with SuggestionStore() as store:
        assert store.upsert_pending(make_suggestion(confidence=0.7), NOW, "agent") == "CREATED"
        assert store.upsert_pending(make_suggestion(confidence=0.9, summary="new"), NOW, "agent") == "REFRESHED"
        assert store.get("abc").confidence == 0.9

        store.transition("abc", STATUS_APPROVED, "alice", NOW)
        assert store.upsert_pending(make_suggestion(confidence=0.1, summary="ignored"), NOW, "agent") == "SKIPPED_REVIEWED"
        kept = store.get("abc")
        assert kept.status == STATUS_APPROVED
        assert kept.confidence == 0.9
        assert kept.summary == "new"


def test_transition_records_reviewer_and_rejects_invalid_moves():
    with SuggestionStore() as store:
        store.upsert_pending(make_suggestion(), NOW, "agent")
        rejected = store.transition("abc", STATUS_REJECTED, "bob", NOW)
        assert rejected.status == STATUS_REJECTED and rejected.reviewed_by == "bob"
        with pytest.raises(InvalidTransition):
            store.transition("abc", STATUS_APPROVED, "carol", NOW)
        with pytest.raises(KeyError):
            store.transition("missing", STATUS_APPROVED, "carol", NOW)


def test_list_filters_by_status():
    with SuggestionStore() as store:
        store.upsert_pending(make_suggestion("a"), NOW, "agent")
        store.upsert_pending(make_suggestion("b"), NOW, "agent")
        store.transition("b", STATUS_APPROVED, "dana", NOW)
        assert [s.suggestion_id for s in store.list(STATUS_PENDING)] == ["a"]
        assert [s.suggestion_id for s in store.list(STATUS_APPROVED)] == ["b"]


def test_action_log_records_every_write_and_chain_verifies():
    with SuggestionStore() as store:
        store.upsert_pending(make_suggestion(), NOW, "agent")
        store.transition("abc", STATUS_APPROVED, "alice", NOW)
        store.log(NOW, "agent", "LLM_CALL", "abc", {"provider": "ollama", "prompt_sha256": "x"})

        entries = store.log_entries()
        assert [e["action"] for e in entries] == ["CREATED", "APPROVED", "LLM_CALL"]
        assert entries[0]["prev_hash"] == "GENESIS"
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert store.verify_log() is True


def test_action_log_is_append_only_at_the_database_level():
    with SuggestionStore() as store:
        store.log(NOW, "agent", "KILL_SWITCH_ACTIVE", None, {})
        with pytest.raises(sqlite3.Error, match="append-only"):
            store._conn.execute("UPDATE action_log SET actor = 'mallory'")
        with pytest.raises(sqlite3.Error, match="append-only"):
            store._conn.execute("DELETE FROM action_log")


def test_tampering_is_detected_by_hash_chain():
    with SuggestionStore() as store:
        store.log(NOW, "agent", "A", None, {"n": 1})
        store.log(NOW, "agent", "B", None, {"n": 2})
        assert store.verify_log() is True

        # Bypass the trigger on purpose to simulate direct tampering with the file.
        store._conn.execute("DROP TRIGGER action_log_no_update")
        store._conn.execute("UPDATE action_log SET details = '{\"n\":99}' WHERE log_id = 1")
        assert store.verify_log() is False


def test_deleted_middle_entry_breaks_chain():
    with SuggestionStore() as store:
        for i in range(3):
            store.log(NOW, "agent", "A%d" % i, None, {})
        store._conn.execute("DROP TRIGGER action_log_no_delete")
        store._conn.execute("DELETE FROM action_log WHERE log_id = 2")
        assert store.verify_log() is False


# --- expiry, reopening, last_seen_at and schema migration ---

from ranger_ai_agent.suggestions.models import STATUS_APPLIED, STATUS_EXPIRED  # noqa: E402
from ranger_ai_agent.suggestions.store import SCHEMA_VERSION, SchemaTooOld  # noqa: E402

LATER = "2026-06-02T00:00:00Z"


def test_expire_missing_closes_only_pending_and_approved():
    with SuggestionStore() as store:
        for sid in ("pending", "approved", "rejected", "applied", "kept"):
            store.upsert_pending(make_suggestion(sid=sid), NOW, "agent")
        store.transition("approved", STATUS_APPROVED, "alice", NOW)
        store.transition("rejected", STATUS_REJECTED, "alice", NOW)
        store.transition("applied", STATUS_APPROVED, "alice", NOW)
        store.transition("applied", STATUS_APPLIED, "agent", NOW)

        assert store.expire_missing({"kept"}, LATER, "agent") == ["approved", "pending"]
        assert store.get("pending").status == STATUS_EXPIRED
        assert store.get("approved").status == STATUS_EXPIRED
        assert store.get("approved").reviewed_by == "alice"  # history of the old review is kept
        assert store.get("rejected").status == STATUS_REJECTED
        assert store.get("applied").status == STATUS_APPLIED
        assert store.get("kept").status == STATUS_PENDING
        expired = [e for e in store.log_entries() if e["action"] == STATUS_EXPIRED]
        assert {e["details"]["previous_status"] for e in expired} == {STATUS_PENDING, STATUS_APPROVED}
        assert store.verify_log() is True


def test_expired_suggestion_reopens_as_pending_without_its_old_approval():
    with SuggestionStore() as store:
        store.upsert_pending(make_suggestion(), NOW, "agent")
        store.transition("abc", STATUS_APPROVED, "alice", NOW)
        store.expire_missing(set(), NOW, "agent")

        assert store.upsert_pending(make_suggestion(summary="again"), LATER, "agent") == "REOPENED"
        reopened = store.get("abc")
        assert (reopened.status, reopened.reviewed_by, reopened.reviewed_at) == (STATUS_PENDING, None, None)
        assert reopened.summary == "again"
        assert store.last_seen("abc") == LATER
        with pytest.raises(InvalidTransition):
            store.transition("abc", STATUS_APPLIED, "agent", LATER)  # needs a fresh approval first


def test_last_seen_is_set_on_create_and_refresh_and_by_mark_seen():
    with SuggestionStore() as store:
        store.upsert_pending(make_suggestion(), NOW, "agent")
        assert store.last_seen("abc") == NOW
        store.upsert_pending(make_suggestion(), LATER, "agent")
        assert store.last_seen("abc") == LATER
        store.mark_seen("abc", "2026-06-03T00:00:00Z")
        assert store.last_seen("abc") == "2026-06-03T00:00:00Z"
        assert store.last_seen("missing") is None


def _old_store(path):
    """A store file as written before last_seen_at existed (schema version 0)."""
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE suggestions (suggestion_id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, "
        "confidence REAL NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);"
    )
    conn.execute(
        "INSERT INTO suggestions VALUES ('abc', 'ABNORMAL_ACCESS_TIME', 'PENDING', 0.7, ?, ?, ?)",
        (__import__("json").dumps(make_suggestion().to_dict()), NOW, LATER),
    )
    conn.commit()
    conn.close()


def test_old_store_is_migrated_on_open(tmp_path):
    path = str(tmp_path / "old.db")
    _old_store(path)
    with SuggestionStore(path) as store:
        assert store.last_seen("abc") == LATER  # backfilled from updated_at
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    with SuggestionStore(path) as store:  # opening again is a no-op
        assert store.get("abc").status == STATUS_PENDING


def test_read_only_open_of_an_old_store_asks_for_an_upgrade(tmp_path):
    path = str(tmp_path / "old.db")
    _old_store(path)
    with pytest.raises(SchemaTooOld, match="upgrade"):
        SuggestionStore(path, read_only=True)
    SuggestionStore(path).close()
    SuggestionStore(path, read_only=True).close()
