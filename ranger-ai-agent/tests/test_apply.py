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

import copy
from datetime import datetime, timezone

import pytest

from ranger_ai_agent.clients.ranger_admin import RangerApiError
from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.detectors import DetectorConfig, run_detectors
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.suggestions import apply as ap
from ranger_ai_agent.suggestions.models import (
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_ROLLED_BACK,
    suggestion_id_for,
)
from ranger_ai_agent.suggestions.service import SuggestionService
from ranger_ai_agent.suggestions.store import InvalidTransition, LogKeyRequired, SuggestionStore
from ranger_ai_agent.synthetic import build_scenario

FIXED_CLOCK = datetime(2026, 6, 1, tzinfo=timezone.utc)
SID_REMOVE = suggestion_id_for("OVER_PRIVILEGED", 1, "carol")
SID_DISABLE = suggestion_id_for("STALE_POLICY", 9, None)
SID_REVIEW = suggestion_id_for("ABNORMAL_ACCESS_TIME", None, "dave")


class Crash(Exception):
    """Stands in for the agent process dying in the middle of a write."""


class FakeRanger:
    """In-memory Ranger with the version semantics of the real policy API."""

    def __init__(self, policies):
        self.policies = {p["id"]: copy.deepcopy(p) for p in policies}
        self.writes = []
        self.fail_write = False
        self.ignore_writes = False
        self.raise_after_write = False  # the change is saved, then the call fails (a timeout)
        self.fail_reads_after_write = False
        self.mangle = False  # Ranger saves something other than what was sent
        self.crash = None  # "before" or "after" the save: the process dies mid-write

    def get_policy(self, policy_id):
        if self.fail_reads_after_write and self.writes:
            raise RangerApiError("GET policy timed out")
        if policy_id not in self.policies:
            raise RangerApiError("GET policy returned HTTP 404")
        return copy.deepcopy(self.policies[policy_id])

    def update_policy(self, policy_id, body):
        self.writes.append((policy_id, copy.deepcopy(body)))
        if self.crash == "before":
            raise Crash()
        if self.fail_write:
            raise RangerApiError("PUT policy returned HTTP 500")
        if self.ignore_writes:
            return {}
        stored = copy.deepcopy(body)
        stored["version"] = self.policies[policy_id]["version"] + 1
        if self.mangle:
            stored["policyItems"] = []
        self.policies[policy_id] = stored
        if self.crash == "after":
            raise Crash()
        if self.raise_after_write:
            raise RangerApiError("PUT policy timed out")
        return copy.deepcopy(stored)

    def concurrent_edit(self, policy_id):
        """Simulate another administrator changing the policy after approval."""
        self.policies[policy_id]["version"] += 1


LOG_KEY = b"test-action-log-key-0123456789abcdef"


def build_world(safety=None, approve=(SID_REMOVE, SID_DISABLE), log_key=LOG_KEY):
    sc = build_scenario()
    raw = {p["id"]: dict(copy.deepcopy(p), version=3) for p in sc.source.list_policies()}
    ranger = FakeRanger(raw.values())
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    findings = run_detectors(snap, DetectorConfig())

    store = SuggestionStore(log_key=log_key)
    service = SuggestionService(store, safety=SafetyConfig(dry_run=True), clock=lambda: FIXED_CLOCK)
    service.generate(snap, findings, copy.deepcopy(raw))
    for sid in approve:
        service.approve(sid, "alice")

    safety = safety or SafetyConfig(kill_switch=False, dry_run=False, max_changes_per_day=5)
    applier = ap.Applier(store, ranger, ranger, safety=safety, clock=lambda: FIXED_CLOCK, audit=sc.source)
    return store, ranger, applier, service, safety


def outcomes(results):
    return {r.suggestion_id: r.outcome for r in results}


def test_dry_run_is_the_default_and_writes_nothing():
    store, ranger, applier, _, _ = build_world(safety=SafetyConfig())
    results = applier.apply_approved()
    assert ranger.writes == []
    assert outcomes(results)[SID_REMOVE] == ap.DRY_RUN
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert store.verify_log() is True


def test_apply_writes_policy_and_marks_suggestion_applied():
    store, ranger, applier, _, _ = build_world()
    before_remove = copy.deepcopy(ranger.policies[1])
    results = applier.apply_approved()
    got = outcomes(results)

    assert got[SID_REMOVE] == ap.APPLIED
    assert got[SID_DISABLE] == ap.APPLIED
    assert SID_REVIEW not in got  # not approved in this world, so never considered
    assert len(ranger.writes) == 2

    live1 = ranger.policies[1]
    assert live1["policyItems"][0]["users"] == ["alice", "bob", "dave"]
    assert live1["version"] == before_remove["version"] + 1
    assert ranger.policies[9]["isEnabled"] is False

    assert store.get(SID_REMOVE).status == STATUS_APPLIED
    assert store.get(SID_DISABLE).status == STATUS_APPLIED
    assert store.get(SID_REMOVE).reviewed_by == "alice"  # approver is kept, not overwritten by the agent
    assert store.active_application(SID_REMOVE)["version_after"] == live1["version"]
    assert store.verify_log() is True


def test_review_only_suggestions_are_never_written():
    store, ranger, applier, _, _ = build_world(approve=(SID_REMOVE, SID_DISABLE, SID_REVIEW))
    got = outcomes(applier.apply_approved())
    assert got[SID_REVIEW] == ap.NO_POLICY_CHANGE
    assert sorted(pid for pid, _ in ranger.writes) == [1, 9]
    assert len(ranger.writes) == 2
    assert store.get(SID_REVIEW).status == STATUS_APPROVED


def test_pending_suggestions_are_not_applied():
    store, ranger, applier, _, _ = build_world(approve=())
    assert applier.apply_approved() == []
    assert ranger.writes == []
    assert store.get(SID_REMOVE).status == STATUS_PENDING


def test_second_run_does_not_reapply():
    store, ranger, applier, _, _ = build_world()
    applier.apply_approved()
    writes_after_first = len(ranger.writes)
    assert applier.apply_approved() == []
    assert len(ranger.writes) == writes_after_first


def test_kill_switch_blocks_apply():
    store, ranger, applier, _, _ = build_world(safety=SafetyConfig(kill_switch=True, dry_run=False))
    results = applier.apply_approved()
    assert {r.outcome for r in results} == {ap.KILL_SWITCH}
    assert ranger.writes == []
    assert store.get(SID_REMOVE).status == STATUS_APPROVED


def test_conflict_when_live_policy_changed_after_approval():
    store, ranger, applier, _, _ = build_world()
    ranger.concurrent_edit(1)
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.CONFLICT
    assert ranger.policies[1]["policyItems"][0]["users"] == ["alice", "bob", "dave", "carol"]  # untouched
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert got[SID_DISABLE] == ap.APPLIED  # other suggestions still proceed


def test_daily_cap_limits_real_writes():
    store, ranger, applier, _, _ = build_world(safety=SafetyConfig(dry_run=False, max_changes_per_day=1))
    results = applier.apply_approved()
    assert [r.outcome for r in results].count(ap.APPLIED) == 1
    assert [r.outcome for r in results].count(ap.CAP_REACHED) == 1
    assert len(ranger.writes) == 1
    assert [e["action"] for e in store.log_entries()].count(ap.CAP_REACHED) == 1


def test_daily_cap_also_limits_dry_run_plans():
    store, ranger, applier, _, _ = build_world(safety=SafetyConfig(dry_run=True, max_changes_per_day=1))
    results = applier.apply_approved()
    assert sorted(r.outcome for r in results) == sorted([ap.DRY_RUN, ap.CAP_REACHED])
    assert ranger.writes == []


def test_cap_counts_applications_inside_the_window_only():
    store, ranger, applier, _, _ = build_world(safety=SafetyConfig(dry_run=False, max_changes_per_day=1))
    # An application from well outside the 24-hour window must not count against the cap.
    store._conn.execute(
        "INSERT INTO applications (suggestion_id, policy_id, applied_at, applied_by, version_before, version_after) "
        "VALUES ('old', 1, '2026-05-01T00:00:00Z', 'agent', 1, 2)"
    )
    results = applier.apply_approved()
    assert ap.APPLIED in [r.outcome for r in results]


def test_protected_policy_is_refused_at_apply_time():
    safety = SafetyConfig(dry_run=False)
    store, ranger, applier, _, _ = build_world(safety=safety)
    safety.protected_policy_ids = frozenset({9})  # protected after approval
    got = outcomes(applier.apply_approved())
    assert got[SID_DISABLE] == ap.REFUSED
    assert ranger.policies[9]["isEnabled"] is True
    assert store.get(SID_DISABLE).status == STATUS_APPROVED


def test_failed_write_leaves_suggestion_approved():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_write = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.FAILED
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert store.active_application(SID_REMOVE) is None


def test_write_that_does_not_take_effect_is_recorded_as_aborted():
    store, ranger, applier, _, _ = build_world()
    ranger.ignore_writes = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.VERIFY_FAILED
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert store.active_application(SID_REMOVE) is None
    assert {a["state"] for a in store.list_applications()} == {"ABORTED"}
    # the attempts still count toward the daily cap, so a failing write is not retried without limit
    assert store.count_applications_since("2000-01-01T00:00:00Z") == 2


def test_missing_policy_is_reported_as_failure():
    store, ranger, applier, _, _ = build_world()
    del ranger.policies[9]
    got = outcomes(applier.apply_approved())
    assert got[SID_DISABLE] == ap.FAILED


def test_rollback_restores_the_pre_change_policy():
    store, ranger, applier, _, _ = build_world()
    original = copy.deepcopy(ranger.policies[1])
    applier.apply_approved()

    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.ROLLED_BACK
    assert ranger.policies[1]["policyItems"] == original["policyItems"]
    assert ranger.policies[1]["isEnabled"] == original["isEnabled"]
    assert store.get(SID_REMOVE).status == STATUS_ROLLED_BACK
    assert store.active_application(SID_REMOVE) is None
    assert store.verify_log() is True


def test_rollback_refuses_if_policy_changed_since_agent_write():
    store, ranger, applier, _, _ = build_world()
    applier.apply_approved()
    ranger.concurrent_edit(1)
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.CONFLICT
    assert store.get(SID_REMOVE).status == STATUS_APPLIED


def test_rollback_requires_a_named_human():
    store, ranger, applier, _, _ = build_world()
    applier.apply_approved()
    for name in ("", "  ", "agent", "AGENT"):
        with pytest.raises(ValueError, match="named human"):
            applier.rollback(SID_REMOVE, name)


def test_rollback_only_applies_to_applied_suggestions():
    store, ranger, applier, _, _ = build_world()
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.NOT_APPLIED


def test_rollback_blocked_by_kill_switch():
    store, ranger, applier, _, safety = build_world()
    applier.apply_approved()
    safety.kill_switch = True
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.KILL_SWITCH
    assert store.get(SID_REMOVE).status == STATUS_APPLIED


def test_rollback_dry_run_does_not_write():
    store, ranger, applier, _, safety = build_world()
    applier.apply_approved()
    safety.dry_run = True
    writes = len(ranger.writes)
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.DRY_RUN
    assert len(ranger.writes) == writes
    assert store.get(SID_REMOVE).status == STATUS_APPLIED


def test_applied_suggestion_cannot_be_reviewed_again():
    store, ranger, applier, service, _ = build_world()
    applier.apply_approved()
    with pytest.raises(InvalidTransition):
        service.reject(SID_REMOVE, "bob")


def test_action_log_records_applies_and_rollbacks_with_hashes():
    store, ranger, applier, _, _ = build_world()
    applier.apply_approved()
    applier.rollback(SID_REMOVE, "bob")
    entries = store.log_entries()
    applied = [e for e in entries if e["action"] == ap.APPLIED]
    assert len(applied) == 2
    assert all(len(e["details"]["before_sha256"]) == 64 for e in applied)
    assert any(e["action"] == ap.ROLLED_BACK and e["actor"] == "bob" for e in entries)
    assert store.verify_log() is True


def test_store_rejects_applied_status_without_approval_or_write():
    store, ranger, applier, _, _ = build_world(approve=())
    with pytest.raises(InvalidTransition):
        store.transition(SID_REMOVE, STATUS_APPLIED, "agent", "2026-06-01T00:00:00Z")  # pending -> applied is not a lifecycle move


# --- evidence must be current and unchanged before a write ---

from datetime import timedelta  # noqa: E402

from ranger_ai_agent.clients.solr_audit import PolicyUsage, SolrAuditError, UserPolicyUsage  # noqa: E402
from ranger_ai_agent.suggestions.models import STATUS_EXPIRED  # noqa: E402


class FakeAudit:
    """Audit source for the re-check: usage since the snapshot, or an outage."""

    def __init__(self, user_usage=(), policy_usage=(), error=None):
        self.user_usage = list(user_usage)
        self.policies = list(policy_usage)
        self.error = error
        self.windows = []

    def _check(self, start, end):
        self.windows.append((start, end))
        if self.error:
            raise self.error

    def user_usage_for_policy(self, policy_id, start, end):
        self._check(start, end)
        return [u for pid, u in self.user_usage if pid == policy_id]

    def policy_usage(self, start, end):
        self._check(start, end)
        return self.policies


def applier_for(store, ranger, safety, audit, clock=FIXED_CLOCK):
    return ap.Applier(store, ranger, ranger, safety=safety, clock=lambda: clock, audit=audit)


def test_evidence_older_than_the_limit_is_not_applied():
    store, ranger, _, _, safety = build_world()
    late = applier_for(store, ranger, safety, FakeAudit(), clock=FIXED_CLOCK + timedelta(hours=49))
    got = outcomes(late.apply_approved())
    assert got == {SID_REMOVE: ap.STALE_EVIDENCE, SID_DISABLE: ap.STALE_EVIDENCE}
    assert ranger.writes == []
    assert store.get(SID_REMOVE).status == STATUS_APPROVED  # a fresh suggest run can confirm it again


def test_evidence_within_the_limit_is_applied():
    store, ranger, _, _, safety = build_world()
    ok = applier_for(store, ranger, safety, FakeAudit(), clock=FIXED_CLOCK + timedelta(hours=47))
    assert set(outcomes(ok.apply_approved()).values()) == {ap.APPLIED}


def test_removal_is_expired_when_the_user_has_used_the_policy_since():
    store, ranger, _, _, safety = build_world()
    audit = FakeAudit(user_usage=[(1, UserPolicyUsage("carol", 3, "2026-05-31T10:00:00Z"))])
    got = outcomes(applier_for(store, ranger, safety, audit).apply_approved())
    assert got[SID_REMOVE] == ap.EVIDENCE_CHANGED
    assert got[SID_DISABLE] == ap.APPLIED
    assert [pid for pid, _ in ranger.writes] == [9]
    assert store.get(SID_REMOVE).status == STATUS_EXPIRED
    # the window starts at the snapshot the suggestion was built from
    assert audit.windows[0][0] == datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert store.verify_log() is True


def test_other_users_activity_does_not_block_the_removal():
    store, ranger, _, _, safety = build_world()
    audit = FakeAudit(user_usage=[(1, UserPolicyUsage("alice", 50, None))])
    assert outcomes(applier_for(store, ranger, safety, audit).apply_approved())[SID_REMOVE] == ap.APPLIED


def test_disable_is_expired_when_the_policy_has_been_used_since():
    store, ranger, _, _, safety = build_world()
    audit = FakeAudit(policy_usage=[PolicyUsage(9, 1, "2026-05-31T10:00:00Z")])
    got = outcomes(applier_for(store, ranger, safety, audit).apply_approved())
    assert got[SID_DISABLE] == ap.EVIDENCE_CHANGED
    assert ranger.policies[9]["isEnabled"] is True
    assert store.get(SID_DISABLE).status == STATUS_EXPIRED


def test_evidence_change_is_also_caught_in_dry_run():
    store, ranger, _, _, _ = build_world()
    audit = FakeAudit(policy_usage=[PolicyUsage(9, 1, None)])
    got = outcomes(applier_for(store, ranger, SafetyConfig(), audit).apply_approved())
    assert got[SID_DISABLE] == ap.EVIDENCE_CHANGED
    assert got[SID_REMOVE] == ap.DRY_RUN


def test_audit_outage_fails_the_write_safely():
    store, ranger, _, _, safety = build_world()
    audit = FakeAudit(error=SolrAuditError("Solr returned HTTP 503"))
    got = outcomes(applier_for(store, ranger, safety, audit).apply_approved())
    assert set(got.values()) == {ap.FAILED}
    assert ranger.writes == []
    assert store.get(SID_REMOVE).status == STATUS_APPROVED


def test_live_writes_need_an_audit_source_but_dry_runs_do_not():
    store, ranger, _, _, safety = build_world()
    assert set(outcomes(applier_for(store, ranger, safety, None).apply_approved()).values()) == {ap.REFUSED}
    assert ranger.writes == []
    assert set(outcomes(applier_for(store, ranger, SafetyConfig(), None).apply_approved()).values()) == {ap.DRY_RUN}


# --- every write is recorded before it is sent, and settled from what Ranger holds ---

from ranger_ai_agent.suggestions.models import STATUS_NEEDS_ATTENTION  # noqa: E402


def only(store, sid):
    rows = [a for a in store.list_applications() if a["suggestion_id"] == sid]
    assert len(rows) == 1
    return rows[0]


def test_write_that_errors_but_was_saved_is_recorded_as_applied():
    store, ranger, applier, _, _ = build_world()
    ranger.raise_after_write = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.APPLIED
    assert store.get(SID_REMOVE).status == STATUS_APPLIED
    assert only(store, SID_REMOVE)["state"] == "APPLIED"
    assert only(store, SID_REMOVE)["version_after"] == 4
    assert applier.rollback(SID_REMOVE, "bob").outcome == ap.ROLLED_BACK  # now reachable by rollback


def test_unreadable_policy_after_write_needs_attention():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_reads_after_write = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.NEEDS_ATTENTION
    assert store.get(SID_REMOVE).status == STATUS_NEEDS_ATTENTION
    row = only(store, SID_REMOVE)
    assert (row["state"], row["version_after"]) == ("UNCERTAIN", None)
    assert store.verify_log() is True


def test_policy_matching_neither_side_needs_attention_with_its_version():
    store, ranger, applier, _, _ = build_world()
    ranger.mangle = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.NEEDS_ATTENTION
    assert only(store, SID_REMOVE)["version_after"] == 4


def test_needs_attention_is_not_retried_and_not_expired():
    store, ranger, applier, service, _ = build_world(approve=(SID_REMOVE,))
    ranger.fail_reads_after_write = True
    applier.apply_approved()
    ranger.fail_reads_after_write = False
    writes = len(ranger.writes)
    assert SID_REMOVE not in outcomes(applier.apply_approved())
    assert len(ranger.writes) == writes
    assert SID_REMOVE not in store.expire_missing(set(), "2026-06-01T00:00:00Z", "agent")
    assert store.get(SID_REMOVE).status == STATUS_NEEDS_ATTENTION


def test_uncertain_attempts_count_toward_the_daily_cap():
    store, ranger, _, _, _ = build_world()
    ranger.fail_reads_after_write = True
    capped = applier_for(store, ranger, SafetyConfig(dry_run=False, max_changes_per_day=1), FakeAudit())
    assert sorted(outcomes(capped.apply_approved()).values()) == [ap.CAP_REACHED, ap.NEEDS_ATTENTION]


def test_cap_is_not_double_counted_within_a_run():
    store, ranger, _, _, _ = build_world()
    two = applier_for(store, ranger, SafetyConfig(dry_run=False, max_changes_per_day=2), FakeAudit())
    assert set(outcomes(two.apply_approved()).values()) == {ap.APPLIED}


def test_crash_after_save_is_recovered_as_applied_without_writing_again():
    store, ranger, applier, _, _ = build_world(approve=(SID_REMOVE,))
    ranger.crash = "after"
    with pytest.raises(Crash):
        applier.apply_approved()
    assert only(store, SID_REMOVE)["state"] == "IN_FLIGHT"

    ranger.crash = None
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.APPLIED
    assert len(ranger.writes) == 1
    assert store.get(SID_REMOVE).status == STATUS_APPLIED
    assert store.verify_log() is True


def test_crash_before_save_is_recovered_as_aborted_and_then_retried():
    store, ranger, applier, _, _ = build_world(approve=(SID_REMOVE,))
    ranger.crash = "before"
    with pytest.raises(Crash):
        applier.apply_approved()

    ranger.crash = None
    results = applier.apply_approved()
    assert [r.outcome for r in results] == [ap.FAILED, ap.APPLIED]  # recovery, then the retry
    states = [a["state"] for a in store.list_applications()]
    assert states == ["ABORTED", "APPLIED"]


def test_reconcile_confirms_a_write_that_did_happen():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_reads_after_write = True
    applier.apply_approved()
    ranger.fail_reads_after_write = False

    result = applier.reconcile(SID_REMOVE, "carol-admin")
    assert result.outcome == ap.APPLIED
    assert store.get(SID_REMOVE).status == STATUS_APPLIED
    assert store.active_application(SID_REMOVE)["version_after"] == ranger.policies[1]["version"]
    assert any(e["action"] == STATUS_APPLIED and e["actor"] == "carol-admin" for e in store.log_entries())


def test_reconcile_reopens_a_write_that_did_not_happen():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_reads_after_write = True
    original = copy.deepcopy(ranger.policies[1])
    applier.apply_approved()
    ranger.fail_reads_after_write = False
    ranger.policies[1] = original  # it turns out the change never landed

    result = applier.reconcile(SID_REMOVE, "bob")
    assert result.outcome == ap.ABORTED
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert only(store, SID_REMOVE)["state"] == "ABORTED"


def test_reconcile_of_a_mangled_policy_records_its_version_so_rollback_can_restore():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_reads_after_write = True
    original = copy.deepcopy(ranger.policies[1])
    ranger.mangle = True
    applier.apply_approved()
    ranger.fail_reads_after_write = False

    assert applier.reconcile(SID_REMOVE, "bob").outcome == ap.CONFLICT
    assert only(store, SID_REMOVE)["version_after"] == ranger.policies[1]["version"]
    ranger.mangle = False
    assert applier.rollback(SID_REMOVE, "bob").outcome == ap.ROLLED_BACK
    assert ranger.policies[1]["policyItems"] == original["policyItems"]
    assert store.get(SID_REMOVE).status == STATUS_ROLLED_BACK


def test_reconcile_needs_a_human_and_a_suggestion_needing_attention():
    store, ranger, applier, _, _ = build_world()
    with pytest.raises(ValueError, match="named human"):
        applier.reconcile(SID_REMOVE, "agent")
    assert applier.reconcile(SID_REMOVE, "bob").outcome == ap.NOTHING_TO_RECONCILE


def test_rollback_with_an_unknown_version_asks_for_reconcile():
    store, ranger, applier, _, _ = build_world()
    ranger.fail_reads_after_write = True
    ranger.mangle = True
    applier.apply_approved()
    ranger.fail_reads_after_write = False
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.REFUSED and "reconcile" in result.detail


def test_rollback_whose_read_back_failed_completes_on_the_next_try():
    store, ranger, applier, _, _ = build_world()
    applier.apply_approved()

    real_get = ranger.get_policy
    reads = []

    def read_back_fails_once(policy_id):
        reads.append(policy_id)
        if len(reads) == 2:  # the read-back right after the rollback write
            raise RangerApiError("GET policy timed out")
        return real_get(policy_id)

    ranger.get_policy = read_back_fails_once
    assert applier.rollback(SID_REMOVE, "bob").outcome == ap.VERIFY_FAILED
    assert store.get(SID_REMOVE).status == STATUS_APPLIED
    # The live version moved, but the policy matches the original, so the retry records the rollback.
    assert applier.rollback(SID_REMOVE, "bob").outcome == ap.ROLLED_BACK
    assert store.get(SID_REMOVE).status == STATUS_ROLLED_BACK
    assert len(ranger.writes) == 3  # two applies and one rollback; the retry does not write again


def test_live_apply_needs_a_signed_log():
    store, ranger, applier, service, safety = build_world(log_key=None)
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == got[SID_DISABLE] == ap.LOG_KEY_REQUIRED
    assert ranger.writes == []
    assert store.list_applications() == []


def test_dry_run_does_not_need_a_log_key():
    store, ranger, applier, service, safety = build_world(safety=SafetyConfig(dry_run=True), log_key=None)
    assert set(outcomes(applier.apply_approved()).values()) == {ap.DRY_RUN}


def test_rollback_writes_nothing_without_the_key():
    store, ranger, applier, service, safety = build_world()
    assert outcomes(applier.apply_approved())[SID_REMOVE] == ap.APPLIED
    writes = len(ranger.writes)
    keyless = SuggestionStore.__new__(SuggestionStore)  # the same rows, opened without the key
    keyless._conn, keyless._key = store._conn, None
    with pytest.raises(LogKeyRequired):
        ap.Applier(keyless, ranger, ranger, safety=safety, clock=lambda: FIXED_CLOCK, audit=applier._audit).rollback(SID_REMOVE, "bob")
    assert len(ranger.writes) == writes


# --- approvals are read from the signed log, not from the status column ---

import json as _json  # noqa: E402

from ranger_ai_agent.suggestions import store as st  # noqa: E402


def _edit_row(store, sid, status=None, after=None, before=None):
    """Change a suggestion row directly, as someone who can write the database file could."""
    data = store.get(sid).to_dict()
    if status:
        data["status"] = status
    if after is not None:
        data["proposal"]["after"] = after
    if before is not None:
        data["proposal"]["before"] = before
    store._conn.execute(
        "UPDATE suggestions SET status = ?, payload = ? WHERE suggestion_id = ?",
        (data["status"], _json.dumps(data, sort_keys=True), sid),
    )
    store._conn.commit()


def test_status_set_to_approved_in_the_database_is_not_applied():
    store, ranger, applier, service, safety = build_world(approve=(SID_REMOVE,))
    _edit_row(store, SID_DISABLE, status=STATUS_APPROVED)
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.APPLIED
    assert got[SID_DISABLE] == ap.APPROVAL_UNVERIFIED
    assert [w[0] for w in ranger.writes] == [1]


def test_proposal_edited_after_approval_is_not_applied():
    store, ranger, applier, service, safety = build_world(approve=(SID_REMOVE,))
    # Retarget the removal from carol to bob. It passes validation, but it is not what alice approved.
    data = store.get(SID_REMOVE).to_dict()
    proposal = data["proposal"]
    proposal["target_user"] = "bob"
    proposal["after"] = copy.deepcopy(proposal["before"])
    proposal["after"]["policyItems"][0]["users"].remove("bob")
    assert ap.validate_proposal(ap.Suggestion.from_dict(data).proposal, safety.protected_policy_ids) == []
    store._conn.execute("UPDATE suggestions SET payload = ? WHERE suggestion_id = ?", (_json.dumps(data, sort_keys=True), SID_REMOVE))
    result = applier.apply_approved()
    assert outcomes(result)[SID_REMOVE] == ap.APPROVAL_UNVERIFIED
    assert "not the one that was approved" in result[0].detail
    assert ranger.writes == []


def test_forged_unsigned_approval_entry_blocks_every_write():
    store, ranger, applier, service, safety = build_world(approve=(SID_REMOVE,))
    _edit_row(store, SID_DISABLE, status=STATUS_APPROVED)
    last = store.log_entries()[-1]["entry_hash"]
    details = {"proposal_sha256": ap.proposal_digest(store.get(SID_DISABLE))}
    h = st._entry_hash(last, "2026-06-01T00:00:00Z", "alice", STATUS_APPROVED, SID_DISABLE, st._canonical(details))
    store._conn.execute(
        "INSERT INTO action_log (ts, actor, action, suggestion_id, details, prev_hash, entry_hash, hash_alg) "
        "VALUES (?, 'alice', 'APPROVED', ?, ?, ?, ?, 'sha256')",
        ("2026-06-01T00:00:00Z", SID_DISABLE, st._canonical(details), last, h),
    )
    got = outcomes(applier.apply_approved())
    assert set(got.values()) == {ap.APPROVAL_UNVERIFIED}
    assert ranger.writes == []


def test_approval_made_before_binding_must_be_renewed():
    store, ranger, applier, service, safety = build_world(approve=())
    # An approval as recorded by earlier versions: a signed APPROVED entry with no digest.
    _edit_row(store, SID_REMOVE, status=STATUS_APPROVED)
    store.log("2026-06-01T00:00:00Z", "alice", STATUS_APPROVED, SID_REMOVE, {})
    result = applier.apply_approved()
    assert outcomes(result)[SID_REMOVE] == ap.APPROVAL_UNVERIFIED and "run approve again" in result[0].detail
    service.approve(SID_REMOVE, "alice")  # APPROVED -> APPROVED records a bound approval
    assert outcomes(applier.apply_approved())[SID_REMOVE] == ap.APPLIED


def test_unsigned_approval_is_not_accepted_once_the_log_is_signed(tmp_path):
    path = str(tmp_path / "s.db")
    sc = build_scenario()
    raw = {p["id"]: dict(copy.deepcopy(p), version=3) for p in sc.source.list_policies()}
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    with SuggestionStore(path) as unsigned:
        service = SuggestionService(unsigned, safety=SafetyConfig(dry_run=True), clock=lambda: FIXED_CLOCK)
        service.generate(snap, run_detectors(snap, DetectorConfig()), copy.deepcopy(raw))
        service.approve(SID_REMOVE, "alice")
    ranger = FakeRanger(raw.values())
    safety = SafetyConfig(kill_switch=False, dry_run=False, max_changes_per_day=5)
    with SuggestionStore(path, log_key=LOG_KEY) as store:
        applier = ap.Applier(store, ranger, ranger, safety=safety, clock=lambda: FIXED_CLOCK, audit=sc.source)
        result = applier.apply_approved()
        assert outcomes(result)[SID_REMOVE] == ap.APPROVAL_UNVERIFIED and "signed" in result[0].detail
        SuggestionService(store, clock=lambda: FIXED_CLOCK).approve(SID_REMOVE, "alice")
        assert outcomes(applier.apply_approved())[SID_REMOVE] == ap.APPLIED


def test_rollback_refuses_an_edited_original():
    store, ranger, applier, service, safety = build_world(approve=(SID_REMOVE,))
    assert outcomes(applier.apply_approved())[SID_REMOVE] == ap.APPLIED
    writes = len(ranger.writes)
    tampered = copy.deepcopy(store.get(SID_REMOVE).proposal.before)
    tampered["policyItems"][0]["users"].append("mallory")
    _edit_row(store, SID_REMOVE, before=tampered)
    result = applier.rollback(SID_REMOVE, "bob")
    assert result.outcome == ap.APPROVAL_UNVERIFIED
    assert len(ranger.writes) == writes


def test_approval_digest_is_recorded_and_reset_by_a_new_proposal():
    store, ranger, applier, service, safety = build_world(approve=(SID_REMOVE,))
    entry = store.approval_entry(SID_REMOVE)
    assert entry["actor"] == "alice" and entry["hash_alg"] == "hmac-sha256"
    assert entry["details"]["proposal_sha256"] == ap.proposal_digest(store.get(SID_REMOVE))
    assert store.approval_entry(SID_DISABLE) is None
