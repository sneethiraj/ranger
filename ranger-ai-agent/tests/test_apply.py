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
from ranger_ai_agent.suggestions.store import InvalidTransition, SuggestionStore
from ranger_ai_agent.synthetic import build_scenario

FIXED_CLOCK = datetime(2026, 6, 1, tzinfo=timezone.utc)
SID_REMOVE = suggestion_id_for("OVER_PRIVILEGED", 1, "carol")
SID_DISABLE = suggestion_id_for("STALE_POLICY", 9, None)
SID_REVIEW = suggestion_id_for("ABNORMAL_ACCESS_TIME", None, "dave")


class FakeRanger:
    """In-memory Ranger with the version semantics of the real policy API."""

    def __init__(self, policies):
        self.policies = {p["id"]: copy.deepcopy(p) for p in policies}
        self.writes = []
        self.fail_write = False
        self.ignore_writes = False

    def get_policy(self, policy_id):
        if policy_id not in self.policies:
            raise RangerApiError("GET policy returned HTTP 404")
        return copy.deepcopy(self.policies[policy_id])

    def update_policy(self, policy_id, body):
        self.writes.append((policy_id, copy.deepcopy(body)))
        if self.fail_write:
            raise RangerApiError("PUT policy returned HTTP 500")
        if self.ignore_writes:
            return {}
        stored = copy.deepcopy(body)
        stored["version"] = self.policies[policy_id]["version"] + 1
        self.policies[policy_id] = stored
        return copy.deepcopy(stored)

    def concurrent_edit(self, policy_id):
        """Simulate another administrator changing the policy after approval."""
        self.policies[policy_id]["version"] += 1


def build_world(safety=None, approve=(SID_REMOVE, SID_DISABLE)):
    sc = build_scenario()
    raw = {p["id"]: dict(copy.deepcopy(p), version=3) for p in sc.source.list_policies()}
    ranger = FakeRanger(raw.values())
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    findings = run_detectors(snap, DetectorConfig())

    store = SuggestionStore()
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


def test_write_that_does_not_take_effect_is_reported_and_not_recorded():
    store, ranger, applier, _, _ = build_world()
    ranger.ignore_writes = True
    got = outcomes(applier.apply_approved())
    assert got[SID_REMOVE] == ap.VERIFY_FAILED
    assert store.get(SID_REMOVE).status == STATUS_APPROVED
    assert store.count_applications_since("2000-01-01T00:00:00Z") == 0


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
