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
import json
from datetime import datetime, timezone

from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.detectors import DetectorConfig, run_detectors
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.report import build_insights, change_summary, render_insights
from ranger_ai_agent.suggestions.apply import Applier
from ranger_ai_agent.suggestions.models import ACTION_DISABLE_POLICY, suggestion_id_for
from ranger_ai_agent.suggestions.service import SuggestionService
from ranger_ai_agent.suggestions.store import SuggestionStore
from ranger_ai_agent.synthetic import build_scenario

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
SID_REMOVE = suggestion_id_for("OVER_PRIVILEGED", 1, "carol")
SID_DISABLE = suggestion_id_for("STALE_POLICY", 9, None)
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>'


class HostileModel:
    """Returns markup in its explanation, as a compromised or confused model might."""

    name = "hostile"
    external = False

    def complete_json(self, prompt):
        return json.dumps(
            {
                "summary": HOSTILE,
                "rationale": "<b>bold</b> & 'quotes'",
                "recommended_action": "REMOVE_USER_FROM_POLICY",
                "self_confidence": 0.5,
                "caveats": ["<i>caveat</i>"],
            }
        )


class FakeRanger:
    def __init__(self, policies):
        self.policies = {p["id"]: copy.deepcopy(p) for p in policies}

    def get_policy(self, policy_id):
        return copy.deepcopy(self.policies[policy_id])

    def update_policy(self, policy_id, body):
        stored = copy.deepcopy(body)
        stored["version"] = self.policies[policy_id]["version"] + 1
        self.policies[policy_id] = stored
        return copy.deepcopy(stored)


def populated_store(provider=None, apply_removal=False):
    sc = build_scenario()
    raw = {p["id"]: p for p in sc.source.list_policies()}
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    findings = run_detectors(snap, DetectorConfig())
    store = SuggestionStore()
    service = SuggestionService(store, provider=provider, safety=SafetyConfig(dry_run=True), clock=lambda: NOW)
    service.generate(snap, findings, copy.deepcopy(raw))
    service.approve(SID_REMOVE, "alice")
    if apply_removal:
        ranger = FakeRanger(sc.source.list_policies())
        Applier(store, ranger, ranger, safety=SafetyConfig(dry_run=False), clock=lambda: NOW, audit=sc.source).apply_approved()
    return store


def page(store, safety=None):
    return render_insights(store, safety or SafetyConfig(), NOW)


def test_hostile_model_output_is_escaped_everywhere():
    store = populated_store(provider=HostileModel())
    text = page(store)
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "<script" not in text.lower()
    assert "<img" not in text.lower()
    assert "&lt;b&gt;bold&lt;/b&gt;" in text
    assert "&lt;i&gt;caveat&lt;/i&gt;" in text


def test_page_has_no_scripts_and_a_strict_content_security_policy():
    text = page(populated_store())
    assert "Content-Security-Policy" in text
    assert "default-src 'none'" in text
    assert "<script" not in text.lower()
    assert "<form" not in text.lower()


def test_status_counts_and_pending_section():
    text = page(populated_store())
    assert "Awaiting review (2)" in text  # dave's and erin's suggestions are still pending
    assert "Reviewed and applied (1)" in text  # carol's is approved
    assert "Action log" in text and "intact" in text


def test_change_summaries_are_plain_language():
    store = populated_store()
    by_id = {s.suggestion_id: s for s in store.list()}
    assert change_summary(by_id[SID_REMOVE]) == "remove carol from policy 1"
    assert change_summary(by_id[SID_DISABLE]) == "disable policy 9"
    assert "review only" in change_summary(by_id[suggestion_id_for("ABNORMAL_ACCESS_TIME", None, "dave")])
    assert by_id[SID_DISABLE].proposal.action == ACTION_DISABLE_POLICY


def test_applied_changes_show_versions_and_state():
    text = page(populated_store(apply_removal=True))
    assert "Applied changes" in text
    assert "1 → 2" in text  # synthetic policies start at version 1
    assert "active" in text


def test_rolled_back_state_is_shown():
    store = populated_store(apply_removal=True)
    ranger_before = store.active_application(SID_REMOVE)
    assert ranger_before is not None
    store.commit_rollback(ranger_before["application_id"], SID_REMOVE, "2026-06-01T00:00:00Z", "bob")
    text = page(store)
    assert "rolled back 2026-06-01T00:00:00Z by bob" in text


def test_tampered_log_is_reported_in_the_page():
    store = populated_store()
    # Tamper through the store's own connection, bypassing the append-only triggers.
    store._conn.execute("DROP TRIGGER action_log_no_update")
    store._conn.execute("UPDATE action_log SET actor = 'mallory' WHERE log_id = 1")
    text = page(store)
    assert "FAILED verification" in text


def test_build_insights_is_json_serializable_and_summarizes_changes():
    store = populated_store(apply_removal=True)
    data = build_insights(store, SafetyConfig(dry_run=False), NOW)
    json.dumps(data)  # must not raise
    assert data["counts"]["APPLIED"] == 1
    assert data["counts"]["PENDING"] == 2
    assert data["applications"][0]["version_after"] == 2
    by_id = {s["id"]: s for s in data["suggestions"]}
    assert by_id[SID_REMOVE]["change"] == "remove carol from policy 1"
    assert by_id[SID_REMOVE]["reviewed_by"] == "alice"
    assert data["mode"]["dry_run"] is False


def test_build_insights_log_is_newest_first_and_limited():
    store = populated_store()
    data = build_insights(store, SafetyConfig(), NOW, log_limit=2)
    assert len(data["recent_log"]) == 2
    assert data["action_log"]["entries"] > 2
    assert data["recent_log"][0]["action"] == "APPROVED"  # carol's approval is the latest entry
    assert set(data["recent_log"][0]) == {"ts", "actor", "action", "suggestion_id"}  # details are not exposed


def test_empty_store_renders_placeholders():
    text = page(SuggestionStore())
    assert "No suggestions yet." in text
    assert "No changes applied." in text
    assert "Log is empty." in text


def test_safety_state_is_shown():
    text = page(SuggestionStore(), SafetyConfig(kill_switch=True, dry_run=True, max_changes_per_day=3))
    assert "dry run (no changes written)" in text
    assert "ON: all agent actions stopped" in text
    assert "Daily change cap</th><td>3" in text
