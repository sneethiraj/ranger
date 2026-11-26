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
from dataclasses import replace

from ranger_ai_agent.detectors import DetectorConfig, run_detectors
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.suggestions.models import (
    ACTION_DISABLE_POLICY,
    ACTION_REMOVE_USER,
    ACTION_REVIEW_ONLY,
    Proposal,
)
from ranger_ai_agent.suggestions.proposals import build_proposal, grants, remove_user, validate_proposal
from ranger_ai_agent.synthetic import build_scenario


def _scenario_findings():
    sc = build_scenario()
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    raw = {p["id"]: p for p in sc.source.list_policies()}
    return snap, run_detectors(snap, DetectorConfig()), raw


def _proposal_for(kind):
    _, findings, raw = _scenario_findings()
    finding = next(f for f in findings if f.kind == kind)
    return build_proposal(finding, raw.get(finding.policy_id))


def test_removal_drops_only_the_target_user():
    proposal = _proposal_for("OVER_PRIVILEGED")
    assert proposal.action == ACTION_REMOVE_USER
    assert proposal.target_user == "carol"
    remaining = proposal.after["policyItems"][0]["users"]
    assert remaining == ["alice", "bob", "dave"]
    assert validate_proposal(proposal) == []


def test_disable_proposal_keeps_grants_and_turns_policy_off():
    proposal = _proposal_for("STALE_POLICY")
    assert proposal.action == ACTION_DISABLE_POLICY
    assert proposal.after["isEnabled"] is False
    assert proposal.after["policyItems"] == proposal.before["policyItems"]
    assert validate_proposal(proposal) == []


def test_time_findings_produce_review_only_proposals():
    proposal = _proposal_for("ABNORMAL_ACCESS_TIME")
    assert proposal.action == ACTION_REVIEW_ONLY
    assert proposal.before is None and proposal.after is None
    assert validate_proposal(proposal) == []


def test_before_state_is_preserved_for_rollback():
    proposal = _proposal_for("OVER_PRIVILEGED")
    assert "carol" in proposal.before["policyItems"][0]["users"]


def test_validator_rejects_added_grant():
    proposal = _proposal_for("OVER_PRIVILEGED")
    tampered = copy.deepcopy(proposal.after)
    tampered["policyItems"][0]["users"].append("mallory")
    violations = validate_proposal(replace(proposal, after=tampered))
    assert any("adds" in v for v in violations)


def test_validator_rejects_wildcard_and_group_additions():
    proposal = _proposal_for("OVER_PRIVILEGED")
    tampered = copy.deepcopy(proposal.after)
    tampered["policyItems"][0]["groups"] = ["admins"]
    violations = validate_proposal(replace(proposal, after=tampered))
    assert any("adds" in v for v in violations)


def test_validator_rejects_reenabling_a_policy_on_disable():
    proposal = _proposal_for("STALE_POLICY")
    still_on = copy.deepcopy(proposal.before)
    violations = validate_proposal(replace(proposal, after=still_on))
    assert any("enabled" in v for v in violations)


def test_validator_rejects_changed_identity():
    proposal = _proposal_for("STALE_POLICY")
    renamed = copy.deepcopy(proposal.after)
    renamed["name"] = "something_else"
    assert any("'name'" in v for v in validate_proposal(replace(proposal, after=renamed)))


def test_validator_rejects_removal_of_other_principals():
    proposal = _proposal_for("OVER_PRIVILEGED")
    wrong_target = replace(proposal, target_user="alice")
    assert any("other principals" in v for v in validate_proposal(wrong_target))


def test_validator_enforces_protected_policies():
    proposal = _proposal_for("OVER_PRIVILEGED")
    assert any("protected" in v for v in validate_proposal(proposal, frozenset({1})))


def test_validator_rejects_missing_state():
    bare = Proposal(action=ACTION_DISABLE_POLICY, policy_id=9)
    assert "missing before or after" in validate_proposal(bare)[0]


def test_remove_user_drops_empty_items_but_keeps_groups():
    raw = {
        "id": 1,
        "policyItems": [
            {"users": ["carol"], "groups": [], "accesses": []},
            {"users": ["carol"], "groups": ["ops"], "accesses": []},
        ],
    }
    after = remove_user(raw, "carol")
    assert len(after["policyItems"]) == 1
    assert after["policyItems"][0]["groups"] == ["ops"]


def test_grants_ignore_denied_accesses():
    raw = {"policyItems": [{"users": ["a"], "accesses": [{"type": "select", "isAllowed": False}, {"type": "update"}]}]}
    assert grants(raw) == {("user:a", "update")}
