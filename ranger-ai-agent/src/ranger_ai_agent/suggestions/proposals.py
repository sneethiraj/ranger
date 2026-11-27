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

"""Builds candidate policy changes and checks them before they are stored.

Safety rule: a proposal may only remove grants or disable a policy. It can
never add a principal, add an access type, re-enable a policy, or change a
policy's identity. Admin and wildcard grants therefore cannot be introduced.

Each action may change exactly one field (policyItems for a removal, isEnabled
for a disable); every other field must be identical. A policy that denies,
masks or filters rows is never disabled, because that would widen access.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from ranger_ai_agent.detectors.core import Finding
from ranger_ai_agent.detectors.rules import KIND_OVER_PRIVILEGED, KIND_STALE_POLICY
from ranger_ai_agent.models import POLICY_TYPE_ACCESS, is_macro_user, restricts_access
from ranger_ai_agent.suggestions.models import (
    ACTION_DISABLE_POLICY,
    ACTION_REMOVE_USER,
    ACTION_REVIEW_ONLY,
    Proposal,
)

# The only field each action may change.
_CHANGEABLE_FIELD = {ACTION_REMOVE_USER: "policyItems", ACTION_DISABLE_POLICY: "isEnabled"}

Grant = Tuple[str, str]  # (principal such as "user:alice", access type such as "select")


def names_in_policy(raw: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for item in raw.get("policyItems") or []:
        names.update(item.get("users") or [])
    return names


def grants(raw: Dict[str, Any]) -> Set[Grant]:
    """Allowed (principal, access) pairs from policy items."""
    pairs: Set[Grant] = set()
    for item in raw.get("policyItems") or []:
        principals = ["user:%s" % u for u in item.get("users") or []]
        principals += ["group:%s" % g for g in item.get("groups") or []]
        principals += ["role:%s" % r for r in item.get("roles") or []]
        for access in item.get("accesses") or []:
            if not access.get("isAllowed", True):
                continue
            for principal in principals:
                pairs.add((principal, str(access.get("type", ""))))
    return pairs


def remove_user(raw: Dict[str, Any], user: str) -> Dict[str, Any]:
    after = copy.deepcopy(raw)
    kept = []
    for item in after.get("policyItems") or []:
        users = [u for u in item.get("users") or [] if u != user]
        if users or item.get("groups") or item.get("roles"):
            item["users"] = users
            kept.append(item)
    after["policyItems"] = kept
    return after


def build_proposal(finding: Finding, raw: Optional[Dict[str, Any]]) -> Proposal:
    if finding.kind == KIND_OVER_PRIVILEGED:
        if raw is None or finding.user is None or finding.policy_id is None:
            raise ValueError("over-privileged proposal needs the policy and the user")
        return Proposal(
            action=ACTION_REMOVE_USER,
            policy_id=finding.policy_id,
            target_user=finding.user,
            before=copy.deepcopy(raw),
            after=remove_user(raw, finding.user),
        )
    if finding.kind == KIND_STALE_POLICY:
        if raw is None or finding.policy_id is None:
            raise ValueError("stale-policy proposal needs the policy")
        after = copy.deepcopy(raw)
        after["isEnabled"] = False
        return Proposal(action=ACTION_DISABLE_POLICY, policy_id=finding.policy_id, before=copy.deepcopy(raw), after=after)
    # Time-of-access findings describe behavior, not a policy defect, so no policy change is proposed.
    return Proposal(action=ACTION_REVIEW_ONLY, policy_id=finding.policy_id)


def validate_proposal(proposal: Proposal, protected_policy_ids: FrozenSet[int] = frozenset()) -> List[str]:
    """Return violations. An empty list means the proposal may be stored."""
    if proposal.action == ACTION_REVIEW_ONLY:
        return []

    violations: List[str] = []
    if proposal.policy_id in protected_policy_ids:
        violations.append("policy %s is on the protected list" % proposal.policy_id)
    if proposal.before is None or proposal.after is None:
        return violations + ["proposal is missing before or after state"]

    changeable = _CHANGEABLE_FIELD.get(proposal.action)
    for key in sorted(set(proposal.before) | set(proposal.after)):
        if key != changeable and proposal.before.get(key) != proposal.after.get(key):
            violations.append("proposal changes policy field %r" % key)

    before_grants = grants(proposal.before)
    after_grants = grants(proposal.after)
    added = after_grants - before_grants
    if added:
        violations.append("proposal adds %d grant(s)" % len(added))

    before_enabled = bool(proposal.before.get("isEnabled", True))
    after_enabled = bool(proposal.after.get("isEnabled", True))

    if proposal.action == ACTION_REMOVE_USER:
        if proposal.target_user is None:
            violations.append("removal proposal has no target user")
        elif is_macro_user(proposal.target_user):
            violations.append("removal proposal targets the macro %s, not a user" % proposal.target_user)
        removed = before_grants - after_grants
        if not removed:
            violations.append("removal proposal removes nothing")
        other = [g for g in removed if g[0] != "user:%s" % proposal.target_user]
        if other:
            violations.append("removal proposal touches grants for other principals")
        if before_enabled != after_enabled:
            violations.append("removal proposal changes the enabled flag")

    elif proposal.action == ACTION_DISABLE_POLICY:
        if after_enabled:
            violations.append("disable proposal leaves the policy enabled")
        if int(proposal.before.get("policyType") or POLICY_TYPE_ACCESS) != POLICY_TYPE_ACCESS:
            violations.append("disabling a data-mask or row-filter policy would widen access")
        if restricts_access(proposal.before):
            violations.append("disabling a policy that denies access would widen access")
        if before_grants != after_grants:
            violations.append("disable proposal changes grants")

    else:
        violations.append("unknown action %r" % proposal.action)

    return violations
