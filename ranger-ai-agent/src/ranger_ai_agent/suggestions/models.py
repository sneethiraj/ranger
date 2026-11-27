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

"""Suggestion and proposal models.

A Proposal is a concrete, reversible policy change. It stores the policy as it
was (`before`) and as it would be (`after`), so that a later rollback has the
original. Proposals are built by deterministic code, never by a model.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_APPLIED = "APPLIED"
STATUS_ROLLED_BACK = "ROLLED_BACK"
# The finding is no longer detected, or its evidence changed before it was applied.
STATUS_EXPIRED = "EXPIRED"

ACTION_REMOVE_USER = "REMOVE_USER_FROM_POLICY"
ACTION_DISABLE_POLICY = "DISABLE_POLICY"
ACTION_REVIEW_ONLY = "REVIEW_ONLY"
ALLOWED_ACTIONS = (ACTION_REMOVE_USER, ACTION_DISABLE_POLICY, ACTION_REVIEW_ONLY)

# Weight given to the model's self-assessed confidence when it is available.
LLM_WEIGHT = 0.3


def suggestion_id_for(kind: str, policy_id: Optional[int], user: Optional[str]) -> str:
    """One open suggestion per (kind, policy, user), so daily reruns refresh instead of duplicating."""
    raw = "%s|%s|%s" % (kind, "" if policy_id is None else policy_id, user or "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def combine_confidence(detector: float, llm: Optional[float]) -> float:
    if llm is None:
        return round(detector, 3)
    return round((1.0 - LLM_WEIGHT) * detector + LLM_WEIGHT * llm, 3)


@dataclass(frozen=True)
class Proposal:
    action: str
    policy_id: Optional[int] = None
    target_user: Optional[str] = None
    before: Optional[Dict[str, Any]] = None
    after: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "policy_id": self.policy_id,
            "target_user": self.target_user,
            "before": self.before,
            "after": self.after,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proposal":
        return cls(
            action=data["action"],
            policy_id=data.get("policy_id"),
            target_user=data.get("target_user"),
            before=data.get("before"),
            after=data.get("after"),
        )


@dataclass(frozen=True)
class Suggestion:
    suggestion_id: str
    kind: str
    as_of: str
    summary: str
    rationale: str
    recommended_action: str
    caveats: Tuple[str, ...]
    evidence: Tuple[str, ...]
    detector_confidence: float
    llm_confidence: Optional[float]
    confidence: float
    proposal: Proposal
    llm_provider: str
    policy_id: Optional[int] = None
    user: Optional[str] = None
    status: str = STATUS_PENDING
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "kind": self.kind,
            "as_of": self.as_of,
            "summary": self.summary,
            "rationale": self.rationale,
            "recommended_action": self.recommended_action,
            "caveats": list(self.caveats),
            "evidence": list(self.evidence),
            "detector_confidence": self.detector_confidence,
            "llm_confidence": self.llm_confidence,
            "confidence": self.confidence,
            "proposal": self.proposal.to_dict(),
            "llm_provider": self.llm_provider,
            "policy_id": self.policy_id,
            "user": self.user,
            "status": self.status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Suggestion":
        return cls(
            suggestion_id=data["suggestion_id"],
            kind=data["kind"],
            as_of=data["as_of"],
            summary=data["summary"],
            rationale=data["rationale"],
            recommended_action=data["recommended_action"],
            caveats=tuple(data["caveats"]),
            evidence=tuple(data["evidence"]),
            detector_confidence=float(data["detector_confidence"]),
            llm_confidence=data["llm_confidence"],
            confidence=float(data["confidence"]),
            proposal=Proposal.from_dict(data["proposal"]),
            llm_provider=data["llm_provider"],
            policy_id=data.get("policy_id"),
            user=data.get("user"),
            status=data["status"],
            reviewed_by=data.get("reviewed_by"),
            reviewed_at=data.get("reviewed_at"),
        )
