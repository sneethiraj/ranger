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

"""Turns detector findings into reviewable suggestions.

Pipeline for each finding:
  1. skip if a human has already reviewed this suggestion
  2. build the proposal deterministically and validate it
  3. ask the model (optional) for an explanation; fall back on any failure
  4. store the suggestion as PENDING and log every step

Nothing here writes to Ranger. Approval only changes the suggestion's status.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime
from typing import Callable, Dict, Iterable, Optional, Set, Tuple

from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.detectors.core import Finding
from ranger_ai_agent.features.snapshot import FeatureSnapshot
from ranger_ai_agent.llm.explain import (
    Explanation,
    ExplanationError,
    build_prompt,
    parse_explanation,
    template_explanation,
)
from ranger_ai_agent.llm.providers import LLMError
from ranger_ai_agent.llm.redact import Pseudonymizer
from ranger_ai_agent.models import UTC, format_utc
from ranger_ai_agent.suggestions.models import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Suggestion,
    combine_confidence,
    suggestion_id_for,
)
from ranger_ai_agent.suggestions.proposals import build_proposal, names_in_policy, validate_proposal
from ranger_ai_agent.suggestions.store import SuggestionStore

AGENT = "agent"
NO_LLM = "none"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SuggestionService:
    def __init__(
        self,
        store: SuggestionStore,
        provider=None,
        pseudonymizer: Optional[Pseudonymizer] = None,
        safety: Optional[SafetyConfig] = None,
        protected_policy_ids: Iterable[int] = (),
        max_per_run: int = 50,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._store = store
        self._provider = provider
        self._pseudo = pseudonymizer or Pseudonymizer.from_env()
        self._safety = safety or SafetyConfig.from_env()
        self._protected: Set[int] = set(protected_policy_ids) | set(self._safety.protected_policy_ids)
        self._max = max_per_run
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> str:
        return format_utc(self._clock())

    def generate(
        self,
        snap: FeatureSnapshot,
        findings: Iterable[Finding],
        raw_policies: Dict[int, dict],
    ) -> list:
        now = self._now()
        findings = list(findings)

        if self._safety.kill_switch:
            self._store.log(now, AGENT, "KILL_SWITCH_ACTIVE", None, {"findings_suppressed": len(findings)})
            return []

        produced = []
        for finding in findings[: self._max]:
            suggestion = self._build_one(now, snap, finding, raw_policies)
            if suggestion is not None:
                produced.append(suggestion)
        return produced

    def _build_one(self, now: str, snap: FeatureSnapshot, finding: Finding, raw_policies: Dict[int, dict]) -> Optional[Suggestion]:
        sid = suggestion_id_for(finding.kind, finding.policy_id, finding.user)

        existing = self._store.get(sid)
        if existing is not None and existing.status != STATUS_PENDING:
            self._store.log(now, AGENT, "SKIPPED_REVIEWED", sid, {"status": existing.status})
            return None

        raw = raw_policies.get(finding.policy_id) if finding.policy_id is not None else None
        if finding.policy_id is not None and raw is None:
            self._store.log(now, AGENT, "POLICY_NOT_FOUND", sid, {"policy_id": finding.policy_id})
            return None

        proposal = build_proposal(finding, raw)
        violations = validate_proposal(proposal, frozenset(self._protected))
        if violations:
            self._store.log(now, AGENT, "VALIDATION_REJECTED", sid, {"violations": violations})
            return None

        explanation, provider_name, llm_used = self._explain(now, sid, finding, raw)
        caveats = list(explanation.caveats)
        if llm_used and explanation.recommended_action != proposal.action:
            caveats.append("Model recommendation differs from the deterministic proposal; the proposal is authoritative.")

        suggestion = Suggestion(
            suggestion_id=sid,
            kind=finding.kind,
            as_of=format_utc(snap.as_of),
            summary=explanation.summary,
            rationale=explanation.rationale,
            recommended_action=proposal.action,
            caveats=tuple(caveats),
            evidence=finding.evidence,
            detector_confidence=round(finding.confidence, 3),
            llm_confidence=round(explanation.self_confidence, 3) if llm_used else None,
            confidence=combine_confidence(finding.confidence, explanation.self_confidence if llm_used else None),
            proposal=proposal,
            llm_provider=provider_name,
            policy_id=finding.policy_id,
            user=finding.user,
        )
        self._store.upsert_pending(suggestion, now, AGENT)
        return suggestion

    def _explain(self, now: str, sid: str, finding: Finding, raw: Optional[dict]) -> Tuple[Explanation, str, bool]:
        """Returns (explanation, provider name, whether the model produced it)."""
        if self._provider is None:
            return template_explanation(finding), NO_LLM, False

        names = names_in_policy(raw) if raw else set()
        if finding.user:
            names.add(finding.user)
        policy_name = str(raw.get("name", "")) if raw else ""
        prompt = build_prompt(finding, policy_name, names, self._pseudo)

        try:
            text = self._provider.complete_json(prompt)
        except LLMError as exc:
            self._store.log(now, AGENT, "LLM_FALLBACK", sid, {"provider": self._provider.name, "error": str(exc)[:200]})
            return template_explanation(finding), NO_LLM, False

        self._store.log(
            now,
            AGENT,
            "LLM_CALL",
            sid,
            {
                "provider": self._provider.name,
                "external": bool(getattr(self._provider, "external", False)),
                "prompt_sha256": _sha256(prompt.system + "\n" + prompt.user),
                "response_sha256": _sha256(text or ""),
            },
        )

        try:
            parsed = parse_explanation(text)
        except ExplanationError as exc:
            self._store.log(now, AGENT, "LLM_FALLBACK", sid, {"provider": self._provider.name, "error": str(exc)[:200]})
            return template_explanation(finding), NO_LLM, False

        restored = replace(
            parsed,
            summary=self._pseudo.reveal(parsed.summary),
            rationale=self._pseudo.reveal(parsed.rationale),
            caveats=tuple(self._pseudo.reveal(c) for c in parsed.caveats),
        )
        return restored, self._provider.name, True

    def approve(self, suggestion_id: str, reviewer: str) -> Suggestion:
        return self._review(suggestion_id, STATUS_APPROVED, reviewer)

    def reject(self, suggestion_id: str, reviewer: str) -> Suggestion:
        return self._review(suggestion_id, STATUS_REJECTED, reviewer)

    def _review(self, suggestion_id: str, new_status: str, reviewer: str) -> Suggestion:
        if not reviewer or not reviewer.strip() or reviewer.strip().lower() == AGENT:
            raise ValueError("a named human reviewer is required")
        return self._store.transition(suggestion_id, new_status, reviewer.strip(), self._now())
