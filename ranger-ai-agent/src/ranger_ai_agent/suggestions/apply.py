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

"""Applies approved suggestions to Ranger, and rolls them back.

Every write follows the same steps:
  1. honor the kill switch and the daily change cap
  2. re-validate the proposal against current safety rules (protected policies may
     have changed since approval)
  3. require that a detection run confirmed the finding recently (last_seen_at)
  4. read the live policy and require its version to equal the version the
     proposal was built from (optimistic concurrency; a human must re-review on conflict)
  5. re-check the evidence in the audit store since the snapshot: a removed user
     must still have no allowed access, a disabled policy must still be unused.
     If it changed, the suggestion is expired.
  6. in dry-run mode, log the planned change and stop
  7. PUT the proposed policy, read it back, and check its effect matches the proposal
  8. record the application and move the suggestion to APPLIED, in one transaction

Rollback repeats the checks with the stored pre-change policy as the target. It
refuses if the live version is not the one the agent wrote.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Protocol

from ranger_ai_agent.clients.ranger_admin import RangerApiError
from ranger_ai_agent.clients.solr_audit import SolrAuditError
from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.models import UTC, format_utc, parse_utc
from ranger_ai_agent.sources import AuditSource
from ranger_ai_agent.suggestions.models import (
    ACTION_DISABLE_POLICY,
    ACTION_REMOVE_USER,
    ACTION_REVIEW_ONLY,
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    Suggestion,
)
from ranger_ai_agent.suggestions.proposals import grants, validate_proposal
from ranger_ai_agent.suggestions.store import SuggestionStore

AGENT = "agent"
WINDOW = timedelta(hours=24)

# Outcomes returned to the caller and written to the action log.
APPLIED = "APPLIED"
ROLLED_BACK = "ROLLED_BACK"
DRY_RUN = "DRY_RUN"
CONFLICT = "CONFLICT"
REFUSED = "REFUSED"
FAILED = "FAILED"
VERIFY_FAILED = "VERIFY_FAILED"
NO_POLICY_CHANGE = "NO_POLICY_CHANGE"
KILL_SWITCH = "KILL_SWITCH"
CAP_REACHED = "CAP_REACHED"
NOT_APPLIED = "NOT_APPLIED"
STALE_EVIDENCE = "STALE_EVIDENCE"
EVIDENCE_CHANGED = "EVIDENCE_CHANGED"


class PolicyReader(Protocol):
    def get_policy(self, policy_id: int) -> Dict[str, Any]: ...


class PolicyWriter(Protocol):
    def update_policy(self, policy_id: int, body: Dict[str, Any]) -> Dict[str, Any]: ...


@dataclass(frozen=True)
class ApplyResult:
    suggestion_id: str
    outcome: str
    detail: str = ""


def _digest(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _same_effect(live: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    """Compare what a policy does, not its bookkeeping fields (version, updateTime, ...).

    Ranger may normalize item layout on save, so grants are compared as a set.
    """
    return bool(live.get("isEnabled", True)) == bool(expected.get("isEnabled", True)) and grants(live) == grants(expected)


def _require_human(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned or cleaned.lower() == AGENT:
        raise ValueError("a named human is required")
    return cleaned


class Applier:
    def __init__(
        self,
        store: SuggestionStore,
        reader: PolicyReader,
        writer: PolicyWriter,
        safety: Optional[SafetyConfig] = None,
        clock: Optional[Callable[[], datetime]] = None,
        audit: Optional[AuditSource] = None,
    ) -> None:
        """`audit` re-checks evidence before a write. Without it, live writes are refused."""
        self._store = store
        self._reader = reader
        self._writer = writer
        self._audit = audit
        self._safety = safety or SafetyConfig.from_env()
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> str:
        return format_utc(self._clock())

    def _window_start(self) -> str:
        return format_utc(self._clock() - WINDOW)

    def apply_approved(self) -> List[ApplyResult]:
        """Attempt every APPROVED suggestion once. Dry-run mode never writes to Ranger."""
        now = self._now()
        approved = self._store.list(STATUS_APPROVED)

        if self._safety.kill_switch:
            self._store.log(now, AGENT, KILL_SWITCH, None, {"approved_pending": len(approved)})
            return [ApplyResult(s.suggestion_id, KILL_SWITCH, "kill switch is on") for s in approved]

        results: List[ApplyResult] = []
        planned = 0
        cap_logged = False
        for index, suggestion in enumerate(approved):
            if suggestion.proposal.action == ACTION_REVIEW_ONLY:
                results.append(self._note(now, suggestion, NO_POLICY_CHANGE, "review-only suggestion; no policy change"))
                continue

            used = self._store.count_applications_since(self._window_start()) + planned
            if used >= self._safety.max_changes_per_day:
                if not cap_logged:
                    self._store.log(now, AGENT, CAP_REACHED, None, {"max_changes_per_day": self._safety.max_changes_per_day})
                    cap_logged = True
                results.extend(ApplyResult(s.suggestion_id, CAP_REACHED, "daily change cap reached") for s in approved[index:]
                               if s.proposal.action != ACTION_REVIEW_ONLY)
                break

            result = self._apply_one(now, suggestion)
            if result.outcome in (APPLIED, DRY_RUN):
                planned += 1
            results.append(result)
        return results

    def _apply_one(self, now: str, suggestion: Suggestion) -> ApplyResult:
        sid = suggestion.suggestion_id
        proposal = suggestion.proposal

        violations = validate_proposal(proposal, self._safety.protected_policy_ids)
        if violations:
            return self._note(now, suggestion, REFUSED, "; ".join(violations))

        stale = self._stale_reason(sid)
        if stale:
            return self._note(now, suggestion, STALE_EVIDENCE, stale)

        if self._audit is None and not self._safety.dry_run:
            return self._note(now, suggestion, REFUSED, "no audit source configured to re-check the evidence")

        try:
            live = self._reader.get_policy(proposal.policy_id)
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "could not read policy: %s" % exc)

        before_version = proposal.before.get("version") if proposal.before else None
        live_version = live.get("version")
        if before_version is None or live_version != before_version:
            return self._note(
                now,
                suggestion,
                CONFLICT,
                "live version %r differs from proposal version %r; re-review required" % (live_version, before_version),
                {"policy_id": proposal.policy_id, "live_version": live_version, "proposal_version": before_version},
            )

        if self._audit is not None:
            try:
                changed = self._evidence_changed(suggestion)
            except SolrAuditError as exc:
                return self._note(now, suggestion, FAILED, "could not re-check evidence: %s" % exc)
            if changed:
                self._store.transition(
                    sid, STATUS_EXPIRED, AGENT, now, {"reason": "evidence changed before apply", "detail": changed}
                )
                return ApplyResult(sid, EVIDENCE_CHANGED, changed + "; suggestion expired")

        details = {
            "policy_id": proposal.policy_id,
            "version_before": before_version,
            "before_sha256": _digest(proposal.before),
            "after_sha256": _digest(proposal.after),
        }

        if self._safety.dry_run:
            return self._note(now, suggestion, DRY_RUN, "dry run; policy not changed", details)

        try:
            self._writer.update_policy(proposal.policy_id, copy.deepcopy(proposal.after))
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "policy update failed: %s" % exc, details)

        try:
            after_live = self._reader.get_policy(proposal.policy_id)
        except RangerApiError as exc:
            return self._note(now, suggestion, VERIFY_FAILED, "read-back failed after write: %s" % exc, details)

        version_after = after_live.get("version")
        if version_after is None:
            return self._note(now, suggestion, VERIFY_FAILED, "read-back has no policy version", details)
        if not _same_effect(after_live, proposal.after):
            return self._note(now, suggestion, VERIFY_FAILED, "live policy does not match proposal after write", details)

        self._store.commit_application(
            sid,
            proposal.policy_id,
            now,
            AGENT,
            before_version,
            version_after,
            details={"before_sha256": details["before_sha256"], "after_sha256": details["after_sha256"]},
        )
        return ApplyResult(sid, APPLIED, "policy %s updated to version %s" % (proposal.policy_id, version_after))

    def _stale_reason(self, suggestion_id: str) -> Optional[str]:
        """Why the suggestion's evidence is too old to act on, or None if it is current."""
        seen = self._store.last_seen(suggestion_id)
        limit = timedelta(hours=self._safety.max_evidence_age_hours)
        if seen is None:
            return "no detection run has confirmed this finding; run suggest again"
        if self._clock() - parse_utc(seen) > limit:
            return "finding last confirmed at %s, more than %d hours ago; run suggest again" % (
                seen,
                self._safety.max_evidence_age_hours,
            )
        return None

    def _evidence_changed(self, suggestion: Suggestion) -> Optional[str]:
        """Re-run the detector's key check over [snapshot time, now]. Returns what changed, or None."""
        proposal = suggestion.proposal
        start = parse_utc(suggestion.as_of)
        end = self._clock()
        if proposal.action == ACTION_REMOVE_USER:
            for usage in self._audit.user_usage_for_policy(proposal.policy_id, start, end):
                if usage.user == proposal.target_user and usage.allowed_count > 0:
                    return "%s had %d allowed access(es) through policy %s since %s" % (
                        proposal.target_user,
                        usage.allowed_count,
                        proposal.policy_id,
                        suggestion.as_of,
                    )
        elif proposal.action == ACTION_DISABLE_POLICY:
            for usage in self._audit.policy_usage(start, end):
                if usage.policy_id == proposal.policy_id and usage.allowed_count > 0:
                    return "policy %s had %d allowed access(es) since %s" % (
                        proposal.policy_id,
                        usage.allowed_count,
                        suggestion.as_of,
                    )
        return None

    def rollback(self, suggestion_id: str, requested_by: str) -> ApplyResult:
        """Restore the pre-change policy for an applied suggestion. Requires a named human."""
        actor = _require_human(requested_by)
        now = self._now()
        suggestion = self._store.get(suggestion_id)
        if suggestion is None:
            raise KeyError("no suggestion with id %s" % suggestion_id)

        if self._safety.kill_switch:
            self._store.log(now, actor, KILL_SWITCH, suggestion_id, {"operation": "rollback"})
            return ApplyResult(suggestion_id, KILL_SWITCH, "kill switch is on; roll back after turning it off")

        if suggestion.status != STATUS_APPLIED:
            return ApplyResult(suggestion_id, NOT_APPLIED, "status is %s" % suggestion.status)

        application = self._store.active_application(suggestion_id)
        if application is None:
            return self._note(now, suggestion, REFUSED, "no active application record", actor=actor)

        policy_id = application["policy_id"]
        try:
            live = self._reader.get_policy(policy_id)
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "could not read policy: %s" % exc, actor=actor)

        if live.get("version") != application["version_after"]:
            return self._note(
                now,
                suggestion,
                CONFLICT,
                "policy changed since the agent applied it (version %r, expected %r)"
                % (live.get("version"), application["version_after"]),
                {"policy_id": policy_id},
                actor=actor,
            )

        before = suggestion.proposal.before
        details = {"policy_id": policy_id, "application_id": application["application_id"], "before_sha256": _digest(before)}

        if self._safety.dry_run:
            return self._note(now, suggestion, DRY_RUN, "dry run; rollback not performed", details, actor=actor)

        try:
            self._writer.update_policy(policy_id, copy.deepcopy(before))
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "rollback write failed: %s" % exc, details, actor=actor)

        try:
            restored = self._reader.get_policy(policy_id)
        except RangerApiError as exc:
            return self._note(now, suggestion, VERIFY_FAILED, "read-back failed after rollback: %s" % exc, details, actor=actor)

        if not _same_effect(restored, before):
            return self._note(now, suggestion, VERIFY_FAILED, "live policy does not match pre-change state", details, actor=actor)

        self._store.commit_rollback(
            application["application_id"], suggestion_id, now, actor, details={"version_restored": restored.get("version")}
        )
        return ApplyResult(suggestion_id, ROLLED_BACK, "policy %s restored" % policy_id)

    def _note(
        self,
        now: str,
        suggestion: Suggestion,
        outcome: str,
        detail: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = AGENT,
    ) -> ApplyResult:
        """Log an outcome that does not change suggestion status."""
        payload = dict(details or {})
        payload["outcome"] = outcome
        payload["detail"] = detail
        self._store.log(now, actor, outcome, suggestion.suggestion_id, payload)
        return ApplyResult(suggestion.suggestion_id, outcome, detail)
