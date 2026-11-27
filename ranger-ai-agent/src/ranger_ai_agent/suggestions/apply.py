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
  1. honor the kill switch and the daily change cap; live writes also need an
     audit source and a log key (RANGER_AI_LOG_KEY), so the record is signed
  2. re-validate the proposal against current safety rules (protected policies may
     have changed since approval), and require a verified action log with a
     signed approval, by a person, of exactly this proposal (its digest)
  3. require that a detection run confirmed the finding recently (last_seen_at)
  4. read the live policy and require its version to equal the version the
     proposal was built from (optimistic concurrency; a human must re-review on conflict)
  5. re-check the evidence in the audit store since the snapshot: a removed user
     must still have no allowed access, a disabled policy must still be unused.
     If it changed, the suggestion is expired.
  6. in dry-run mode, log the planned change and stop
  7. record the attempt as IN_FLIGHT, then PUT the proposed policy
  8. settle the attempt from what Ranger now holds, whether or not the PUT reported
     an error (a timeout does not mean nothing was written):
       - matches the proposal at a new version: APPLIED (suggestion APPLIED)
       - unchanged at the original version: ABORTED (suggestion stays APPROVED)
       - anything else, or unreadable: UNCERTAIN (suggestion NEEDS_ATTENTION)

Attempts left IN_FLIGHT by a crash are settled the same way at the start of the
next apply run. A person settles NEEDS_ATTENTION with reconcile or rollback.

Rollback repeats the checks with the stored pre-change policy as the target. It
refuses if the live version is not the one the agent wrote, unless the policy
already matches the original.
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
from ranger_ai_agent.identity import AUTH_RANGER, REVIEWER_AUTH_ENV
from ranger_ai_agent.models import UTC, format_utc, parse_utc
from ranger_ai_agent.sources import AuditSource
from ranger_ai_agent.suggestions.models import (
    ACTION_DISABLE_POLICY,
    ACTION_REMOVE_USER,
    ACTION_REVIEW_ONLY,
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_NEEDS_ATTENTION,
    Suggestion,
    proposal_digest,
)
from ranger_ai_agent.suggestions.proposals import grants, validate_proposal
from ranger_ai_agent.suggestions.store import ALG_HMAC, LOG_INTACT, LOG_KEY_ENV, SuggestionStore

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
NEEDS_ATTENTION = "NEEDS_ATTENTION"
ABORTED = "ABORTED"
NOTHING_TO_RECONCILE = "NOTHING_TO_RECONCILE"
LOG_KEY_REQUIRED = "LOG_KEY_REQUIRED"
APPROVAL_UNVERIFIED = "APPROVAL_UNVERIFIED"

_NO_LOG_KEY = "live writes need a signed action log; set %s" % LOG_KEY_ENV


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
        """Settle interrupted writes, then attempt every APPROVED suggestion once.

        Dry-run mode never writes to Ranger.
        """
        now = self._now()

        if self._safety.kill_switch:
            approved = self._store.list(STATUS_APPROVED)
            self._store.log(now, AGENT, KILL_SWITCH, None, {"approved_pending": len(approved)})
            return [ApplyResult(s.suggestion_id, KILL_SWITCH, "kill switch is on") for s in approved]

        results: List[ApplyResult] = self._recover(now)
        approved = self._store.list(STATUS_APPROVED)

        log_problem = self._log_problem()
        if log_problem:
            # Approvals are read from the log, so nothing in it can be trusted.
            return results + [self._note(now, s, APPROVAL_UNVERIFIED, log_problem) for s in approved]
        # Live attempts are rows in the store, so they are already in count_applications_since.
        # Dry-run plans leave no row, so they are counted here.
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
            if result.outcome == DRY_RUN:
                planned += 1
            results.append(result)
        return results

    def _recover(self, now: str) -> List[ApplyResult]:
        """Settle write attempts that a previous run started but never recorded an outcome for."""
        results = []
        for row in self._store.in_flight_applications():
            suggestion = self._store.get(row["suggestion_id"])
            if suggestion is None:
                continue
            results.append(
                self._settle(
                    now,
                    suggestion,
                    row["application_id"],
                    row["version_before"],
                    "a previous run stopped before recording the outcome",
                )
            )
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

        if not self._store.keyed and not self._safety.dry_run:
            return self._note(now, suggestion, LOG_KEY_REQUIRED, _NO_LOG_KEY)

        unverified = self._approval_problem(suggestion)
        if unverified:
            return self._note(now, suggestion, APPROVAL_UNVERIFIED, unverified)

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

        application_id = self._store.begin_application(
            sid, proposal.policy_id, now, AGENT, before_version, details["before_sha256"], details["after_sha256"]
        )
        write_error = None
        try:
            self._writer.update_policy(proposal.policy_id, copy.deepcopy(proposal.after))
        except RangerApiError as exc:
            write_error = "policy update reported an error: %s" % exc
        return self._settle(now, suggestion, application_id, before_version, write_error)

    def _settle(
        self,
        now: str,
        suggestion: Suggestion,
        application_id: int,
        version_before: Optional[int],
        write_error: Optional[str],
    ) -> ApplyResult:
        """Decide what a write attempt did by reading the policy back, and record it."""
        sid = suggestion.suggestion_id
        proposal = suggestion.proposal
        notes = {"write_error": write_error} if write_error else {}

        try:
            live = self._reader.get_policy(proposal.policy_id)
        except RangerApiError as exc:
            live = None
            notes["read_error"] = str(exc)

        version = live.get("version") if live is not None else None
        if live is not None and version is not None and version != version_before and _same_effect(live, proposal.after):
            self._store.commit_application(application_id, sid, now, AGENT, version, details=notes)
            detail = "policy %s updated to version %s" % (proposal.policy_id, version)
            if write_error:
                detail += " (the update reported an error, but the change is in place)"
            return ApplyResult(sid, APPLIED, detail)

        if live is not None and version == version_before and _same_effect(live, proposal.before):
            outcome = FAILED if write_error else VERIFY_FAILED
            detail = (write_error or "the update did not take effect") + "; policy unchanged"
            self._store.abort_application(application_id, sid, now, AGENT, outcome, dict(notes, detail=detail))
            return ApplyResult(sid, outcome, detail)

        if live is None:
            reason = "could not read the policy after the write: %s" % notes["read_error"]
        else:
            reason = "policy %s (version %r) matches neither the proposal nor the original" % (proposal.policy_id, version)
        detail = reason + "; inspect it, then run reconcile or rollback"
        self._store.mark_uncertain(application_id, sid, now, AGENT, version, dict(notes, detail=detail))
        return ApplyResult(sid, NEEDS_ATTENTION, detail)

    def _log_problem(self) -> Optional[str]:
        check = self._store.check_log()
        if check.state != LOG_INTACT:
            return "the action log is %s (%s); nothing is written until it verifies" % (check.state, check.reason)
        return None

    def _approval_problem(self, suggestion: Suggestion) -> Optional[str]:
        """Why the stored status and proposal are not backed by a matching approval in the log, or None.

        The status column and the proposal can be edited by anyone who can write
        the database. The approval entry in a signed log cannot be forged without
        the key, and it records the digest of the proposal that was approved.
        """
        entry = self._store.approval_entry(suggestion.suggestion_id)
        if entry is None:
            return "no approval of the current proposal is recorded in the action log"
        if entry["actor"].strip().lower() == AGENT:
            return "the recorded approval was not made by a person"
        recorded = entry["details"].get("proposal_sha256")
        if recorded is None:
            return "the approval was recorded before approvals were bound to proposals; run approve again"
        if recorded != proposal_digest(suggestion):
            return "the stored proposal is not the one that was approved"
        if entry["details"].get("auth") != AUTH_RANGER:
            return "the approver %r was not confirmed with Ranger; approve again with %s=ranger" % (
                entry["actor"],
                REVIEWER_AUTH_ENV,
            )
        if self._store.keyed and entry["hash_alg"] != ALG_HMAC:
            return "the approval is not a signed log entry; run approve again with %s set" % LOG_KEY_ENV
        return None

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

        if suggestion.status not in (STATUS_APPLIED, STATUS_NEEDS_ATTENTION):
            return ApplyResult(suggestion_id, NOT_APPLIED, "status is %s" % suggestion.status)

        application = self._store.open_application(suggestion_id)
        if application is None:
            return self._note(now, suggestion, REFUSED, "no active application record", actor=actor)

        # Rollback writes the stored original, so it must be the one that was approved.
        unverified = self._log_problem() or self._approval_problem(suggestion)
        if unverified:
            return self._note(now, suggestion, APPROVAL_UNVERIFIED, unverified, actor=actor)

        policy_id = application["policy_id"]
        before = suggestion.proposal.before
        try:
            live = self._reader.get_policy(policy_id)
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "could not read policy: %s" % exc, actor=actor)

        if _same_effect(live, before):
            # Already back to the original: an earlier rollback whose read-back failed, or a manual fix.
            self._store.commit_rollback(
                application["application_id"],
                suggestion_id,
                now,
                actor,
                details={"version_restored": live.get("version"), "already_restored": True},
            )
            return ApplyResult(suggestion_id, ROLLED_BACK, "policy %s already matches the original" % policy_id)

        if application["version_after"] is None:
            return self._note(
                now,
                suggestion,
                REFUSED,
                "the policy version after the write is unknown; run reconcile first",
                {"policy_id": policy_id},
                actor=actor,
            )

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

        details = {"policy_id": policy_id, "application_id": application["application_id"], "before_sha256": _digest(before)}

        if self._safety.dry_run:
            return self._note(now, suggestion, DRY_RUN, "dry run; rollback not performed", details, actor=actor)

        if not self._store.keyed:
            return self._note(now, suggestion, LOG_KEY_REQUIRED, _NO_LOG_KEY, details, actor=actor)

        write_error = None
        try:
            self._writer.update_policy(policy_id, copy.deepcopy(before))
        except RangerApiError as exc:
            write_error = "rollback write reported an error: %s" % exc

        # Check the result even after an error: the write may have gone through.
        try:
            restored = self._reader.get_policy(policy_id)
        except RangerApiError as exc:
            detail = "read-back failed after rollback: %s; run rollback again to check" % exc
            if write_error:
                detail = write_error + "; " + detail
            return self._note(now, suggestion, VERIFY_FAILED, detail, details, actor=actor)

        if not _same_effect(restored, before):
            if write_error:
                return self._note(now, suggestion, FAILED, write_error + "; policy not restored", details, actor=actor)
            return self._note(now, suggestion, VERIFY_FAILED, "live policy does not match pre-change state", details, actor=actor)

        self._store.commit_rollback(
            application["application_id"], suggestion_id, now, actor, details={"version_restored": restored.get("version")}
        )
        return ApplyResult(suggestion_id, ROLLED_BACK, "policy %s restored" % policy_id)

    def reconcile(self, suggestion_id: str, reviewer: str, auth: Optional[str] = None) -> ApplyResult:
        """Settle a NEEDS_ATTENTION suggestion from the live policy. Requires a named human.

        Matches the proposal: APPLIED. Matches the original: the attempt is ABORTED and
        the suggestion goes back to APPROVED. Matches neither: its current version is
        recorded, so that rollback can restore the original once a person has inspected it.
        Ranger is only read, so this is allowed while the kill switch is on.
        `auth` is how the reviewer was checked; a suggestion it moves back to
        APPROVED counts as approved by them.
        """
        actor = _require_human(reviewer)
        now = self._now()
        suggestion = self._store.get(suggestion_id)
        if suggestion is None:
            raise KeyError("no suggestion with id %s" % suggestion_id)
        if suggestion.status != STATUS_NEEDS_ATTENTION:
            return ApplyResult(suggestion_id, NOTHING_TO_RECONCILE, "status is %s" % suggestion.status)

        application = self._store.open_application(suggestion_id)
        if application is None:
            return self._note(now, suggestion, REFUSED, "no open application record", actor=actor)

        proposal = suggestion.proposal
        try:
            live = self._reader.get_policy(application["policy_id"])
        except RangerApiError as exc:
            return self._note(now, suggestion, FAILED, "could not read policy: %s" % exc, actor=actor)

        version = live.get("version")
        if version is not None and version != application["version_before"] and _same_effect(live, proposal.after):
            self._store.commit_application(application["application_id"], suggestion_id, now, actor, version, {"reconciled": True})
            return ApplyResult(suggestion_id, APPLIED, "policy %s matches the proposal at version %s" % (proposal.policy_id, version))

        if _same_effect(live, proposal.before):
            self._store.abort_application(
                application["application_id"],
                suggestion_id,
                now,
                actor,
                ABORTED,
                {"live_version": version, "auth": auth},
                reopen=True,
            )
            return ApplyResult(
                suggestion_id, ABORTED, "policy %s matches the original; the suggestion is APPROVED again" % proposal.policy_id
            )

        if version is not None and version != application["version_after"]:
            self._store.record_version_after(application["application_id"], version, now, actor)
        return self._note(
            now,
            suggestion,
            CONFLICT,
            "policy %s (version %r) matches neither the proposal nor the original; fix it in Ranger, "
            "or run rollback to restore the original" % (proposal.policy_id, version),
            {"policy_id": proposal.policy_id, "live_version": version},
            actor=actor,
        )

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
