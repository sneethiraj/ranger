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

"""Read-only "AI Insights" page generated from the suggestion store.

The output is one self-contained HTML file: no scripts, no forms, no external
resources. A Content-Security-Policy meta tag blocks script and network loads
even if the file is opened in a browser that would otherwise allow them.

Every value is HTML-escaped, because summaries and rationales can contain
text returned by a language model.

The page shows real user names, since it is for administrators. Pseudonyms
apply only to what is sent to a model.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from ranger_ai_agent.config import SafetyConfig
from ranger_ai_agent.models import format_utc
from ranger_ai_agent.suggestions.models import ACTION_DISABLE_POLICY, ACTION_REMOVE_USER, STATUS_PENDING, Suggestion
from ranger_ai_agent.suggestions.store import SuggestionStore

STATUSES = ("PENDING", "APPROVED", "REJECTED", "APPLIED", "ROLLED_BACK", "EXPIRED")
LOG_LIMIT = 50

_CSS = """
body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1d1d1f; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.15rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin-top: 0.5rem; }
th, td { border-bottom: 1px solid #d2d2d7; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f5f5f7; font-weight: 600; }
.muted { color: #6e6e73; } .ok { color: #1a7f37; font-weight: 600; } .bad { color: #cf222e; font-weight: 600; }
.pill { display: inline-block; padding: 0.05rem 0.5rem; border-radius: 999px; background: #e8e8ed; font-size: 0.8rem; }
ul { margin: 0.2rem 0 0 1rem; padding: 0; } code { font-size: 0.85rem; }
"""


INSIGHTS_SCHEMA = 1


def build_insights(store: SuggestionStore, safety: SafetyConfig, generated_at: datetime, log_limit: int = LOG_LIMIT) -> Dict[str, Any]:
    """JSON-serializable view of the store for a UI to render.

    Raw policy bodies (proposal before/after) and log details are left out; the
    UI needs the plain-language change summary, not the policy JSON.
    """
    suggestions = store.list()
    counts = {status: 0 for status in STATUSES}
    for s in suggestions:
        counts[s.status] = counts.get(s.status, 0) + 1

    entries = store.log_entries()
    return {
        "schema": INSIGHTS_SCHEMA,
        "generated_at": format_utc(generated_at),
        "mode": {
            "dry_run": safety.dry_run,
            "kill_switch": safety.kill_switch,
            "max_changes_per_day": safety.max_changes_per_day,
        },
        "action_log": {"intact": store.verify_log(), "entries": len(entries)},
        "counts": counts,
        "suggestions": [
            {
                "id": s.suggestion_id,
                "status": s.status,
                "kind": s.kind,
                "policy_id": s.policy_id,
                "user": s.user,
                "recommended_action": s.recommended_action,
                "change": change_summary(s),
                "confidence": s.confidence,
                "detector_confidence": s.detector_confidence,
                "llm_confidence": s.llm_confidence,
                "llm_provider": s.llm_provider,
                "summary": s.summary,
                "rationale": s.rationale,
                "caveats": list(s.caveats),
                "evidence": list(s.evidence),
                "as_of": s.as_of,
                "reviewed_by": s.reviewed_by,
                "reviewed_at": s.reviewed_at,
            }
            for s in suggestions
        ],
        "applications": store.list_applications(),
        "recent_log": [
            {"ts": e["ts"], "actor": e["actor"], "action": e["action"], "suggestion_id": e["suggestion_id"]}
            for e in reversed(entries[-log_limit:])
        ],
    }


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _conf(value: Optional[float]) -> str:
    return "-" if value is None else "%.2f" % value


def change_summary(suggestion: Suggestion) -> str:
    """Plain-language description of the proposed policy change."""
    p = suggestion.proposal
    if p.action == ACTION_REMOVE_USER and p.before and p.after:
        before = {u for item in p.before.get("policyItems") or [] for u in item.get("users") or []}
        after = {u for item in p.after.get("policyItems") or [] for u in item.get("users") or []}
        removed = ", ".join(sorted(before - after)) or "(none)"
        return "remove %s from policy %s" % (removed, p.policy_id)
    if p.action == ACTION_DISABLE_POLICY:
        return "disable policy %s" % p.policy_id
    return "no policy change (review only)"


def _list(items: Iterable[str]) -> str:
    rendered = "".join("<li>%s</li>" % _e(item) for item in items)
    return "<ul>%s</ul>" % rendered if rendered else "<span class='muted'>none</span>"


def _suggestion_rows(suggestions: List[Suggestion]) -> str:
    if not suggestions:
        return "<tr><td colspan='7' class='muted'>No suggestions yet.</td></tr>"
    rows = []
    for s in suggestions:
        reviewed = "" if not s.reviewed_by else "<div class='muted'>by %s</div>" % _e(s.reviewed_by)
        rows.append(
            "<tr>"
            "<td><code>%s</code></td>"
            "<td><span class='pill'>%s</span>%s</td>"
            "<td>%s<div class='muted'>%s</div></td>"
            "<td>%s</td>"
            "<td>%s<div class='muted'>detector %s · model %s</div></td>"
            "<td>%s<div class='muted'>%s</div></td>"
            "<td>%s</td>"
            "</tr>"
            % (
                _e(s.suggestion_id),
                _e(s.status),
                reviewed,
                _e(s.kind),
                _e(s.llm_provider),
                _e(change_summary(s)),
                _conf(s.confidence),
                _conf(s.detector_confidence),
                _conf(s.llm_confidence),
                _e(s.summary),
                _e(s.rationale),
                _list(s.caveats) + "<div class='muted'>evidence</div>" + _list(s.evidence),
            )
        )
    return "".join(rows)


def _application_rows(applications: List[dict]) -> str:
    if not applications:
        return "<tr><td colspan='5' class='muted'>No changes applied.</td></tr>"
    rows = []
    for a in applications:
        status = "rolled back %s by %s" % (_e(a["rolled_back_at"]), _e(a["rolled_back_by"])) if a["rolled_back_at"] else "active"
        rows.append(
            "<tr><td><code>%s</code></td><td>%s</td><td>%s → %s</td><td>%s</td><td>%s</td></tr>"
            % (
                _e(a["suggestion_id"]),
                _e(a["policy_id"]),
                _e(a["version_before"]),
                _e(a["version_after"]),
                _e(a["applied_by"]),
                _e(a["applied_at"]) + " · " + status,
            )
        )
    return "".join(rows)


def _log_rows(entries: List[dict]) -> str:
    if not entries:
        return "<tr><td colspan='4' class='muted'>Log is empty.</td></tr>"
    rows = []
    for e in reversed(entries):
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>"
            % (
                _e(e["ts"]),
                _e(e["actor"]),
                _e(e["action"]),
                _e(e["suggestion_id"] or ""),
            )
        )
    return "".join(rows)


def render_insights(store: SuggestionStore, safety: SafetyConfig, generated_at: datetime) -> str:
    suggestions = store.list()
    applications = store.list_applications()
    entries = store.log_entries()
    intact = store.verify_log()

    counts = {status: 0 for status in STATUSES}
    for s in suggestions:
        counts[s.status] = counts.get(s.status, 0) + 1

    pending = [s for s in suggestions if s.status == STATUS_PENDING]
    others = [s for s in suggestions if s.status != STATUS_PENDING]
    mode = "dry run (no changes written)" if safety.dry_run else "live"
    kill = "ON: all agent actions stopped" if safety.kill_switch else "off"
    chain = "<span class='ok'>intact</span>" if intact else "<span class='bad'>FAILED verification</span>"

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<title>Ranger AI Insights</title><style>%s</style></head><body>" % _CSS,
        "<h1>Ranger AI Insights</h1>",
        "<p class='muted'>Generated %s. Read-only view of the suggestion store.</p>" % _e(format_utc(generated_at)),
        "<h2>Status</h2>",
        "<table><tr><th>Mode</th><td>%s</td></tr>" % _e(mode),
        "<tr><th>Kill switch</th><td>%s</td></tr>" % _e(kill),
        "<tr><th>Daily change cap</th><td>%d</td></tr>" % safety.max_changes_per_day,
        "<tr><th>Action log</th><td>%s (%d entries)</td></tr></table>" % (chain, len(entries)),
        "<h2>Suggestions by status</h2><table><tr>%s</tr><tr>%s</tr></table>"
        % (
            "".join("<th>%s</th>" % s for s in STATUSES),
            "".join("<td>%d</td>" % counts[s] for s in STATUSES),
        ),
        "<h2>Awaiting review (%d)</h2>" % len(pending),
        "<table><tr><th>ID</th><th>Status</th><th>Finding</th><th>Change</th><th>Confidence</th><th>Explanation</th><th>Details</th></tr>",
        _suggestion_rows(pending),
        "</table>",
        "<h2>Reviewed and applied (%d)</h2>" % len(others),
        "<table><tr><th>ID</th><th>Status</th><th>Finding</th><th>Change</th><th>Confidence</th><th>Explanation</th><th>Details</th></tr>",
        _suggestion_rows(others),
        "</table>",
        "<h2>Applied changes</h2>",
        "<table><tr><th>Suggestion</th><th>Policy</th><th>Version</th><th>Applied by</th><th>Applied at · state</th></tr>",
        _application_rows(applications),
        "</table>",
        "<h2>Recent action log (last %d)</h2>" % LOG_LIMIT,
        "<table><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Suggestion</th></tr>",
        _log_rows(entries[-LOG_LIMIT:]),
        "</table></body></html>",
    ]
    return "".join(parts)
