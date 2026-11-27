<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# RANGER-5278: Agentic AI for policy suggestions and anomaly detection

Status: DRAFT for discussion on the JIRA and dev@ranger.apache.org

## 1. Goals

Provide an out-of-process agent that reads Ranger policies and audit logs,
finds policy gaps and anomalous behavior, and proposes human-readable policy
changes with confidence scores. Changes reach Ranger only after explicit admin
approval, and every agent decision is logged and reversible.

Non-goals for the MVP: auto-apply, Elasticsearch/DB audit backends, full
dashboard analytics.

## 2. Principles

1. **Read-only by default.** The agent's Ranger account only needs read access
   until a human approves a suggestion. The client library enforces GET-only
   in the read path.
2. **Detectors find, the LLM explains.** Anomaly and gap detection is
   deterministic and testable. The LLM turns findings into readable text and
   candidate policy JSON; it never decides what is anomalous.
3. **Validate before storing.** Candidate policies are validated against
   Ranger before they appear as suggestions.
4. **Audit data is untrusted input.** Resource names, request data and
   reasons are never passed to the LLM as instructions.
5. **Minimize data sent to models.** Aggregates are preferred over raw events;
   user names can be pseudonymized for external providers.
6. **No impact without approval.** Nothing changes in Ranger unless a specific
   suggestion is approved.

## 3. Architecture

```
Solr audits ──┐
Ranger REST ──┼─► collectors ─► feature store ─► detectors ─► findings
              │                                                   │
              │                                  LLM layer ◄──────┘
              │                                      │
              │                       suggestions (PENDING) + action log
              │                                      │
Ranger Admin UI ◄── approve/reject ◄──────────────────┘
              │
              └─► applier (only on approval): snapshot -> validate -> apply
```

Code layout: see `ranger-ai-agent/src/ranger_ai_agent/`.

## 4. Data sources

### 4.1 Ranger Admin REST (read)

| Data | Endpoint |
|---|---|
| Policies | `GET /service/public/v2/api/policy` (paged: `pageSize`, `startIndex`) |
| Services | `GET /service/public/v2/api/service` |
| Roles | `GET /service/public/v2/api/roles` |
| Security zones | `GET /service/public/v2/api/zones` |
| Users | `GET /service/xusers/users` |

### 4.2 Solr audit collection (`ranger_audits`)

Fields used: `evtTime`, `reqUser`, `repo`, `repoType`, `resource`, `resType`,
`access`, `result` (1 = allowed, 0 = denied), `policy` (policy id),
`policyVersion`, `zoneName`, `agent`, `cliIP`, `event_count`.

The collector uses **facet and stats queries**, not raw event pulls, so
volume does not drive memory use.

## 5. Detectors (MVP)

| Detector | Signal | Evidence |
|---|---|---|
| Over-privileged | Policy item grants user/group access that audit shows unused for N days | policy id, user, last-access time |
| Stale policy | Policy matched zero allowed events in N days | policy id, version, last match |
| Abnormal access time | User's hour-of-day histogram vs current window (z-score) | user, hours, event counts |

Each finding has `score` in [0, 1], a `type`, and an `evidence` list.

## 6. Suggestion model

```
id, type, confidence, summary, rationale,
evidence[ {kind, ref} ],
proposed_change { policy_id, before, after },
status: PENDING | APPROVED | REJECTED | APPLIED | ROLLED_BACK | EXPIRED | NEEDS_ATTENTION,
created_at, reviewed_by, reviewed_at, applied_at, last_seen_at,
detector_confidence, llm_confidence, model_summary, model_rationale, model_caveats
```

`confidence` is the detector score only. The LLM's self-assessment is stored as
`llm_confidence` and shown separately; it never changes `confidence` or the
order of suggestions. `summary` and `rationale` are always the deterministic
text. The LLM's text is kept in `model_summary`, `model_rationale` and
`model_caveats` and shown as an unverified model explanation, never in place of
the deterministic text.

## 7. Approval, apply and rollback

- Every `suggest` run expires the PENDING and APPROVED suggestions whose finding
  it did not detect, or now refuses. A finding that returns reopens its
  suggestion as PENDING, without the old approval.
- Approve (named human; the APPROVED log entry records the SHA-256 of the
  suggestion id, evidence time and proposal) -> require the action log to verify,
  and the latest approval to be signed, by a person, and to match the stored
  proposal (`APPROVAL_UNVERIFIED` otherwise; rollback checks this too, since it
  writes the stored original) -> re-validate against current protections -> require
  a detection run within `max_evidence_age_hours` -> read the live policy and
  require its version to equal the version the proposal was built from ->
  re-check the audit store since the snapshot, and expire the suggestion if the
  user or policy has been used since -> record the attempt as IN_FLIGHT -> PUT
  the proposed policy -> read it back, even if the PUT reported an error, and
  settle the attempt: APPLIED if grants and the enabled flag match the proposal
  at a new version (the suggestion moves to APPLIED in the same transaction),
  ABORTED if the policy is unchanged (the suggestion stays APPROVED), otherwise
  UNCERTAIN (the suggestion moves to NEEDS_ATTENTION).
- A person settles NEEDS_ATTENTION with `reconcile` (APPLIED, back to APPROVED,
  or the live version recorded for rollback) or `rollback`. Attempts a crash
  left IN_FLIGHT are settled at the start of the next apply run. Every attempt,
  in any state, counts toward the daily cap.
- Rollback restores the stored pre-change policy. It is refused if the policy
  changed since the agent wrote it (unless it already matches the original), and
  it is blocked while the kill switch is on.
- Safeguards: dry-run default, kill switch, rolling 24-hour change cap, protected
  policy list, and no added grants (so no admin or wildcard grants can be introduced).
  Each action may change one field only, and deny, data-mask and row-filter
  policies are never disabled, since that would widen access.
- A write the agent cannot confirm is never silent: the attempt row stays
  UNCERTAIN with the live version if it could be read, and the suggestion stays
  NEEDS_ATTENTION, which `apply` skips, until a person settles it.

## 8. Security and logging

- Append-only, hash-chained action log for suggestion creation, LLM calls
  (provider name and SHA-256 of the prompt and of the response; never the raw
  text), reviews, applies and rollbacks. Editing or deleting entries breaks
  `verify-log`. Database triggers also reject UPDATE and DELETE.
- With `RANGER_AI_LOG_KEY`, entries are HMAC-SHA256 signed (schema v3 adds
  `action_log.hash_alg`). The first signed entry, `LOG_KEY_ENABLED`, records a
  key id (an HMAC of a fixed string, not the key). After it, an unsigned entry
  fails verification, and a store opened without the key refuses to append.
  The log check has three results: intact, unverified (signed, but this process
  has no key, as for `serve` without it), and broken. Live apply and rollback
  require the key. Limits: a log rewritten from the start as unsigned looks like
  one that was never signed, and a truncated tail is not detected; keeping the
  head hash printed by `verify-log` outside the store catches both.
- Non-local model endpoints are refused unless `RANGER_AI_ALLOW_EXTERNAL_LLM` is set.
- Secrets (Ranger password, LLM API keys) come from environment variables or
  the Ranger credential provider, never from plain config files.
- TLS verification is on by default.

## 9. Open questions

1. Suggestion store: SQLite is implemented. A pluggable backend is not.
2. UI path: resolved. A read-only page in Ranger Admin, reached through a thin
   proxy endpoint so the browser reuses Ranger authentication. See section 11.
   The standalone HTML report remains for use without Ranger Admin.
3. Packaging: still a standalone Python package. Maven or distro integration is open.

## 10. Implementation status

Implemented on `ranger_5278` and covered by unit tests (279 Python, 24 Java),
with planted-anomaly accuracy measured on synthetic data only:

- read-only Ranger and Solr clients; a GET-only reader and a separate PUT-only writer
- feature snapshots, feature store, three detectors, replay harness
- LLM layer: HMAC pseudonyms, strict JSON validation, deterministic fallback, opt-in for remote endpoints
- suggestion store, validation, human review, guarded apply, rollback
- command-line workflow and read-only HTML report
- read-only JSON endpoint (`serve`), a system-admin-only proxy in Ranger Admin,
  and an "AI Insights" page in the Ranger Admin UI (section 11)

Known gaps:

- Not tested against a live Ranger or Solr instance. The write path's assumptions
  about Ranger's update behavior come from reading the server source, not from a run.
- Group and role grants are not evaluated. Only direct user grants are checked.
- The suggestion id is not written into the policy's description, as the apply
  step above once proposed.
- Per-policy audit queries run once per policy (N+1), which may be slow on large
  deployments.
- The Ranger Admin page is read-only. Approve, apply and rollback are
  command-line only, by design.
- The Ranger Admin integration has not been run in a deployed Ranger Admin with a
  browser session. See section 11 for what was and was not checked.
- Synthetic results show that the detectors and workflow behave as designed. They
  do not show accuracy on real audit data.

## 11. Ranger Admin UI

System administrators can open **Settings > AI Insights** in Ranger Admin to
see the same information as the HTML report: mode (dry-run, kill switch, daily
cap), action-log integrity, suggestions with explanations, applied changes and
recent activity.

```
browser --(Ranger login)--> Ranger Admin --(bearer token)--> ranger-ai-agent serve
        GET /service/ai-insights/report        GET /api/v1/insights (read-only store)
```

Why a proxy and a native page, not an embedded report: Ranger Admin sends
`X-Frame-Options: DENY` and a content security policy with `connect-src 'self'`,
so a browser cannot frame the agent or call it directly. Going through Ranger
Admin also means the user is authenticated by whatever Ranger is configured for
(local, LDAP, AD, SSO), and the agent needs no login of its own.

Agent side (`python -m ranger_ai_agent.cli serve`):

- Serves one route, `GET /api/v1/insights`. Other paths return 404, and other
  methods return 405.
- Requires `RANGER_AI_SERVE_TOKEN` (at least 32 characters) as a bearer token,
  compared in constant time. It refuses to start without one.
- Binds to loopback by default. A non-loopback bind needs `--allow-non-loopback`,
  and there is no TLS in the agent, so put it behind a TLS-terminating proxy.
- Opens the suggestion store read-only for each request. It never calls Ranger or
  the model. It cannot approve, apply or roll back.
- Leaves out raw policy bodies and action-log details. The page gets the plain
  change summary, not policy JSON.
- Returns `{"error": "internal error"}` with no details on failure.

Ranger Admin side (`AIInsightsREST`, `AIInsightsProxy`):

- `GET /service/ai-insights/report` is limited to `ROLE_SYS_ADMIN`. Auditors and
  other roles get 403. A unit test fails if any endpoint in the class loses that
  restriction or accepts a non-GET method.
- The agent URL and token come only from configuration (`ranger.ai.insights.*`).
  No request parameter selects a target, so it cannot be used to reach other
  hosts. Redirects are not followed, the URL may not contain credentials, and
  only http and https are accepted.
- The token can be held in the Ranger credential store through
  `ranger.ai.insights.credential.alias`, so it need not sit in a config file.
- Limits: 3 s connect and 10 s read timeouts (configurable), a 5 MiB response cap,
  and the body must be a JSON object.
- Off by default. While `ranger.ai.insights.enabled` is not `true`, the endpoint
  returns `{"enabled": false}` and contacts nothing.
- Failures reach the browser as 503 (misconfigured) or 502 (agent unreachable or
  invalid) with a fixed message. Details go to the Ranger Admin log, which never
  contains the token.

UI side (`views/AIInsights/AIInsights.jsx`):

- The menu entry and the route are for system administrators. The page also
  redirects anyone else to the forbidden page.
- It renders every value as React text, so markup in a policy name or an
  explanation is shown literally and never run.
- It is read-only: its only control is Refresh.

What was checked: Python unit tests for the endpoint and the read-only store;
Java unit tests for the proxy (against a local HTTP server: token and path sent,
redirect not followed, timeout, size cap, non-JSON, bad URLs and tokens) and for
the access rule; a production webpack build of the web app; a jsdom render of the
page against a real agent payload, including a check that hostile markup is
escaped; and one run of the compiled Java proxy against the real `serve`
process (good token accepted, wrong token refused, dead port reported).

What was not checked: a deployed Ranger Admin with a real login, the Spring
Security rule firing in a running server, Ranger's CSRF filter, and the page in a
real browser. The `@PreAuthorize` rule follows the pattern other Ranger resources
use, but it should be confirmed by logging in as a non-admin on a test system.

Trade-offs: the sidebar shows the entry to every system administrator even when
the feature is off, and the page then explains how to enable it. The page shows
real user names and policy IDs to system administrators, who can already see
that data in Ranger.
