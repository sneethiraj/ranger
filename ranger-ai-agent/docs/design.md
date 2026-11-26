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
status: PENDING | APPROVED | REJECTED | APPLIED | ROLLED_BACK,
created_at, reviewed_by, reviewed_at, applied_at
```

`confidence` = weighted combination of detector score and LLM self-assessment;
the formula is documented and unit tested.

## 7. Approval, apply and rollback

- Approve -> re-validate -> snapshot current policy (version N) -> apply ->
  record suggestion id in the policy change description.
- Rollback restores the stored snapshot and is itself logged.
- Safeguards: dry-run default, kill switch, per-day change cap, protected
  service/policy deny-list, no admin or wildcard grants.

## 8. Security and logging

- Append-only action log for every collect, detect, prompt, response,
  decision and apply, with the model name/version and an evidence hash.
- Secrets (Ranger password, LLM API keys) come from environment variables or
  the Ranger credential provider, never from plain config files.
- TLS verification is on by default.

## 9. Open questions

1. Suggestion store: SQLite for the MVP, pluggable later?
2. UI path: thin proxy endpoint in security-admin so the browser reuses Ranger
   authentication?
3. Packaging: standalone Python service now, optional Maven/distro integration
   later?
