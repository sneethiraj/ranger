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

# ranger-ai-agent

Agentic AI for Apache Ranger: policy suggestions and anomaly detection
([RANGER-5278](https://issues.apache.org/jira/browse/RANGER-5278)).
See [docs/design.md](docs/design.md).

Status: early development. Implemented so far:

- configuration, a read-only Ranger Admin client, and a read-only Solr audit client
- point-in-time feature snapshots, with a SQLite feature store
- three deterministic detectors: over-privileged grants, stale policies, abnormal access time
- a replay harness and a synthetic scenario with planted anomalies and ground truth
- an optional LLM explanation layer: pseudonymized input, strict output validation, deterministic fallback
- a suggestion store with an append-only, hash-chained action log
- human approval, guarded apply with read-back verification, and rollback (dry run by default)
- a command-line workflow and a read-only HTML "AI Insights" report
- a read-only "AI Insights" page in the Ranger Admin UI for system administrators
  (see [Viewing the report in Ranger Admin](#viewing-the-report-in-ranger-admin))

Not yet implemented: evaluation of group and role grants, and end-to-end testing
against a live Ranger and Solr. The Ranger Admin page has not been run in a deployed
Ranger Admin.
See [docs/design.md](docs/design.md#10-implementation-status) for the full list of gaps.

## Demo

Replays 30 days of synthetic audit history and prints a report with precision
and recall against the planted anomalies:

```
PYTHONPATH=src python -m ranger_ai_agent.demo [--store features.db] [--seed 7]
```

## Detectors

| Detector | Flags when | Confidence (heuristic) |
|---|---|---|
| `OVER_PRIVILEGED` | An enabled policy has at least `min_policy_events` (20) allowed events in the 90-day lookback, and a user granted it has zero allowed events through it | `0.6 + 0.3 * min(1, policy_events / 50)` |
| `STALE_POLICY` | An enabled policy was created or changed at least 90 days ago and has no allowed events in the lookback | fixed `0.8` |
| `ABNORMAL_ACCESS_TIME` | Off-hours share (UTC, default 18:00-05:59) of the last 7 days is at least 0.2 above the user's 30-day baseline share, with a binomial z-score of at least 3 | `min(0.95, 0.5 + 0.1 * z)` |

Limitations of the current rules:

- Grants made through groups or roles are not evaluated, because group
  membership is not yet read. Only direct user grants are checked.
- Service and automation accounts can be flagged. Use `exclude_users` in
  `DetectorConfig` to suppress them.
- Off-hours are defined in UTC. Per-user time zones are not modelled yet.
- The abnormal-time rule has a detection lag. In the synthetic scenario the
  change starts on 2026-05-25 and is first flagged on 2026-05-28, because the
  0.2 minimum-delta gate is not crossed earlier. Lowering `min_share_delta`
  shortens the lag and increases false positives.

## Setup

```
cd ranger-ai-agent
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `RANGER_AI_RANGER_URL` | `http://localhost:6080` | Ranger Admin base URL |
| `RANGER_AI_RANGER_USER` / `RANGER_AI_RANGER_PASSWORD` | empty | Read-only service account |
| `RANGER_AI_RANGER_VERIFY_TLS` | `true` | `true`, `false`, or a CA bundle path |
| `RANGER_AI_SOLR_URL` | `http://localhost:6083/solr` | Solr base URL |
| `RANGER_AI_SOLR_COLLECTION` | `ranger_audits` | Audit collection |
| `RANGER_AI_SOLR_USER` / `RANGER_AI_SOLR_PASSWORD` | unset | Solr basic auth |
| `RANGER_AI_DRY_RUN` | `true` | Log planned policy changes, never write to Ranger |
| `RANGER_AI_KILL_SWITCH` | `false` | Stop generating, applying, and rolling back |
| `RANGER_AI_MAX_CHANGES_PER_DAY` | `5` | Cap on applied changes in a rolling 24-hour window |
| `RANGER_AI_PROTECTED_POLICY_IDS` | empty | Comma-separated policy IDs the agent must never change |
| `RANGER_AI_STORE` | `ranger-ai-suggestions.db` | SQLite file for suggestions and the action log |
| `RANGER_AI_LLM_PROVIDER` | `none` | `none`, `openai` (any OpenAI-compatible endpoint), or `ollama` |
| `RANGER_AI_LLM_URL` / `RANGER_AI_LLM_MODEL` / `RANGER_AI_LLM_API_KEY` | unset | Model endpoint settings |
| `RANGER_AI_ALLOW_EXTERNAL_LLM` | `false` | Required to use a non-local model endpoint (pseudonymized data leaves the host) |
| `RANGER_AI_PSEUDONYM_KEY` | random per process | HMAC key for pseudonyms sent to a model; set it for stable pseudonyms |
| `RANGER_AI_SERVE_TOKEN` | unset | Bearer token (32+ characters) the `serve` command requires. `serve` refuses to start without it |

## Command line

```
export PYTHONPATH=src
python -m ranger_ai_agent.cli suggest --synthetic   # or `suggest` with live Ranger and Solr
python -m ranger_ai_agent.cli list --status PENDING
python -m ranger_ai_agent.cli show <id>
python -m ranger_ai_agent.cli approve <id> --reviewer alice
python -m ranger_ai_agent.cli apply                 # dry run unless RANGER_AI_DRY_RUN=0
python -m ranger_ai_agent.cli rollback <id> --requester alice
python -m ranger_ai_agent.cli report --output insights.html   # read-only HTML "AI Insights" page
python -m ranger_ai_agent.cli verify-log
python -m ranger_ai_agent.cli serve                 # read-only JSON for the Ranger Admin page (needs RANGER_AI_SERVE_TOKEN)
```

The report is a single static file with no scripts, forms, or external
resources. It shows real user names, so treat it as internal.

Reviewer and requester names must identify a person; `agent` is refused.
Exit codes: `0` success, `1` refused or failed, `2` action log failed verification.

## Viewing the report in Ranger Admin

System administrators can see the report under **Settings > AI Insights** in the
Ranger Admin UI. The page is read-only. Approving, applying and rolling back stay
on the command line.

1. Make a token of at least 32 characters:
   `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`
2. Create the store with `suggest`, then start the endpoint on the Ranger Admin host:
   ```
   export RANGER_AI_SERVE_TOKEN=<token>
   python -m ranger_ai_agent.cli serve            # 127.0.0.1:6090
   ```
   `serve` binds to loopback only. To listen elsewhere, add `--allow-non-loopback`
   and put a TLS-terminating proxy in front, because the agent speaks plain HTTP.
3. In `ranger-admin-site.xml`, then restart Ranger Admin:

   | Property | Value |
   |---|---|
   | `ranger.ai.insights.enabled` | `true` (default `false`) |
   | `ranger.ai.insights.url` | `http://127.0.0.1:6090` |
   | `ranger.ai.insights.token` | the token, or leave empty and use the alias below |
   | `ranger.ai.insights.credential.alias` | alias in the Ranger credential store that holds the token; used instead of the plain property when found |
   | `ranger.ai.insights.connect.timeout.ms` / `ranger.ai.insights.read.timeout.ms` | `3000` / `10000` |

Ranger Admin fetches the report with the token, so the browser never sees it. Only
the `ROLE_SYS_ADMIN` role can call `GET /service/ai-insights/report`, and the target
URL comes only from this configuration. If the agent is down or misconfigured the
page shows a short error, and the details are in the Ranger Admin log. See
[docs/design.md](docs/design.md#11-ranger-admin-ui) for the security model.

## Safety

- Suggestions are read-only until a person approves them.
- Proposals are built by deterministic code. A model can explain a finding but
  cannot change its proposal, status, or confidence.
- Proposals may remove grants or disable a policy. They may never add grants,
  re-enable a policy, or change a policy's identity.
- Before any write, the applier checks the kill switch, the daily cap, the
  protected-policy list, and that the live policy version is the one the proposal
  was built from. A mismatch is reported as `CONFLICT` and nothing is written.
- Every write is read back and checked. Rollback restores the stored pre-change
  policy and refuses if the policy changed since the agent wrote it.
- The action log is append-only (database triggers) and hash-chained, so
  `verify-log` detects edits made around the triggers.
- The read client is GET-only. Writes go through a separate client that can only
  update a policy.
