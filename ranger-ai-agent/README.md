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

Not yet implemented: the LLM reasoning layer, suggestion storage, approval and
rollback, and the UI.

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
| `RANGER_AI_DRY_RUN` | `true` | Never write to Ranger when true |
| `RANGER_AI_KILL_SWITCH` | `false` | Disable all agent actions |

## Safety

The Ranger and Solr clients are read-only by construction. Nothing in this
package changes Ranger state; applying approved suggestions will live in a
separate, approval-gated component.
