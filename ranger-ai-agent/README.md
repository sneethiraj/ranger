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

Status: early development. Implemented so far: configuration, a read-only
Ranger Admin client, and a read-only Solr audit client.

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
