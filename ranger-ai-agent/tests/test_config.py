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

from ranger_ai_agent.config import RangerConfig, SafetyConfig, SolrConfig


def test_safety_defaults_are_restrictive(monkeypatch):
    monkeypatch.delenv("RANGER_AI_DRY_RUN", raising=False)
    monkeypatch.delenv("RANGER_AI_KILL_SWITCH", raising=False)
    cfg = SafetyConfig.from_env()
    assert cfg.dry_run is True
    assert cfg.kill_switch is False


def test_tls_verify_defaults_on_and_accepts_ca_path(monkeypatch):
    monkeypatch.delenv("RANGER_AI_RANGER_VERIFY_TLS", raising=False)
    assert RangerConfig.from_env().verify_tls is True
    monkeypatch.setenv("RANGER_AI_RANGER_VERIFY_TLS", "false")
    assert RangerConfig.from_env().verify_tls is False
    monkeypatch.setenv("RANGER_AI_RANGER_VERIFY_TLS", "/etc/ssl/ca.pem")
    assert RangerConfig.from_env().verify_tls == "/etc/ssl/ca.pem"


def test_password_not_in_repr(monkeypatch):
    monkeypatch.setenv("RANGER_AI_RANGER_PASSWORD", "s3cret")
    monkeypatch.setenv("RANGER_AI_SOLR_PASSWORD", "s3cret2")
    assert "s3cret" not in repr(RangerConfig.from_env())
    assert "s3cret2" not in repr(SolrConfig.from_env())
