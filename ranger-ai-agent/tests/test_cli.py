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

import copy
import json
import os
import sqlite3

import pytest

from ranger_ai_agent import cli
from ranger_ai_agent.clients.ranger_admin import RangerApiError
from ranger_ai_agent.clients.solr_audit import SolrAuditError
from ranger_ai_agent.suggestions.models import suggestion_id_for
from ranger_ai_agent.synthetic import build_scenario

SID_REMOVE = suggestion_id_for("OVER_PRIVILEGED", 1, "carol")
SID_DISABLE = suggestion_id_for("STALE_POLICY", 9, None)


class FakeRanger:
    def __init__(self, policies):
        self.policies = {p["id"]: copy.deepcopy(p) for p in policies}
        self.writes = 0

    def get_policy(self, policy_id):
        return copy.deepcopy(self.policies[policy_id])

    def update_policy(self, policy_id, body):
        self.writes += 1
        stored = copy.deepcopy(body)
        stored["version"] = self.policies[policy_id]["version"] + 1
        self.policies[policy_id] = stored
        return copy.deepcopy(stored)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("RANGER_AI_"):
            monkeypatch.delenv(name)


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "suggestions.db")


@pytest.fixture(autouse=True)
def log_key(monkeypatch):
    monkeypatch.setenv("RANGER_AI_LOG_KEY", "test-action-log-key-0123456789abcdef")


@pytest.fixture
def ranger(monkeypatch):
    fake = FakeRanger(build_scenario().source.list_policies())
    monkeypatch.setattr(cli, "build_ranger_clients", lambda: (fake, fake))
    monkeypatch.setattr(cli, "build_audit_source", lambda: build_scenario().source)
    return fake


def run(store_path, *args):
    return cli.main(["--store", store_path, *args])


def suggest_and_approve(store_path, capsys):
    assert run(store_path, "suggest", "--synthetic") == 0
    capsys.readouterr()
    assert run(store_path, "approve", SID_REMOVE, "--reviewer", "alice") == 0
    assert run(store_path, "approve", SID_DISABLE, "--reviewer", "alice") == 0
    capsys.readouterr()


def test_suggest_writes_the_three_planted_findings(store_path, capsys):
    assert run(store_path, "suggest", "--synthetic") == 0
    out = capsys.readouterr().out
    assert "3 suggestion(s) written" in out
    assert run(store_path, "list") == 0
    assert "3 suggestion(s)" in capsys.readouterr().out


def test_list_filters_by_status(store_path, capsys):
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "list", "--status", "APPROVED") == 0
    out = capsys.readouterr().out
    assert SID_REMOVE in out and SID_DISABLE in out
    assert "2 suggestion(s)" in out


def test_show_prints_the_proposal_as_json(store_path, capsys):
    run(store_path, "suggest", "--synthetic")
    capsys.readouterr()
    assert run(store_path, "show", SID_REMOVE) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["proposal"]["action"] == "REMOVE_USER_FROM_POLICY"
    assert data["proposal"]["target_user"] == "carol"


def test_show_unknown_id_fails_cleanly(store_path, capsys):
    assert run(store_path, "show", "nope") == 1
    assert "no suggestion with id nope" in capsys.readouterr().err


def test_agent_cannot_approve(store_path, capsys):
    run(store_path, "suggest", "--synthetic")
    capsys.readouterr()
    assert run(store_path, "approve", SID_REMOVE, "--reviewer", "agent") == 1
    assert "named human" in capsys.readouterr().err


def test_reject_after_approve_is_refused(store_path, capsys):
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "reject", SID_REMOVE, "--reviewer", "bob") == 1
    assert "cannot move suggestion" in capsys.readouterr().err


def test_apply_defaults_to_dry_run_and_writes_nothing(store_path, capsys, ranger):
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "apply") == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "DRY_RUN" in out
    assert ranger.writes == 0


def test_apply_live_writes_approved_changes(store_path, capsys, ranger, monkeypatch):
    monkeypatch.setenv("RANGER_AI_DRY_RUN", "0")
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "apply") == 0
    out = capsys.readouterr().out
    assert "LIVE" in out and out.count("APPLIED") == 2
    assert ranger.writes == 2
    assert run(store_path, "list", "--status", "APPLIED") == 0
    assert "2 suggestion(s)" in capsys.readouterr().out


def test_rollback_restores_and_requires_a_human(store_path, capsys, ranger, monkeypatch):
    monkeypatch.setenv("RANGER_AI_DRY_RUN", "0")
    suggest_and_approve(store_path, capsys)
    run(store_path, "apply")
    capsys.readouterr()

    assert run(store_path, "rollback", SID_REMOVE, "--requester", "agent") == 1
    assert "named human" in capsys.readouterr().err

    assert run(store_path, "rollback", SID_REMOVE, "--requester", "bob") == 0
    assert "ROLLED_BACK" in capsys.readouterr().out


def test_kill_switch_stops_generation(store_path, capsys, monkeypatch):
    monkeypatch.setenv("RANGER_AI_KILL_SWITCH", "1")
    assert run(store_path, "suggest", "--synthetic") == 0
    assert "kill switch is on" in capsys.readouterr().out
    run(store_path, "list")
    assert "0 suggestion(s)" in capsys.readouterr().out


def test_live_suggest_uses_injected_sources_at_current_time(store_path, capsys, monkeypatch):
    # The live path evaluates as of "now", so the synthetic history (anchored in 2026-06)
    # produces different findings than --synthetic does. Only the wiring is checked here.
    scenario = build_scenario()
    monkeypatch.setattr(cli, "build_live_sources", lambda: (scenario.source, scenario.source))
    assert run(store_path, "suggest") == 0
    out = capsys.readouterr().out
    assert "finding(s)" in out and "suggestion(s) written" in out


def test_source_errors_are_reported_without_a_traceback(store_path, capsys, monkeypatch):
    def broken():
        raise SolrAuditError("Solr returned HTTP 503")

    monkeypatch.setattr(cli, "build_live_sources", broken)
    assert run(store_path, "suggest") == 1
    err = capsys.readouterr().err
    assert "SolrAuditError: Solr returned HTTP 503" in err
    assert "Traceback" not in err


def test_ranger_errors_during_apply_are_reported(store_path, capsys, monkeypatch):
    suggest_and_approve(store_path, capsys)

    class Down:
        def get_policy(self, policy_id):
            raise RangerApiError("GET policy returned HTTP 503")

        def update_policy(self, policy_id, body):
            raise RangerApiError("unreachable")

    monkeypatch.setattr(cli, "build_ranger_clients", lambda: (Down(), Down()))
    monkeypatch.setattr(cli, "build_audit_source", lambda: build_scenario().source)
    assert run(store_path, "apply") == 0  # each suggestion reports FAILED; the run itself completes
    assert "FAILED" in capsys.readouterr().out


def test_verify_log_passes_then_detects_tampering(store_path, capsys):
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "verify-log") == 0
    assert "intact" in capsys.readouterr().out

    conn = sqlite3.connect(store_path)
    conn.execute("DROP TRIGGER action_log_no_update")
    conn.execute("UPDATE action_log SET actor = 'mallory' WHERE log_id = 1")
    conn.commit()
    conn.close()

    assert run(store_path, "verify-log") == 2
    assert "FAILED verification" in capsys.readouterr().err


def test_verify_log_reports_signing_and_head(store_path, capsys):
    suggest_and_approve(store_path, capsys)
    assert run(store_path, "verify-log") == 0
    out = capsys.readouterr().out
    assert "signed" in out and "not signed" not in out
    assert out.splitlines()[-1].startswith("head ")


def test_signed_store_without_the_key_cannot_be_verified_or_written(store_path, capsys, monkeypatch):
    suggest_and_approve(store_path, capsys)
    monkeypatch.delenv("RANGER_AI_LOG_KEY")
    assert run(store_path, "verify-log") == 1
    assert "RANGER_AI_LOG_KEY" in capsys.readouterr().err
    assert run(store_path, "suggest", "--synthetic") == 1
    assert "LogKeyRequired" in capsys.readouterr().err


def test_live_apply_without_a_log_key_writes_nothing(tmp_path, capsys, ranger, monkeypatch):
    monkeypatch.delenv("RANGER_AI_LOG_KEY")
    monkeypatch.setenv("RANGER_AI_DRY_RUN", "0")
    path = str(tmp_path / "unsigned.db")
    suggest_and_approve(path, capsys)
    assert run(path, "apply") == 0
    assert "LOG_KEY_REQUIRED" in capsys.readouterr().out
    assert ranger.writes == 0


def test_report_writes_a_read_only_page(store_path, tmp_path, capsys):
    suggest_and_approve(store_path, capsys)
    target = tmp_path / "insights.html"
    assert run(store_path, "report", "--output", str(target)) == 0
    assert "wrote" in capsys.readouterr().out
    text = target.read_text(encoding="utf-8")
    assert "Ranger AI Insights" in text
    assert "<script" not in text.lower()


def test_suggest_reports_expired_suggestions(store_path, capsys):
    run(store_path, "suggest", "--synthetic")
    assert "0 expired" in capsys.readouterr().out
    run(store_path, "list", "--status", "EXPIRED")
    assert "0 suggestion(s)" in capsys.readouterr().out


def test_reconcile_settles_a_write_that_needs_attention(store_path, capsys, ranger, monkeypatch):
    monkeypatch.setenv("RANGER_AI_DRY_RUN", "0")
    suggest_and_approve(store_path, capsys)

    real_get = ranger.get_policy

    def unreadable_after_a_write(policy_id):
        if ranger.writes:
            raise RangerApiError("GET policy timed out")
        return real_get(policy_id)

    ranger.get_policy = unreadable_after_a_write
    run(store_path, "apply")
    assert "NEEDS_ATTENTION" in capsys.readouterr().out

    ranger.get_policy = real_get
    assert run(store_path, "reconcile", SID_REMOVE, "--reviewer", "agent") == 1
    assert "named human" in capsys.readouterr().err
    assert run(store_path, "reconcile", SID_REMOVE, "--reviewer", "alice") == 0
    assert "APPLIED" in capsys.readouterr().out
    run(store_path, "list", "--status", "APPLIED")
    assert "1 suggestion(s)" in capsys.readouterr().out
