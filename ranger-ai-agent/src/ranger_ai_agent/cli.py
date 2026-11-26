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

"""Command-line workflow: generate suggestions, review them, apply, roll back.

    PYTHONPATH=src python -m ranger_ai_agent.cli suggest --synthetic
    PYTHONPATH=src python -m ranger_ai_agent.cli list
    PYTHONPATH=src python -m ranger_ai_agent.cli approve <id> --reviewer alice
    PYTHONPATH=src python -m ranger_ai_agent.cli apply
    PYTHONPATH=src python -m ranger_ai_agent.cli rollback <id> --requester alice
    PYTHONPATH=src python -m ranger_ai_agent.cli report --output insights.html
    PYTHONPATH=src python -m ranger_ai_agent.cli verify-log

Settings:
    --store / RANGER_AI_STORE     SQLite file (default ./ranger-ai-suggestions.db)
    RANGER_AI_RANGER_*, RANGER_AI_SOLR_*   connection settings (see config.py)
    RANGER_AI_LLM_*               optional explanation model (see llm/providers.py)
    RANGER_AI_KILL_SWITCH, RANGER_AI_DRY_RUN (default on),
    RANGER_AI_MAX_CHANGES_PER_DAY, RANGER_AI_PROTECTED_POLICY_IDS

Exit codes: 0 success; 1 refused or failed request; 2 action log failed verification.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Optional, Sequence, Tuple

from ranger_ai_agent.clients.ranger_admin import RangerAdminReader
from ranger_ai_agent.clients.ranger_admin_writer import RangerAdminWriter
from ranger_ai_agent.clients.solr_audit import SolrAuditReader
from ranger_ai_agent.config import RangerConfig, SafetyConfig, SolrConfig
from ranger_ai_agent.detectors import DetectorConfig, run_detectors
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.llm.providers import provider_from_env
from ranger_ai_agent.models import UTC
from ranger_ai_agent.report import render_insights
from ranger_ai_agent.suggestions.apply import Applier
from ranger_ai_agent.suggestions.service import SuggestionService
from ranger_ai_agent.suggestions.store import SuggestionStore
from ranger_ai_agent.synthetic import build_scenario

DEFAULT_STORE = "ranger-ai-suggestions.db"
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_TAMPERED = 2


def build_live_sources() -> Tuple[SolrAuditReader, RangerAdminReader]:
    """Read-only sources for suggestion generation."""
    return SolrAuditReader(SolrConfig.from_env()), RangerAdminReader(RangerConfig.from_env())


def build_ranger_clients() -> Tuple[RangerAdminReader, RangerAdminWriter]:
    """Reader and writer for applying and rolling back. The writer is only used by apply/rollback."""
    config = RangerConfig.from_env()
    return RangerAdminReader(config), RangerAdminWriter(config)


def cmd_suggest(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    if args.synthetic:
        scenario = build_scenario()
        audit = policies = scenario.source
        as_of = scenario.as_of
    else:
        audit, policies = build_live_sources()
        as_of = datetime.now(UTC)

    raw = {int(p["id"]): p for p in policies.list_policies()}
    snap = SnapshotBuilder(audit, policies).build(as_of)
    findings = run_detectors(snap, DetectorConfig())
    service = SuggestionService(store, provider=provider_from_env(), safety=SafetyConfig.from_env())
    written = service.generate(snap, findings, raw)

    if SafetyConfig.from_env().kill_switch:
        print("kill switch is on: no suggestions generated", file=out)
    else:
        print("%d finding(s); %d suggestion(s) written (new or refreshed)" % (len(findings), len(written)), file=out)
    return EXIT_OK


def cmd_list(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    suggestions = store.list(args.status)
    print("%-20s %-10s %-24s %-8s %-12s %-6s %s" % ("ID", "STATUS", "KIND", "POLICY", "USER", "CONF", "ACTION"), file=out)
    for s in suggestions:
        print(
            "%-20s %-10s %-24s %-8s %-12s %-6.2f %s"
            % (
                s.suggestion_id,
                s.status,
                s.kind,
                "" if s.policy_id is None else s.policy_id,
                s.user or "",
                s.confidence,
                s.recommended_action,
            ),
            file=out,
        )
    print("%d suggestion(s)" % len(suggestions), file=out)
    return EXIT_OK


def cmd_show(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    suggestion = store.get(args.suggestion_id)
    if suggestion is None:
        print("error: no suggestion with id %s" % args.suggestion_id, file=sys.stderr)
        return EXIT_FAILED
    print(json.dumps(suggestion.to_dict(), indent=2, sort_keys=True), file=out)
    return EXIT_OK


def cmd_review(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    service = SuggestionService(store)
    if args.command == "approve":
        suggestion = service.approve(args.suggestion_id, args.reviewer)
    else:
        suggestion = service.reject(args.suggestion_id, args.reviewer)
    print("%s %s by %s" % (suggestion.suggestion_id, suggestion.status, suggestion.reviewed_by), file=out)
    return EXIT_OK


def cmd_apply(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    reader, writer = build_ranger_clients()
    safety = SafetyConfig.from_env()
    print("mode: %s" % ("DRY RUN (no changes written)" if safety.dry_run else "LIVE"), file=out)
    results = Applier(store, reader, writer, safety=safety).apply_approved()
    if not results:
        print("no approved suggestions to apply", file=out)
    for r in results:
        print("%-20s %-16s %s" % (r.suggestion_id, r.outcome, r.detail), file=out)
    return EXIT_OK


def cmd_rollback(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    reader, writer = build_ranger_clients()
    result = Applier(store, reader, writer, safety=SafetyConfig.from_env()).rollback(args.suggestion_id, args.requester)
    print("%-20s %-16s %s" % (result.suggestion_id, result.outcome, result.detail), file=out)
    return EXIT_OK


def cmd_report(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    page = render_insights(store, SafetyConfig.from_env(), datetime.now(UTC))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(page)
        print("wrote %s" % args.output, file=out)
    else:
        print(page, file=out)
    return EXIT_OK


def cmd_verify_log(args: argparse.Namespace, store: SuggestionStore, out) -> int:
    entries = len(store.log_entries())
    if store.verify_log():
        print("action log intact (%d entries)" % entries, file=out)
        return EXIT_OK
    print("error: action log FAILED verification (%d entries); the store may have been modified" % entries, file=sys.stderr)
    return EXIT_TAMPERED


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ranger_ai_agent", description="Review and apply Ranger access suggestions.")
    parser.add_argument("--store", default=os.environ.get("RANGER_AI_STORE", DEFAULT_STORE), help="SQLite file for suggestions and the action log")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("suggest", help="generate suggestions from audit and policy data")
    p.add_argument("--synthetic", action="store_true", help="use the built-in synthetic scenario instead of live Ranger and Solr")
    p.set_defaults(handler=cmd_suggest)

    p = sub.add_parser("list", help="list suggestions")
    p.add_argument("--status", choices=["PENDING", "APPROVED", "REJECTED", "APPLIED", "ROLLED_BACK"])
    p.set_defaults(handler=cmd_list)

    p = sub.add_parser("show", help="show one suggestion as JSON")
    p.add_argument("suggestion_id")
    p.set_defaults(handler=cmd_show)

    for name in ("approve", "reject"):
        p = sub.add_parser(name, help="%s a pending suggestion" % name)
        p.add_argument("suggestion_id")
        p.add_argument("--reviewer", required=True, help="name of the person making the decision")
        p.set_defaults(handler=cmd_review)

    p = sub.add_parser("apply", help="apply approved suggestions (dry run unless RANGER_AI_DRY_RUN=0)")
    p.set_defaults(handler=cmd_apply)

    p = sub.add_parser("rollback", help="restore the policy an applied suggestion changed")
    p.add_argument("suggestion_id")
    p.add_argument("--requester", required=True, help="name of the person requesting the rollback")
    p.set_defaults(handler=cmd_rollback)

    p = sub.add_parser("report", help="write a read-only HTML insights page")
    p.add_argument("--output", help="file to write (default: standard output)")
    p.set_defaults(handler=cmd_report)

    p = sub.add_parser("verify-log", help="check the action log hash chain")
    p.set_defaults(handler=cmd_verify_log)
    return parser


def main(argv: Optional[Sequence[str]] = None, out: Any = None) -> int:
    out = out or sys.stdout
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        with SuggestionStore(args.store) as store:
            return args.handler(args, store, out)
    except KeyError as exc:
        print("error: %s" % (exc.args[0] if exc.args else exc), file=sys.stderr)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - report client and transport failures without a traceback
        print("error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
