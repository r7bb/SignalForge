#!/usr/bin/env python3
"""Detection rule linter - the CI gate for detection pull requests.

    python scripts/validate_rules.py detections
    python scripts/validate_rules.py detections --format github   # annotations
    python scripts/validate_rules.py detections --no-require-tests

Exit codes: 0 clean, 1 errors found, 2 bad invocation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "libs" / "signalforge"))

from signalforge.routing import RoutingError, load_routing_table  # noqa: E402
from signalforge.sigma import lint_rules  # noqa: E402
from signalforge.sigma.loader import load_ruleset  # noqa: E402


def lint_routing(directory: Path) -> Tuple[List[str], int]:
    """Validate the routing table. Returns ``(problems, rule_count)``.

    Beyond what the loader rejects, this checks two things a single rule cannot
    know about itself: that the table has a reachable catch-all, and that no
    rule is shadowed by an earlier one that already matches everything.
    """
    if not directory.exists():
        return [], 0

    problems: List[str] = []
    try:
        table = load_routing_table(directory, strict=True)
    except RoutingError as exc:
        return [str(exc)], 0

    problems.extend(table.errors)

    catch_alls = [rule for rule in table.rules if rule.is_catch_all and rule.enabled]
    if not catch_alls:
        problems.append(
            "%s: no catch-all rule; incidents matching nothing fall back to the "
            "tenant default queue without an explicit routing decision" % directory
        )
    for rule in catch_alls[1:]:
        problems.append(
            "%s: %r is a second catch-all and can never be reached"
            % (rule.source_path or directory, rule.id)
        )
    if catch_alls:
        first_catch_all = catch_alls[0]
        for rule in table.rules:
            if rule is first_catch_all:
                continue
            if rule.enabled and rule.priority > first_catch_all.priority:
                problems.append(
                    "%s: %r (priority %d) sits behind the catch-all %r (priority %d) "
                    "and can never match"
                    % (
                        rule.source_path or directory,
                        rule.id,
                        rule.priority,
                        first_catch_all.id,
                        first_catch_all.priority,
                    )
                )
    return problems, len(table.rules)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SignalForge detection rules")
    parser.add_argument(
        "path", nargs="?", default="detections", help="rule directory (default: detections)"
    )
    parser.add_argument("--format", choices=["text", "json", "github"], default="text")
    parser.add_argument(
        "--no-require-tests",
        action="store_true",
        help="do not fail rules that ship without a test file",
    )
    parser.add_argument(
        "--no-require-attack", action="store_true", help="do not fail rules without ATT&CK tags"
    )
    parser.add_argument("--warnings-as-errors", action="store_true")
    parser.add_argument(
        "--routing",
        default="routing",
        help="routing rule directory to lint as well (default: routing)",
    )
    parser.add_argument("--no-routing", action="store_true", help="skip routing rule validation")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print("rule path %s does not exist" % target, file=sys.stderr)
        return 2

    report = lint_rules(
        target,
        require_tests=not args.no_require_tests,
        require_attack_tags=not args.no_require_attack,
    )
    # Loading with strict=False surfaces reference problems the linter also
    # reports; loading again here proves the engine can actually build the set.
    ruleset = load_ruleset(target)

    # Routing is config-as-code for the same reasons detections are, so it
    # goes through the same gate. A routing rule naming a match field that
    # does not exist is a rule that silently never fires.
    routing_problems: List[str] = []
    routing_count = 0
    if not args.no_routing:
        routing_problems, routing_count = lint_routing(Path(args.routing))

    if args.format == "json":
        payload = report.to_dict()
        payload["load_errors"] = [{"path": path, "error": error} for path, error in ruleset.errors]
        payload["routing"] = {"rules": routing_count, "errors": routing_problems}
        print(json.dumps(payload, indent=2))
    elif args.format == "github":
        for problem in report.problems:
            level = "error" if problem.severity == "error" else "warning"
            print(
                "::%s file=%s,title=%s::%s (%s)"
                % (level, problem.path, problem.code, problem.message, problem.rule_id or "-")
            )
        for problem in routing_problems:
            print("::error title=routing::%s" % problem)
        print(
            "::notice::%d detections, %d correlations, %d with tests, %d routing rules"
            % (report.rule_count, report.correlation_count, report.tested_rules, routing_count)
        )
    else:
        for problem in report.problems:
            print(problem.format())
        print()
        print("detections     : %d" % report.rule_count)
        print("correlations   : %d" % report.correlation_count)
        print("with tests     : %d" % report.tested_rules)
        for problem in routing_problems:
            print("routing: %s" % problem)
        print("routing rules  : %d" % routing_count)
        print("errors         : %d" % (len(report.errors) + len(routing_problems)))
        print("warnings       : %d" % len(report.warnings))
        print("result         : %s" % ("PASS" if report.ok and not routing_problems else "FAIL"))

    failed = not report.ok or bool(ruleset.errors) or bool(routing_problems)
    if args.warnings_as_errors and report.warnings:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
