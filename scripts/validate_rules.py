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

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "libs" / "signalforge"))

from signalforge.sigma import lint_rules  # noqa: E402
from signalforge.sigma.loader import load_ruleset  # noqa: E402


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

    if args.format == "json":
        payload = report.to_dict()
        payload["load_errors"] = [{"path": path, "error": error} for path, error in ruleset.errors]
        print(json.dumps(payload, indent=2))
    elif args.format == "github":
        for problem in report.problems:
            level = "error" if problem.severity == "error" else "warning"
            print(
                "::%s file=%s,title=%s::%s (%s)"
                % (level, problem.path, problem.code, problem.message, problem.rule_id or "-")
            )
        print(
            "::notice::%d detections, %d correlations, %d with tests"
            % (report.rule_count, report.correlation_count, report.tested_rules)
        )
    else:
        for problem in report.problems:
            print(problem.format())
        print()
        print("detections     : %d" % report.rule_count)
        print("correlations   : %d" % report.correlation_count)
        print("with tests     : %d" % report.tested_rules)
        print("errors         : %d" % len(report.errors))
        print("warnings       : %d" % len(report.warnings))
        print("result         : %s" % ("PASS" if report.ok else "FAIL"))

    failed = not report.ok or bool(ruleset.errors)
    if args.warnings_as_errors and report.warnings:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
