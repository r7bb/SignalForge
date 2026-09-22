#!/usr/bin/env python3
"""Drive the case-management features that have no dashboard surface yet.

Linking, merging and presence are API-only (see docs/ROADMAP.md, *What is
left*). Until the dashboard catches up, this is the supported way to use them
rather than hand-rolling ``curl`` with a bearer token each time:

    python scripts/case.py links INC-2004
    python scripts/case.py link INC-2004 INC-2010 --rel related_to --reason "same credential"
    python scripts/case.py unlink INC-2004 INC-2010
    python scripts/case.py merge INC-2004 INC-2010            # preview only
    python scripts/case.py merge INC-2004 INC-2010 --confirm --reason "one intrusion"
    python scripts/case.py viewers INC-2004
    python scripts/case.py watch INC-2004

**Merge previews by default.** The API commits immediately and a merge is not
practically reversible, so this refuses to run one without ``--confirm`` and
shows what would move first: how many alerts, which entities, the resulting
risk. That is the dry-run-first pattern the response playbooks use, applied
client-side until the API grows a preview of its own.

Credentials come from the environment, so nothing lands in shell history:

    export SIGNALFORGE_API=http://localhost:8000/api/v1
    export SIGNALFORGE_EMAIL=dana@acme.test
    export SIGNALFORGE_PASSWORD=...
    export SIGNALFORGE_TENANT=acme
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_API = os.environ.get("SIGNALFORGE_API", "http://localhost:8000/api/v1")

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"


class ApiError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__("%s: %s" % (status, detail))
        self.status = status
        self.detail = detail


class Client:
    def __init__(self, base: str, token: Optional[str] = None) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def call(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self.token:
            headers["authorization"] = "Bearer " + self.token
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request) as response:
                body = response.read()
                return response.status, (json.loads(body) if body else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                detail = json.loads(raw).get("detail", raw)
            except ValueError:
                detail = raw
            raise ApiError(exc.code, str(detail)) from None
        except urllib.error.URLError as exc:
            raise ApiError(0, "cannot reach %s (%s)" % (self.base, exc.reason)) from None

    def login(self, email: str, password: str, tenant: Optional[str]) -> None:
        _, body = self.call(
            "POST", "/auth/login", {"email": email, "password": password, "tenant": tenant}
        )
        self.token = body["access_token"]


def connect(args: argparse.Namespace) -> Client:
    client = Client(args.api, os.environ.get("SIGNALFORGE_TOKEN"))
    if client.token:
        return client

    email = args.email or os.environ.get("SIGNALFORGE_EMAIL")
    password = os.environ.get("SIGNALFORGE_PASSWORD")
    tenant = args.tenant or os.environ.get("SIGNALFORGE_TENANT")
    if not email or not password:
        raise SystemExit(
            "set SIGNALFORGE_TOKEN, or SIGNALFORGE_EMAIL and SIGNALFORGE_PASSWORD "
            "(a password on the command line ends up in shell history)"
        )
    client.login(email, password, tenant)
    return client


# --------------------------------------------------------------------- links
def cmd_links(client: Client, args: argparse.Namespace) -> int:
    _, body = client.call("GET", "/incidents/%s/links" % args.incident)
    links: List[Dict[str, Any]] = body["links"]
    if not links:
        print("%s has no links." % args.incident)
        return 0
    print("%s%s%s" % (BOLD, args.incident, RESET))
    for link in links:
        arrow = "->" if link["outgoing"] else "<-"
        print(
            "  %s %-14s %-9s %s%s%s"
            % (
                arrow,
                link["relationship"],
                link["other_key"],
                DIM,
                link["other_title"][:44],
                RESET,
            )
        )
        if link.get("reason"):
            print("     %s%s%s" % (DIM, link["reason"], RESET))
    return 0


def cmd_link(client: Client, args: argparse.Namespace) -> int:
    _, body = client.call(
        "POST",
        "/incidents/%s/links" % args.incident,
        {"incident": args.other, "relationship": args.rel, "reason": args.reason},
    )
    print(
        "%slinked%s %s %s %s (%d link(s) total)"
        % (GREEN, RESET, args.incident, args.rel, args.other, body["count"])
    )
    return 0


def cmd_unlink(client: Client, args: argparse.Namespace) -> int:
    _, body = client.call("DELETE", "/incidents/%s/links/%s" % (args.incident, args.other))
    print(
        "%sunlinked%s %s and %s (%d remain)"
        % (GREEN, RESET, args.incident, args.other, body["count"])
    )
    return 0


# --------------------------------------------------------------------- merge
def cmd_merge(client: Client, args: argparse.Namespace) -> int:
    """Preview by default; only commit with --confirm."""
    _, survivor = client.call("GET", "/incidents/%s" % args.keep)
    _, duplicate = client.call("GET", "/incidents/%s" % args.merge)

    if duplicate["status"] in ("resolved", "closed_false_positive"):
        print(
            "%s%s is already closed (%s).%s The API refuses to merge it: closing "
            "was a decision somebody made." % (RED, args.merge, duplicate["status"], RESET)
        )
        return 1

    print("%sMerge preview%s" % (BOLD, RESET))
    print("  keep    %-9s %s" % (survivor["key"], survivor["title"][:52]))
    print("  merge   %-9s %s" % (duplicate["key"], duplicate["title"][:52]))
    print()
    print("  %-22s %-10s %-10s %s" % ("", "keep", "merge", "after"))
    print(
        "  %-22s %-10d %-10d %d"
        % (
            "alerts",
            survivor["alert_count"],
            duplicate["alert_count"],
            survivor["alert_count"] + duplicate["alert_count"],
        )
    )
    print(
        "  %-22s %-10d %-10d %d"
        % (
            "evidence events",
            survivor["evidence_count"],
            duplicate["evidence_count"],
            survivor["evidence_count"] + duplicate["evidence_count"],
        )
    )
    print(
        "  %-22s %-10d %-10d %d"
        % (
            "risk",
            survivor["risk_score"],
            duplicate["risk_score"],
            max(survivor["risk_score"], duplicate["risk_score"]),
        )
    )
    for field in ("source_ips", "hostnames"):
        after = sorted(set(survivor.get(field) or []) | set(duplicate.get(field) or []))
        print("  %-22s %s" % (field, ", ".join(after) or "-"))
    print()
    print("  %s%s closes with 'Merged into %s'%s" % (DIM, duplicate["key"], survivor["key"], RESET))

    if not args.confirm:
        print()
        print(
            "%sPreview only.%s Re-run with --confirm to apply. A merge is not "
            "practically reversible." % (YELLOW, RESET)
        )
        return 0

    try:
        _, merged = client.call(
            "POST",
            "/incidents/%s/merge" % args.keep,
            {"incident": args.merge, "reason": args.reason},
        )
    except ApiError as exc:
        if exc.status == 403:
            print(
                "%sRefused (403):%s %s\nA merge needs the responder role."
                % (RED, RESET, exc.detail)
            )
            return 1
        raise
    print()
    print(
        "%smerged%s %s into %s - now %d alerts, risk %d"
        % (GREEN, RESET, args.merge, merged["key"], merged["alert_count"], merged["risk_score"])
    )
    return 0


# ------------------------------------------------------------------ presence
def cmd_viewers(client: Client, args: argparse.Namespace) -> int:
    """Heartbeat, and report who else is on this incident."""
    _, body = client.call("POST", "/incidents/%s/presence" % args.incident)
    viewers = body["viewers"]
    print("presence backend: %s" % body["backend"])
    if not viewers:
        print("Nobody else is viewing %s." % args.incident)
        return 0
    for viewer in viewers:
        print("  %-24s last seen %ss ago" % (viewer["email"], viewer["idle_seconds"]))
    return 0


def cmd_watch(client: Client, args: argparse.Namespace) -> int:
    method = "DELETE" if args.stop else "POST"
    _, body = client.call(method, "/incidents/%s/watch" % args.incident)
    state = "watching" if body["watching"] else "not watching"
    print("%s: %s (%d watcher(s))" % (args.incident, state, len(body["watchers"])))
    for watcher in body["watchers"]:
        print("  %-24s %s" % (watcher["email"], watcher["reason"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--api", default=DEFAULT_API, help="API base (default: %s)" % DEFAULT_API)
    parser.add_argument("--email", help="overrides SIGNALFORGE_EMAIL")
    parser.add_argument("--tenant", help="overrides SIGNALFORGE_TENANT")
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("links", help="show an incident's links")
    show.add_argument("incident")
    show.set_defaults(handler=cmd_links)

    add = sub.add_parser("link", help="link two incidents")
    add.add_argument("incident")
    add.add_argument("other")
    add.add_argument(
        "--rel",
        default="related_to",
        choices=["related_to", "duplicate_of", "caused_by"],
        help="relationship, asserted from `incident` towards `other`",
    )
    add.add_argument("--reason")
    add.set_defaults(handler=cmd_link)

    drop = sub.add_parser("unlink", help="remove the link between two incidents")
    drop.add_argument("incident")
    drop.add_argument("other")
    drop.set_defaults(handler=cmd_unlink)

    merge = sub.add_parser("merge", help="fold one incident into another (preview by default)")
    merge.add_argument("keep", help="the incident that survives")
    merge.add_argument("merge", help="the incident to merge away")
    merge.add_argument("--reason")
    merge.add_argument("--confirm", action="store_true", help="actually do it")
    merge.set_defaults(handler=cmd_merge)

    viewers = sub.add_parser("viewers", help="who else is viewing an incident")
    viewers.add_argument("incident")
    viewers.set_defaults(handler=cmd_viewers)

    watch = sub.add_parser("watch", help="follow an incident without owning it")
    watch.add_argument("incident")
    watch.add_argument("--stop", action="store_true", help="stop watching")
    watch.set_defaults(handler=cmd_watch)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        client = connect(args)
        return int(args.handler(client, args))
    except ApiError as exc:
        print("%serror %s%s %s" % (RED, exc.status, RESET, exc.detail), file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
