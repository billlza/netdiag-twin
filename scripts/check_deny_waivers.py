#!/usr/bin/env python3
"""Ensure cargo-deny advisory ignores are explicit, owned, and time boxed."""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DENY_TOML = ROOT / "deny.toml"
WAIVERS_TOML = ROOT / "security" / "advisory-waivers.toml"
REQUIRED_FIELDS = ("owner", "expires", "rationale", "remediation")
EXACT_CRATE_SPEC = re.compile(r"^[A-Za-z0-9_.-]+@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?$")


def validate_duplicate_policy(deny: dict[str, object], failures: list[str]) -> None:
    bans = deny.get("bans", {})
    if not isinstance(bans, dict):
        failures.append("deny.toml is missing [bans] policy")
        return

    if bans.get("multiple-versions") != "deny":
        failures.append("[bans].multiple-versions must be deny so new duplicates fail")

    for entry in bans.get("skip-tree", []):
        failures.append(f"skip-tree is too broad for release policy: {entry!r}")

    for entry in bans.get("skip", []):
        if not isinstance(entry, dict):
            failures.append(f"duplicate skip must include crate and reason fields: {entry!r}")
            continue
        crate = str(entry.get("crate", "")).strip()
        reason = str(entry.get("reason", "")).strip()
        if not EXACT_CRATE_SPEC.fullmatch(crate):
            failures.append(f"duplicate skip must pin an exact crate version: {crate!r}")
        if len(reason) < 24:
            failures.append(f"duplicate skip needs an audit reason: {crate or entry!r}")


def main() -> int:
    deny = tomllib.loads(DENY_TOML.read_text(encoding="utf-8"))
    waivers = tomllib.loads(WAIVERS_TOML.read_text(encoding="utf-8")).get("waivers", {})
    ignored = set(deny.get("advisories", {}).get("ignore", []))
    failures: list[str] = []
    validate_duplicate_policy(deny, failures)

    for advisory in sorted(ignored):
        metadata = waivers.get(advisory)
        if not isinstance(metadata, dict):
            failures.append(f"{advisory} is ignored in deny.toml but has no waiver metadata")
            continue
        for field in REQUIRED_FIELDS:
            if not str(metadata.get(field, "")).strip():
                failures.append(f"{advisory} waiver is missing required field: {field}")
        expires = metadata.get("expires")
        if not isinstance(expires, dt.date):
            failures.append(f"{advisory} waiver expires must be an ISO date")
        elif expires < dt.date.today():
            failures.append(f"{advisory} waiver expired on {expires.isoformat()}")

    for advisory in sorted(set(waivers) - ignored):
        failures.append(f"{advisory} waiver metadata exists but deny.toml no longer ignores it")

    if failures:
        print("deny waiver guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    if ignored:
        print(f"deny waiver guard passed for {len(ignored)} advisory waiver(s)")
    else:
        print("deny waiver guard passed with no advisory waivers")
    print("deny duplicate policy guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
