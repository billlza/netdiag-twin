#!/usr/bin/env python3
"""Guard the top-level CLI pilot wiring while cli/main.rs is being split."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "crates" / "netdiag-cli" / "src" / "main.rs"
PILOT_COMMANDS = ROOT / "crates" / "netdiag-cli" / "src" / "commands" / "pilot.rs"


def main() -> int:
    main_rs = MAIN.read_text(encoding="utf-8")
    pilot_rs = PILOT_COMMANDS.read_text(encoding="utf-8")
    checks = {
        "Command::Pilot variant uses PilotCommand": re.search(
            r"Pilot\s*\{\s*#\[command\(subcommand\)\]\s*command:\s*commands::pilot::PilotCommand",
            main_rs,
            re.MULTILINE,
        ),
        "Command::Pilot dispatches to commands::pilot::run": re.search(
            r"Command::Pilot\s*\{\s*command\s*\}\s*=>\s*commands::pilot::run\(command\)\?",
            main_rs,
            re.MULTILINE,
        ),
        "pilot preflight command exists": re.search(r"\bPreflight\s*\{", pilot_rs),
        "pilot run command exists": re.search(r"\bRun\s*\{", pilot_rs),
        "pilot workflow command exists": re.search(r"\bWorkflow\s*\{", pilot_rs),
        "pilot model gate command exists": re.search(r"\bModelGate\s*\{", pilot_rs),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        print("pilot CLI wiring guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("pilot CLI wiring guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
