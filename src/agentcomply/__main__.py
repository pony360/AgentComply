"""Command-line tools.

    python -m agentcomply [--lang en|zh-CN] check <policy.yaml>
    python -m agentcomply [--lang en|zh-CN] screen --text "<text>"

``screen`` exits with status 3 when the text would be blocked for a write-type operation.
"""

from __future__ import annotations

import argparse
import sys

from .engine import AgentComply
from .guardrails import Guardrails, categories
from .i18n import SUPPORTED_LOCALES, normalize_locale, translate
from .policy import PolicyError

EXIT_BLOCKED = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentcomply", description="AgentComply policy and guardrail tools")
    parser.add_argument(
        "--lang",
        default=None,
        help=f"output language ({', '.join(SUPPORTED_LOCALES)}); default: $AGENTCOMPLY_LOCALE or en",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="validate a policy file")
    check.add_argument("policy", help="path to a YAML policy file")
    screen = sub.add_parser("screen", help="screen text for jailbreak, injection and offensive signals")
    screen.add_argument("--text", required=True, help="text to screen")
    args = parser.parse_args(argv)

    try:
        locale = normalize_locale(args.lang)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "check":
        try:
            engine = AgentComply(args.policy, locale=locale)
        except PolicyError as exc:
            print(f"{translate('cli.invalid', locale)}: {exc}", file=sys.stderr)
            return 1
        print(f"{translate('cli.valid', locale)}: {engine.policy_id} ({engine.api_version})")
        return 0

    guard = Guardrails(mode="enforce")
    signals = guard.screen(args.text, "cli")
    reason = guard.blocking_reason(signals, operation="write")
    cats = ", ".join(categories(signals)) or "-"
    print(f"{translate('cli.screen_signals', locale)}: {cats}")
    if reason is None:
        print(translate("cli.screen_clear", locale))
        return 0
    print(f"{translate('cli.screen_blocked', locale)}: {translate(f'reason.{reason}', locale, rule_id='')}")
    return EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
