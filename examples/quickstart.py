"""Quickstart / 快速开始.

Run / 运行:
    python examples/quickstart.py            # English (default)
    python examples/quickstart.py --lang zh-CN
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentcomply import AgentComply, AuthorizationDenied, AuthorizationRequest
from agentcomply.i18n import SUPPORTED_LOCALES, normalize_locale

POLICY = Path(__file__).resolve().parent.parent / "policies" / "customer-support.yaml"

TEXT = {
    "en": {
        "title": "AgentComply quickstart: customer support agent",
        "read": "Read orders",
        "export": "Export customers",
        "result": "Tool result",
        "blocked": "Blocked",
        "executed": "Executed",
        "lines": "rows returned",
    },
    "zh-CN": {
        "title": "AgentComply 快速开始：客服 Agent",
        "read": "读取订单",
        "export": "批量导出客户",
        "result": "工具结果",
        "blocked": "已阻止",
        "executed": "已执行",
        "lines": "条记录",
    },
}


def read_orders() -> list[str]:
    return ["order-1001", "order-1002"]


def export_customers() -> list[str]:
    return ["customer-1", "customer-2", "customer-3"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lang", default=None, help=f"one of: {', '.join(SUPPORTED_LOCALES)}")
    args = parser.parse_args()
    locale = normalize_locale(args.lang)
    text = TEXT[locale]

    events: list[dict] = []
    security = AgentComply(POLICY, audit_sink=events.append, locale=locale)
    print(f"== {text['title']} ==")

    read_req = AuthorizationRequest(
        user_id="alice", agent_id="support-agent",
        tool="database.read", resource="orders", action="read",
    )
    export_req = AuthorizationRequest(
        user_id="alice", agent_id="support-agent",
        tool="database.export", resource="customers", action="export",
    )

    for label, req, fn in (
        (text["read"], read_req, read_orders),
        (text["export"], export_req, export_customers),
    ):
        print(f"\n[{label}]")
        try:
            rows = security.execute(req, fn)
            print(f"  {text['executed']}: {len(rows)} {text['lines']} -> {rows}")
        except AuthorizationDenied as exc:
            print(f"  {text['blocked']}: {exc}")
            print(f"  {security.explain(exc.decision)}")

    print(f"\naudit events: {len(events)}")
    for event in events:
        print(f"  {event}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
