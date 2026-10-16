from agentcomply import AgentComply
from agentcomply.i18n import catalog_keys, translate
from agentcomply.models import (
    REASON_APPROVED,
    REASON_DEFAULT_DENY,
    REASON_EXPLICIT_DENY,
    REASON_INJECTION_BLOCKED,
    REASON_INVALID_REQUEST,
    REASON_JAILBREAK_BLOCKED,
    REASON_OFFENSIVE_BLOCKED,
    REASON_PRINCIPAL_INVALID,
    REASON_REQUIRE_APPROVAL,
    REASON_RULE_ALLOW,
    REASON_TASK_GRANT_DENIED,
)

REASON_CODES = [
    REASON_EXPLICIT_DENY, REASON_RULE_ALLOW, REASON_DEFAULT_DENY, REASON_INVALID_REQUEST,
    REASON_PRINCIPAL_INVALID, REASON_TASK_GRANT_DENIED, REASON_REQUIRE_APPROVAL, REASON_APPROVED,
    REASON_OFFENSIVE_BLOCKED, REASON_JAILBREAK_BLOCKED, REASON_INJECTION_BLOCKED,
]


def test_english_and_chinese_catalogs_have_identical_keys():
    assert catalog_keys("en") == catalog_keys("zh-CN")


def test_every_reason_code_has_both_explanations():
    for code in REASON_CODES:
        key = f"reason.{code}"
        assert key in catalog_keys("en") and key in catalog_keys("zh-CN")
        assert translate(key, "en", rule_id="r") != translate(key, "zh-CN", rule_id="r")


def test_chinese_explanations_are_chinese():
    for code in REASON_CODES:
        text = translate(f"reason.{code}", "zh-CN", rule_id="r")
        assert any("一" <= ch <= "鿿" for ch in text), code


def test_blocked_reasons_explain_in_locale(clock=None):
    from agentcomply import Action, Principal

    engine = AgentComply({
        "version": 1, "policy_id": "p", "default": "deny", "rules": [],
    }, locale="zh-CN")
    d = engine.authorize(
        Action(agent_id="a", tool="security.exploit", operation="run", resource="hosts/web"),
        principal=Principal(subject="u"),
    )
    assert d.reason_code == REASON_OFFENSIVE_BLOCKED
    assert engine.explain(d).startswith("已阻止")
