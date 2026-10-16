import copy

import pytest

from agentcomply import (
    REASON_DEFAULT_DENY,
    REASON_EXPLICIT_DENY,
    REASON_INVALID_REQUEST,
    REASON_RULE_ALLOW,
    AgentComply,
    AuthorizationDenied,
    AuthorizationRequest,
    PolicyError,
)

READ = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.read", resource="orders", action="read",
)
EXPORT = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.export", resource="customers", action="export",
)


def base_policy(rules):
    return {"version": 1, "policy_id": "p1", "default": "deny", "rules": rules}


ALLOW_RULE = {
    "id": "allow-read", "effect": "allow", "users": ["alice"], "agents": ["a"],
    "tools": ["t"], "resources": ["r"], "actions": ["read"],
}
DENY_RULE = {
    "id": "deny-read", "effect": "deny", "users": ["alice"], "agents": ["a"],
    "tools": ["t"], "resources": ["r"], "actions": ["read"],
}
REQ = AuthorizationRequest(user_id="alice", agent_id="a", tool="t", resource="r", action="read")


@pytest.fixture
def engine_and_events(policy_path):
    events = []
    return AgentComply(policy_path, audit_sink=events.append), events


@pytest.fixture
def policy_path():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent / "policies" / "customer-support.yaml"


# ---------------------------------------------------------------- decisions

def test_allow_rule_permits_matching_request(engine_and_events):
    engine, _ = engine_and_events
    decision = engine.authorize(READ)
    assert decision.allowed is True
    assert decision.reason_code == REASON_RULE_ALLOW
    assert decision.rule_id == "allow-order-read"
    assert decision.policy_id == "customer-support-v1"


def test_export_is_explicitly_denied_by_policy(engine_and_events):
    engine, _ = engine_and_events
    decision = engine.authorize(EXPORT)
    assert decision.allowed is False
    assert decision.reason_code == REASON_EXPLICIT_DENY
    assert decision.rule_id == "deny-customer-export"


def test_unlisted_export_by_other_user_is_default_denied(engine_and_events):
    engine, _ = engine_and_events
    other = AuthorizationRequest(
        user_id="bob", agent_id="support-agent",
        tool="database.export", resource="customers", action="export",
    )
    decision = engine.authorize(other)
    assert decision.reason_code == REASON_DEFAULT_DENY


def test_deny_takes_precedence_over_allow_regardless_of_order():
    for rules in ([ALLOW_RULE, DENY_RULE], [DENY_RULE, ALLOW_RULE]):
        decision = AgentComply(base_policy(rules)).authorize(REQ)
        assert decision.allowed is False
        assert decision.reason_code == REASON_EXPLICIT_DENY
        assert decision.rule_id == "deny-read"


def test_unmatched_request_is_denied_by_default():
    other = AuthorizationRequest(user_id="bob", agent_id="a", tool="t", resource="r", action="read")
    decision = AgentComply(base_policy([ALLOW_RULE])).authorize(other)
    assert decision.allowed is False
    assert decision.reason_code == REASON_DEFAULT_DENY


def test_empty_rules_deny_everything():
    decision = AgentComply(base_policy([])).authorize(REQ)
    assert decision.allowed is False
    assert decision.reason_code == REASON_DEFAULT_DENY


def test_malformed_request_is_denied_as_invalid():
    bad = AuthorizationRequest(user_id="ali ce", agent_id="a", tool="t", resource="r", action="read")
    decision = AgentComply(base_policy([ALLOW_RULE])).authorize(bad)
    assert decision.allowed is False
    assert decision.reason_code == REASON_INVALID_REQUEST


def test_selectors_are_exact_match_no_wildcards():
    wildcard = AuthorizationRequest(user_id="alice", agent_id="a", tool="t", resource="r*", action="read")
    decision = AgentComply(base_policy([ALLOW_RULE])).authorize(wildcard)
    assert decision.allowed is False


def test_each_decision_has_unique_id(engine_and_events):
    engine, _ = engine_and_events
    assert engine.authorize(READ).decision_id != engine.authorize(READ).decision_id


# -------------------------------------------------------------- policy checks

@pytest.mark.parametrize(
    "mutate, message_fragment",
    [
        (lambda p: p.update(version=2), "version"),
        (lambda p: p.update(version=True), "version"),
        (lambda p: p.update(default="allow"), "default"),
        (lambda p: p.update(extra=1), "extra"),
        (lambda p: p.pop("policy_id"), "policy_id"),
        (lambda p: p.update(policy_id="bad id!"), "policy_id"),
        (lambda p: p.update(rules="nope"), "rules"),
        (lambda p: p["rules"][0].update(effect="maybe"), "effect"),
        (lambda p: p["rules"][0].update(tools=[]), "tools"),
        (lambda p: p["rules"][0].update(users=["ok", " "]), "users"),
        (lambda p: p["rules"][0].update(wildcard=True), "wildcard"),
        (lambda p: p["rules"][0].pop("actions"), "actions"),
        (lambda p: p["rules"].append(copy.deepcopy(p["rules"][0])), "duplicate"),
    ],
)
def test_invalid_policies_fail_closed(mutate, message_fragment):
    policy = base_policy([copy.deepcopy(ALLOW_RULE)])
    mutate(policy)
    with pytest.raises(PolicyError, match=message_fragment):
        AgentComply(policy)


def test_missing_policy_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        AgentComply(tmp_path / "nope.yaml")


def test_invalid_yaml_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: [1, 2\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        AgentComply(path)


# -------------------------------------------------------- execute / audit

def test_execute_calls_allowed_function_exactly_once(engine_and_events):
    engine, _ = engine_and_events
    calls = []
    result = engine.execute(READ, lambda: calls.append(1) or "rows")
    assert result == "rows"
    assert calls == [1]


def test_execute_never_calls_denied_function(engine_and_events):
    engine, _ = engine_and_events
    calls = []
    with pytest.raises(AuthorizationDenied) as info:
        engine.execute(EXPORT, lambda: calls.append(1))
    assert calls == []
    assert info.value.decision.reason_code == REASON_EXPLICIT_DENY


def test_execute_rejects_async_callables(engine_and_events):
    engine, _ = engine_and_events

    async def tool():
        return 1

    with pytest.raises(TypeError):
        engine.execute(READ, tool)


def test_failing_audit_sink_blocks_execution():
    def broken_sink(_event):
        raise OSError("disk full")

    engine = AgentComply(base_policy([ALLOW_RULE]), audit_sink=broken_sink)
    calls = []
    with pytest.raises(AuthorizationDenied):
        engine.execute(REQ, lambda: calls.append(1))
    assert calls == []
    with pytest.raises(AuthorizationDenied):
        engine.authorize(REQ)


def test_audit_event_contains_only_metadata(engine_and_events):
    engine, events = engine_and_events
    engine.authorize(READ)
    assert len(events) == 1
    event = events[0]
    assert {"event", "decision_id", "allowed", "reason_code", "policy_id", "rule_id"} <= set(event)
    assert "parameters" not in event and "prompt" not in str(event).lower()
    assert event["event"] == "authorization_decision"
    assert "orders" not in str(event)


def test_invalid_request_type_raises_type_error(engine_and_events):
    engine, _ = engine_and_events
    with pytest.raises(TypeError):
        engine.authorize({"user_id": "alice"})


# --------------------------------------------------------------- i18n

def test_default_locale_is_english(engine_and_events, monkeypatch):
    monkeypatch.delenv("AGENTCOMPLY_LOCALE", raising=False)
    engine, _ = engine_and_events
    assert engine.locale == "en"
    text = engine.explain(engine.authorize(EXPORT))
    assert text.startswith("Denied")


def test_chinese_explanations(policy_path):
    engine = AgentComply(policy_path, locale="zh-CN")
    assert engine.locale == "zh-CN"
    assert engine.explain(engine.authorize(READ)) == "允许：规则 'allow-order-read' 允许该操作。"
    assert engine.explain(engine.authorize(EXPORT)).startswith("拒绝")


def test_explicit_deny_explanation_mentions_rule(policy_path):
    engine = AgentComply(
        base_policy([ALLOW_RULE, DENY_RULE]), locale="zh-CN"
    )
    text = engine.explain(engine.authorize(REQ))
    assert "deny-read" in text and "明确禁止" in text


def test_invalid_request_explanation_in_chinese():
    engine = AgentComply(base_policy([]), locale="zh-CN")
    bad = AuthorizationRequest(user_id="", agent_id="a", tool="t", resource="r", action="read")
    assert "格式不合法" in engine.explain(engine.authorize(bad))


def test_policy_errors_are_localized_in_chinese():
    with pytest.raises(PolicyError, match="版本|version"):
        AgentComply(base_policy([]) | {"version": 9}, locale="zh-CN")
    with pytest.raises(PolicyError, match="未知字段"):
        AgentComply(base_policy([]) | {"junk": 1}, locale="zh-CN")


def test_execute_error_is_localized():
    engine = AgentComply(base_policy([]), locale="zh-CN")
    with pytest.raises(AuthorizationDenied, match="工具未执行"):
        engine.execute(REQ, lambda: None)


def test_locale_from_environment(monkeypatch, policy_path):
    monkeypatch.setenv("AGENTCOMPLY_LOCALE", "zh-CN")
    engine = AgentComply(policy_path)
    assert engine.locale == "zh-CN"


def test_explicit_locale_overrides_environment(monkeypatch, policy_path):
    monkeypatch.setenv("AGENTCOMPLY_LOCALE", "zh-CN")
    assert AgentComply(policy_path, locale="en").locale == "en"


@pytest.mark.parametrize(
    "raw, expected",
    [("en", "en"), ("EN-us", "en"), ("zh", "zh-CN"), ("zh_CN", "zh-CN"),
     ("zh-Hans", "zh-CN"), ("Chinese", "zh-CN")],
)
def test_locale_aliases(raw, expected):
    from agentcomply import normalize_locale

    assert normalize_locale(raw) == expected


def test_unsupported_locale_rejected(policy_path):
    with pytest.raises(ValueError):
        AgentComply(policy_path, locale="fr")
