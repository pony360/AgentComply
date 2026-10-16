"""Bilingual (English / Simplified Chinese) message catalog.

Machine-readable values (reason codes, audit event fields, rule effects,
policy keys) are always English and never translated. Only human-facing text
such as exception messages, explanations and CLI output is localized.
"""

from __future__ import annotations

import os

DEFAULT_LOCALE = "en"
LOCALE_ENV_VAR = "AGENTCOMPLY_LOCALE"
SUPPORTED_LOCALES = ("en", "zh-CN")

_ALIASES = {
    "en": "en",
    "en-us": "en",
    "en-gb": "en",
    "english": "en",
    "zh": "zh-CN",
    "zh-cn": "zh-CN",
    "zh-hans": "zh-CN",
    "zh-hans-cn": "zh-CN",
    "chinese": "zh-CN",
}

_MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # Policy loading / validation
        "policy.file_not_found": "policy file not found: {path}",
        "policy.yaml_error": "policy file is not valid YAML: {error}",
        "policy.not_a_mapping": "policy must be a mapping at the top level",
        "policy.unknown_field": "unknown top-level field: {field}",
        "policy.missing_field": "missing required field: {field}",
        "policy.invalid_version": "version must be the integer 1",
        "policy.invalid_default": "default must be the string 'deny'",
        "policy.invalid_policy_id": "policy_id must match {pattern}",
        "policy.rules_not_a_list": "rules must be a list",
        "policy.rule_not_a_mapping": "rule #{index} must be a mapping",
        "policy.rule_unknown_field": "rule {rule_id!r} has unknown field: {field}",
        "policy.rule_missing_field": "rule {rule_id!r} is missing field: {field}",
        "policy.invalid_rule_id": "rule id {rule_id!r} must match {pattern}",
        "policy.duplicate_rule_id": "duplicate rule id: {rule_id!r}",
        "policy.invalid_effect": "rule {rule_id!r} effect must be one of: {effects}",
        "policy.invalid_selector": (
            "rule {rule_id!r} selector {field!r} must be a non-empty list of non-empty strings"
        ),
        "policy.wildcard_not_allowed": (
            "rule {rule_id!r} selector {field!r} does not allow wildcards in version 1; "
            "use apiVersion agentcomply.io/v1alpha1"
        ),
        "policy.invalid_resource_pattern": "rule {rule_id!r} has an unsafe resource pattern: {pattern!r}",
        "policy.schema_error": "policy schema violation at {path}: {message}",
        # Request / approval validation
        "request.invalid_field": "invalid request field {field!r}: must match {pattern}",
        "request.not_a_request": "request must be an AuthorizationRequest or Action",
        "request.invalid_action": "action has invalid fields; cannot issue an approval",
        "approval.ttl_out_of_range": "approval ttl must be between 1 and 3600 seconds",
        # Decision explanations (keyed by reason code)
        "reason.EXPLICIT_DENY": "Denied: rule '{rule_id}' explicitly denies this action.",
        "reason.RULE_ALLOW": "Allowed: rule '{rule_id}' permits this action.",
        "reason.DEFAULT_DENY": "Denied: no rule matched, so the default deny applies.",
        "reason.INVALID_REQUEST": "Denied: the request is malformed and was rejected.",
        "reason.PRINCIPAL_INVALID": "Denied: the principal is missing, expired or invalid.",
        "reason.TASK_GRANT_DENIED": "Denied: rule '{rule_id}' requires a valid task grant with the required scopes.",
        "reason.REQUIRE_APPROVAL": "Pending: rule '{rule_id}' requires human approval before this action.",
        "reason.APPROVED": "Allowed: rule '{rule_id}' permits this action with a valid approval.",
        "reason.OFFENSIVE_OPERATION_BLOCKED": (
            "Blocked: this request involves offensive security (hacking) operations, which are never permitted."
        ),
        "reason.JAILBREAK_BLOCKED": "Blocked: a jailbreak attempt was detected in the input.",
        "reason.PROMPT_INJECTION_BLOCKED": "Blocked: a prompt-injection attempt was detected in untrusted content.",
        # Runtime errors
        "denied.execution": "action denied ({reason_code}); the tool was not executed",
        "denied.audit_failed": "audit sink failed; the tool was not executed",
        "denied.token_invalid": (
            "execution token is missing, invalid, expired or bound to a different action; "
            "the tool was not executed"
        ),
        "denied.token_replayed": "execution token was already used; the tool was not executed",
        "execute.async_not_supported": (
            "execute() only supports synchronous callables; use a sync wrapper for async tools"
        ),
        # CLI
        "cli.valid": "policy is valid",
        "cli.invalid": "policy is invalid",
        "cli.screen_signals": "signal categories",
        "cli.screen_clear": "no blocking signal for a write operation",
        "cli.screen_blocked": "would be blocked",
    },
    "zh-CN": {
        # 策略加载 / 校验
        "policy.file_not_found": "未找到策略文件：{path}",
        "policy.yaml_error": "策略文件不是合法的 YAML：{error}",
        "policy.not_a_mapping": "策略顶层必须是映射（mapping）",
        "policy.unknown_field": "顶层存在未知字段：{field}",
        "policy.missing_field": "缺少必填字段：{field}",
        "policy.invalid_version": "version 必须为整数 1",
        "policy.invalid_default": "default 必须为字符串 'deny'",
        "policy.invalid_policy_id": "policy_id 必须匹配 {pattern}",
        "policy.rules_not_a_list": "rules 必须是列表",
        "policy.rule_not_a_mapping": "第 {index} 条规则必须是映射",
        "policy.rule_unknown_field": "规则 {rule_id!r} 存在未知字段：{field}",
        "policy.rule_missing_field": "规则 {rule_id!r} 缺少字段：{field}",
        "policy.invalid_rule_id": "规则 ID {rule_id!r} 必须匹配 {pattern}",
        "policy.duplicate_rule_id": "规则 ID 重复：{rule_id!r}",
        "policy.invalid_effect": "规则 {rule_id!r} 的 effect 必须是以下之一：{effects}",
        "policy.invalid_selector": "规则 {rule_id!r} 的选择器 {field!r} 必须是由非空字符串组成的非空列表",
        "policy.wildcard_not_allowed": (
            "规则 {rule_id!r} 的选择器 {field!r} 在版本 1 中不支持通配符；"
            "请使用 apiVersion agentcomply.io/v1alpha1"
        ),
        "policy.invalid_resource_pattern": "规则 {rule_id!r} 的资源模式不安全：{pattern!r}",
        "policy.schema_error": "策略 Schema 校验失败，位置 {path}：{message}",
        # 请求 / 审批校验
        "request.invalid_field": "请求字段 {field!r} 不合法：必须匹配 {pattern}",
        "request.not_a_request": "请求必须是 AuthorizationRequest 或 Action 类型",
        "request.invalid_action": "操作存在非法字段，无法签发审批",
        "approval.ttl_out_of_range": "审批有效期必须在 1 到 3600 秒之间",
        # 决策解释（按原因码）
        "reason.EXPLICIT_DENY": "拒绝：规则 '{rule_id}' 明确禁止该操作。",
        "reason.RULE_ALLOW": "允许：规则 '{rule_id}' 允许该操作。",
        "reason.DEFAULT_DENY": "拒绝：没有任何规则匹配，适用默认拒绝策略。",
        "reason.INVALID_REQUEST": "拒绝：请求格式不合法，已被拒绝。",
        "reason.PRINCIPAL_INVALID": "拒绝：主体缺失、已过期或不合法。",
        "reason.TASK_GRANT_DENIED": "拒绝：规则 '{rule_id}' 需要具备所需权限范围的有效任务授权。",
        "reason.REQUIRE_APPROVAL": "待审批：规则 '{rule_id}' 要求人工审批后方可执行该操作。",
        "reason.APPROVED": "允许：规则 '{rule_id}' 在有效审批下允许该操作。",
        "reason.OFFENSIVE_OPERATION_BLOCKED": "已阻止：该请求涉及黑客或攻击性安全操作，任何情况下均不允许。",
        "reason.JAILBREAK_BLOCKED": "已阻止：输入中检测到越狱尝试。",
        "reason.PROMPT_INJECTION_BLOCKED": "已阻止：不可信内容中检测到提示词注入尝试。",
        # 运行时错误
        "denied.execution": "操作被拒绝（{reason_code}）；工具未执行",
        "denied.audit_failed": "审计 sink 失败；工具未执行",
        "denied.token_invalid": "执行令牌缺失、无效、已过期或与其他操作绑定；工具未执行",
        "denied.token_replayed": "执行令牌已被使用；工具未执行",
        "execute.async_not_supported": "execute() 仅支持同步函数；异步工具请使用同步包装",
        # 命令行
        "cli.valid": "策略校验通过",
        "cli.invalid": "策略校验失败",
        "cli.screen_signals": "命中的信号类别",
        "cli.screen_clear": "写入类操作未命中阻断信号",
        "cli.screen_blocked": "将被阻止",
    },
}


def normalize_locale(locale: str | None) -> str:
    """Return a canonical locale code ('en' or 'zh-CN').

    ``None`` or an empty string resolves to the ``AGENTCOMPLY_LOCALE``
    environment variable, falling back to English.
    """
    if locale is None or str(locale).strip() == "":
        locale = os.environ.get(LOCALE_ENV_VAR, "").strip() or DEFAULT_LOCALE
    key = str(locale).strip().replace("_", "-").lower()
    canonical = _ALIASES.get(key)
    if canonical is None:
        raise ValueError(
            f"unsupported locale {locale!r}; supported: {', '.join(SUPPORTED_LOCALES)} "
            f"(不支持的语言；可选：en、zh-CN)"
        )
    return canonical


def translate(key: str, locale: str = DEFAULT_LOCALE, **kwargs: object) -> str:
    """Look up ``key`` for ``locale`` and format it. Falls back to English."""
    catalog = _MESSAGES.get(locale, _MESSAGES[DEFAULT_LOCALE])
    template = catalog.get(key) or _MESSAGES[DEFAULT_LOCALE][key]
    return template.format(**kwargs)


def catalog_keys(locale: str) -> frozenset[str]:
    """Keys defined for ``locale``. Used by tests to check bilingual parity."""
    return frozenset(_MESSAGES[locale])
