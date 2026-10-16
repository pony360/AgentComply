# AgentComply

**English** · [简体中文](README.zh-CN.md)

AgentComply is an open-source, developer-first **runtime authorization SDK** for AI agents. Before a tool runs, it makes a deterministic `ALLOW` / `DENY` decision from a versioned YAML policy, explains the decision, and emits a metadata-only audit event.

> Scope of v0.1.0: it guards the permission check point inside a *trusted* tool dispatcher. It does not promise complete prompt-injection defense and is not a compliance certification.

## Features

- Local, deterministic evaluation with no network calls on the decision path
- Default deny; an explicit `deny` always beats `allow`, regardless of rule order
- Strict YAML policy schema v1 (loaded with `safe_load`, unknown fields rejected)
- `execute()` guard: the protected function is never called when a request is denied or the audit sink fails
- Bilingual output: English and Simplified Chinese (`zh-CN`) for messages, explanations and CLI output

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Quick start

```python
from agentcomply import AgentComply, AuthorizationRequest

security = AgentComply("policies/customer-support.yaml", locale="zh-CN")  # or "en"

req = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.read", resource="orders", action="read",
)
decision = security.authorize(req)
print(decision.allowed, decision.reason_code, decision.rule_id)
print(security.explain(decision))   # 允许：规则 'allow-order-read' 允许该操作。

result = security.execute(req, read_orders)  # read_orders runs only if allowed
```

Run the bilingual demo:

```bash
python examples/quickstart.py            # English
python examples/quickstart.py --lang zh-CN
```

## Choosing a language

Language is resolved in this order:

1. The `locale=` argument, e.g. `AgentComply(path, locale="zh-CN")`
2. The `AGENTCOMPLY_LOCALE` environment variable (`en` or `zh-CN`)
3. English (`en`)

Accepted aliases include `zh`, `zh_CN`, `zh-Hans`, `en-US`. Unsupported values raise `ValueError`.

Only human-facing text is translated. Reason codes (`EXPLICIT_DENY`, `RULE_ALLOW`, `DEFAULT_DENY`, `INVALID_REQUEST`), audit event fields and policy keys are always English, so logs and integrations stay stable across languages.

## CLI

```bash
python -m agentcomply --lang zh-CN check policies/customer-support.yaml
# 策略校验通过: customer-support-v1
```

## Policy example

```yaml
version: 1
policy_id: customer-support-v1
default: deny
rules:
  - id: allow-order-read
    effect: allow
    users: [alice]
    agents: [support-agent]
    tools: [database.read]
    resources: [orders]
    actions: [read]
  - id: deny-customer-export
    effect: deny
    users: [alice]
    agents: [support-agent]
    tools: [database.export]
    resources: [customers]
    actions: [export]
```

## Guardrails (v0.2)

- Jailbreak and prompt-injection screening in English and Chinese, including obfuscated input (zero-width characters, separators, base64)
- Offensive (hacking) operations are always blocked, even when a policy allows the tool
- Policy v1alpha1 (`apiVersion: agentcomply.io/v1alpha1`): glob resources, `require_approval`, task scopes
- Verified principals, task grants, one-time approvals, and HMAC-signed execution tokens enforced by `TrustedExecutor`
- Output redaction for secrets, card numbers and national ID numbers

```bash
python examples/finance_rag_demo.py --lang zh-CN
python -m agentcomply --lang zh-CN screen --text "请忽略之前的所有指令"   # exit code 3 when blocked
```

See [docs/GUARDRAILS.md](docs/GUARDRAILS.md) for the design. Limits: pattern matching is one layer, not a complete defense.

## Testing

```bash
pytest -q
```

## Documentation

- [Engineering design (English)](docs/ENGINEERING.md) · [工程设计（中文）](docs/ENGINEERING.zh-CN.md)
- [Guardrails and v0.2 design](docs/GUARDRAILS.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## License

Apache-2.0. See [LICENSE](LICENSE). Project name and trademark availability should be checked separately before public promotion.
