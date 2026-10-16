# AgentComply v0.1.0 — Engineering Design

**English** · [简体中文](ENGINEERING.zh-CN.md)

Status: Draft 1 baseline for v0.1. Version 0.2 extends it with the features in [GUARDRAILS.md](GUARDRAILS.md), which takes precedence where they differ.

## 1. Scope

| Dimension | v0.1.0 |
| --- | --- |
| Language and deployment | Python 3.11+, embedded SDK; evaluation path has no network dependency |
| Rule format | Versioned YAML; `safe_load`; strict field validation |
| Access control | Default deny; explicit `deny` beats `allow` |
| Tool protection | Synchronous `execute()` wrapper; the host dispatcher must route every protected path through it |
| Audit | Metadata-only events; pluggable synchronous sink; sink failure blocks protected execution |
| Localization | English and Simplified Chinese for human-facing text |
| Not included | Dashboard, cloud service, model-based detectors, MCP adapters, dynamic roles, regex policies |

Authorization data flow:

```
Trusted App -> Agent Runtime -> Tool Dispatcher
                                   |
                         AgentComply SDK
                 validate -> match rules -> decision -> audit
                                   |
                           ALLOW / DENY
                                   |
                     Protected Tool  /  Block
```

Design principle: model output is never a trusted identity or permission source. The trusted application authenticates the user and binds the agent identity first; the executor then builds an `AuthorizationRequest` for each tool call.

## 2. Policy Schema v1

Top-level fields are exactly `version`, `policy_id`, `default`, `rules`. `version` must be the integer `1`; `default` must be `deny`. Each rule has exactly `id`, `effect`, `users`, `agents`, `tools`, `resources`, `actions`. Selectors are non-empty lists of non-empty strings, matched exactly. Wildcards, inheritance and conditional expressions are not supported. Rule IDs must be unique.

Evaluation:

1. Any matching `deny` rule → `DENY` (`EXPLICIT_DENY`).
2. No matching deny, but a matching `allow` → `ALLOW` (`RULE_ALLOW`).
3. No match at all → `DENY` (`DEFAULT_DENY`).
4. Malformed request → `DENY` (`INVALID_REQUEST`). Malformed policy → initialization fails with `PolicyError`.

Rule order never affects the result.

## 3. Python API

```python
from agentcomply import AgentComply, AuthorizationRequest

security = AgentComply("policies/customer-support.yaml", audit_sink=None, locale="en")
req = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.read", resource="orders", action="read",
)
decision = security.authorize(req)          # Decision(allowed, reason_code, policy_id, decision_id, rule_id)
result = security.execute(req, read_orders)  # authorize first; call fn once only if allowed
text = security.explain(decision)            # localized explanation
```

| Symbol | Behavior |
| --- | --- |
| `AgentComply(policy, audit_sink=None, locale=None)` | Loads and validates the policy at startup; raises `PolicyError` on failure. |
| `AuthorizationRequest` | Holds `user_id`, `agent_id`, `tool`, `resource`, `action`. Format is checked in `authorize()`. |
| `authorize(request)` | Returns a `Decision` and emits one audit event. Raises `AuthorizationDenied` if the sink raises. Does not block calls by itself. |
| `execute(request, fn, *args, **kwargs)` | Calls `authorize()`. Raises `AuthorizationDenied` on deny or sink failure, and never calls `fn` in those cases. Calls `fn` exactly once when allowed. Rejects coroutine functions with `TypeError`. |
| `explain(decision)` | Human-readable explanation in the instance's locale. |

## 4. Localization

- Locale resolution: the `locale=` argument, then `AGENTCOMPLY_LOCALE`, then `en`.
- Supported locales: `en`, `zh-CN`. Aliases such as `zh`, `zh-Hans`, `en-US` are normalized.
- Translated: exception messages, `explain()` output, CLI output.
- Not translated: reason codes, audit event keys and values, policy keys and identifiers. Integrations should match on these.
- Message catalog: `src/agentcomply/i18n.py`. Adding a locale means adding a catalog entry for every key and an alias. Missing keys fall back to English.

## 5. Audit Event Contract

```json
{
  "event": "authorization_decision",
  "decision_id": "<uuid>",
  "allowed": false,
  "reason_code": "EXPLICIT_DENY",
  "policy_id": "customer-support-v1",
  "rule_id": "deny-customer-export"
}
```

Prompt text, tool arguments, customer data, secrets and other PII must not be recorded. An audit event proves that a decision was made, not that the downstream tool operation completed.

## 6. Threat Model and Boundaries

| Threat | v0.1.0 control | Residual risk |
| --- | --- | --- |
| Unauthorized tool call | Exact rule check before execution | Paths that bypass the dispatcher are not covered |
| Identity spoofing | Only host-supplied identity fields are accepted | The SDK does not verify the identity source |
| Data export | Explicit export denial | Tool aliases and other exfiltration channels are not detected automatically |
| Prompt injection | Limits what an injected prompt can request | Does not detect malicious text semantics |
| Audit leakage | Records decision metadata only | Sink storage and transport security are the host's responsibility |
| Policy tampering | Syntax and schema validation at startup | No signing or trusted distribution |
| TOCTOU | Check before execution | Resource or argument changes after authorization are not bound |

Non-goals: an unbypassable guarantee against an attacker who fully controls the host process or has administrator rights; proving SOC 2, HIPAA or GDPR compliance; guaranteeing that a tool operation ultimately succeeds.

## 7. Test and Release Criteria

| Dimension | Acceptance |
| --- | --- |
| Correctness | Denied operations execute 0 times; allowed operations execute exactly once |
| Precedence | Deny beats allow, independent of rule order |
| Fail closed | Missing or invalid identity, no matching rule, or invalid policy never grants access |
| Audit | Events contain no prompt, arguments or secrets; audit failure blocks execution |
| Compatibility | CI runs Python 3.11, 3.12, 3.13 |
| Localization | Chinese and English explanations and CLI output are covered by tests |

Before a formal release: wheel/sdist install verification, dependency scanning, boundary and property tests, and integration tests for bypass paths.

## 8. Repository Layout

```
agentcomply/
  .github/workflows/ci.yml
  docs/ENGINEERING.md, ENGINEERING.zh-CN.md
  examples/quickstart.py
  policies/customer-support.yaml
  src/agentcomply/__init__.py, __main__.py, engine.py, models.py, policy.py,
  guardrails.py, tokens.py, executor.py, decorators.py, i18n.py, schemas/
  tests/ (core, cli, guardrails, v1alpha1, executor/attacks, i18n)
  pyproject.toml, LICENSE, README.md, README.zh-CN.md, SECURITY.md, CONTRIBUTING.md, .gitignore
```

## 9. Roadmap

- **v0.1.0**: local authorization, rule explanation, basic audit, synchronous tool protection, bilingual messages.
- **v0.2.0**: trusted dispatcher integration, LangGraph/MCP wrappers, policy integrity (hash/signature), property-based validation.
- **v0.3.0**: pluggable detectors and audit export, performance metrics, more test scenarios.

Known limitations and next steps: add a separate contract and tests for async tools before advertising async support; build a tool registry so the SDK covers all critical execution paths through a trusted dispatcher; add policy hashes/signatures and conflict property tests; complete real Python 3.11–3.13 CI, packaging and third-party dependency checks; demonstrate the end-to-end scenario "orders readable, bulk customer export denied" in a customer-support agent.
