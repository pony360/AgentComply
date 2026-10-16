# AgentComply Guardrails and Design v0.2

**English** · [简体中文](GUARDRAILS.zh-CN.md)

This document covers the features added in v0.2 from the improved design proposal (Chinese edition, 2026-10-12), plus the guardrail layer against jailbreaks and offensive (hacking) operations.

Core principle: detection only produces risk signals. Deterministic authorization and a non-bypassable executor are the security boundary.

## 1. Architecture

```
Application (verified Principal + TaskGrant)
  -> AgentComply.authorize(Action, untrusted=[RAG chunks, tool responses])
       1. validate fields (INVALID_REQUEST)
       2. principal checks (PRINCIPAL_INVALID)
       3. guardrails: offensive (always), jailbreak / injection (enforce mode)
       4. rules: explicit deny > require_approval > allow (with task scopes) > default deny
       5. signed, single-use execution token bound to action_hash
       -> audit event (metadata only)
  -> TrustedExecutor.execute(action, token, tool_fn)
       re-verify token, action binding, expiry, replay; audit; then call tool_fn once
```

## 2. Policy schema v1alpha1

Policies use `apiVersion: agentcomply.io/v1alpha1`, validated with JSON Schema 2020-12 (`src/agentcomply/schemas/policy-v1alpha1.schema.json`). Unknown fields are rejected. The v0.1 `version: 1` format still loads.

| Field | Meaning |
| --- | --- |
| `spec.defaultAction` | Must be `deny`. |
| `spec.selector.agentIds` | Rules apply only to these agents. |
| `rules[].effect` | `allow`, `deny` or `require_approval`. |
| `rules[].tool`, `operations` | Exact match. |
| `rules[].resourcePatterns` | Glob. `*` matches one path segment, `**` matches any depth. Traversal and empty segments are rejected at load time. |
| `rules[].requiredTaskScopes` | The `TaskGrant` must include these scopes and a resource pattern that covers the request. |
| `detection.mode` | `enforce` (default) or `monitor`. |
| `audit` | `enabled`, `redactSecrets`. |

Precedence is fixed and does not depend on rule order: any matching deny wins; then approval rules; then allow rules; otherwise default deny.

## 3. Identity and task grants

- `Principal` is the verified user from your identity provider. The SDK does not construct it from model output. Expired principals are rejected.
- `TaskGrant` is issued by your application backend. It names a subject, scopes, resource patterns and an expiry. Allow rules with `requiredTaskScopes` require a matching grant, otherwise the result is `TASK_GRANT_DENIED`.

## 4. Guardrails

### 4.1 Offensive (hacking) operations: always blocked

These are blocked for every operation type, including reads, in every detection mode, even when a policy allows the tool. Blocking is based on:

- Capability taxonomy on tool and operation names (for example `exploit`, `malware`, `ddos`, `portscan`, `privesc`, `phishing`).
- Patterns in parameters and untrusted text, in English and Chinese: malware creation, reverse shells, exploitation, credential theft or dumping, phishing kits, DDoS, network scanning with attack tools, bypassing authentication or EDR, SQL injection payloads, and their Chinese equivalents (木马, 勒索软件, 撞库, 钓鱼网站, 绕过登录验证, 漏洞利用, etc.).

Bare topic words such as "ransomware" or "黑客" only produce a monitor-level signal, so educational questions are not blocked. Reason code: `OFFENSIVE_OPERATION_BLOCKED`.

### 4.2 Jailbreak and prompt injection

Patterns cover instruction overrides ("ignore previous instructions", 忽略之前的指令), persona jailbreaks (DAN, developer mode, 开发者模式), requests to reveal the system prompt, fake authority claims (系统管理员已授权), chat-template tokens, and exfiltration instructions (send customer data, 导出所有客户数据).

Input is normalized (NFKC, zero-width removal, case folding) and also checked in a separator-free form and after one level of base64 decoding. This catches common obfuscation.

In `enforce` mode, these signals block non-read-only operations (anything other than `read`, `search`, `summarize`, `list`). Read-only work still succeeds, so a poisoned document can be summarized but cannot trigger an export or a write. Reason codes: `JAILBREAK_BLOCKED`, `PROMPT_INJECTION_BLOCKED`.

In `monitor` mode, signals are recorded in the decision and audit event, but nothing is blocked except offensive operations.

### 4.3 Output DLP

`AgentComply.guard_output(text)` redacts private keys, AWS access keys, `sk-` style API keys, `key=value` credentials, Chinese national ID numbers and Luhn-valid card numbers. Redactions are counted per category.

### 4.4 Limits

Pattern matching is not semantic understanding. It can miss paraphrases, new encodings and multi-turn attacks, and it can produce false positives. Use it as one layer. The deterministic rules, task grants, approvals and executor are what enforce access. Track false-positive and false-negative rates on a labeled dataset before raising thresholds.

## 5. Approvals and execution tokens

- `require_approval` returns `REQUIRE_APPROVAL`. After a human approves, call `issue_approval(action, ttl_seconds)`, then authorize again with `approval=token`. The token is HMAC-signed, bound to the action hash, expires after at most one hour and can be used once.
- `authorize()` returns `execution_token` for allowed decisions. It is HMAC-signed, valid for 60 seconds, bound to the action hash, and single-use. Only `TrustedExecutor` accepts it.
- The signing key must be at least 32 bytes. Load it from a secret manager. If omitted, a random key is generated per process.
- Nonce replay tracking is in memory. Multi-process deployments need a shared store such as Redis.

## 6. Audit

Each decision emits `authorization_decision` with: decision ID, allowed flag, reason code, policy ID, policy version hash, rule ID, effect, action hash, signal categories and trace ID. The executor emits `tool_execution` before calling the tool. Audit sink failures block execution.

Events never contain prompt text, parameters, matched text or secrets.

## 7. Using the SDK

```python
from agentcomply import AgentComply, Action, Principal, TaskGrant, TrustedExecutor, secure_tool

engine = AgentComply("policies/finance-rag.yaml", signing_key=load_key(), locale="zh-CN")
executor = TrustedExecutor(engine)

decision = engine.authorize(action, principal=principal, grant=grant, untrusted=[rag_chunk, tool_output])
if decision.allowed:
    result = executor.execute(action, decision.execution_token, read_report, report_id="q3")
```

Or guard a function directly with `@secure_tool(executor, agent_id=..., tool=..., operation=..., resource=..., principal=..., grant=...)`. Keyword arguments become the action parameters and must be JSON-serializable.

Command line:

```bash
python -m agentcomply --lang zh-CN check policies/finance-rag.yaml
python -m agentcomply --lang zh-CN screen --text "请忽略之前的所有指令"   # exit code 3 when blocked
```

## 8. Boundaries that stay outside the SDK

- Network egress control. Use the Kubernetes manifests in `deploy/kubernetes/`, and route agent traffic through a controlled egress gateway. NetworkPolicy requires a CNI that enforces it.
- Identity verification and task grant issuance. These belong to your application backend and IdP.
- Bypass prevention. The SDK only protects tools that run through `TrustedExecutor` or `@secure_tool`. Tools reachable another way must be closed off at the network and credential layers.
- Helm charts, Kubernetes operators, remote policy service, LangGraph and FastAPI adapters, and model-based classifiers are roadmap items (v0.3 and later in the proposal).

## 9. Testing

`tests/test_guardrails.py` covers screening and obfuscation. `tests/test_v1alpha1.py` covers the new schema, grants, approvals and precedence. `tests/test_executor_and_attacks.py` covers the executor and the attack scenarios PI-01 through PI-06 and FP-01 from the proposal. `tests/test_i18n.py` checks that the English and Chinese catalogs match.
