# AgentComply 护栏与设计 v0.2

[English](GUARDRAILS.md) · **简体中文**

本文档说明 v0.2 中从改进设计提案（中文版，2026-10-12）加入的功能，以及针对越狱和攻击性（黑客）操作的护栏层。

核心原则：检测只产生风险信号。确定性授权与不可绕过的执行器才是安全边界。

## 1. 架构

```
应用（已验证的 Principal + TaskGrant）
  -> AgentComply.authorize(Action, untrusted=[RAG 片段, 工具响应])
       1. 校验字段（INVALID_REQUEST）
       2. 主体检查（PRINCIPAL_INVALID）
       3. 护栏：攻击性操作（始终生效）、越狱/注入（enforce 模式）
       4. 规则：显式 deny > require_approval > 带任务范围的 allow > 默认拒绝
       5. 与 action_hash 绑定的签名一次性执行令牌
       -> 审计事件（仅元数据）
  -> TrustedExecutor.execute(action, token, 工具函数)
       重新验证令牌、操作绑定、有效期、重放；审计；然后仅调用一次工具函数
```

## 2. 策略 Schema v1alpha1

策略使用 `apiVersion: agentcomply.io/v1alpha1`，由 JSON Schema 2020-12 校验（`src/agentcomply/schemas/policy-v1alpha1.schema.json`）。未知字段会被拒绝。v0.1 的 `version: 1` 格式仍然可以加载。

| 字段 | 含义 |
| --- | --- |
| `spec.defaultAction` | 必须为 `deny`。 |
| `spec.selector.agentIds` | 规则只适用于这些 Agent。 |
| `rules[].effect` | `allow`、`deny` 或 `require_approval`。 |
| `rules[].tool`、`operations` | 精确匹配。 |
| `rules[].resourcePatterns` | Glob 模式。`*` 匹配一个路径段，`**` 匹配任意深度。加载时即拒绝路径穿越和空段。 |
| `rules[].requiredTaskScopes` | `TaskGrant` 必须包含这些范围，且其资源模式覆盖本次请求。 |
| `detection.mode` | `enforce`（默认）或 `monitor`。 |
| `audit` | `enabled`、`redactSecrets`。 |

优先级固定，与规则排列顺序无关：任一匹配的 deny 生效；其次是审批规则；再次是 allow 规则；否则默认拒绝。

## 3. 身份与任务授权

- `Principal` 是身份提供方验证过的用户。SDK 不会从模型输出构造它。已过期的主体会被拒绝。
- `TaskGrant` 由应用后端签发，包含主体、范围、资源模式和过期时间。带有 `requiredTaskScopes` 的 allow 规则需要匹配的授权，否则返回 `TASK_GRANT_DENIED`。

## 4. 护栏

### 4.1 攻击性（黑客）操作：始终阻止

以下请求对所有操作类型（包括读取）、所有检测模式都会阻止，即使策略允许该工具也不例外。判断依据包括：

- 对工具名和操作名的能力分类（例如 `exploit`、`malware`、`ddos`、`portscan`、`privesc`、`phishing`）。
- 参数与不可信文本中的中英文模式：编写恶意软件、反弹 shell、漏洞利用、盗取或撞库凭证、钓鱼页面、DDoS、使用攻击工具扫描网络、绕过认证或 EDR、SQL 注入载荷，以及对应的中文表述（木马、勒索软件、撞库、钓鱼网站、绕过登录验证、漏洞利用等）。

“勒索软件”“黑客”等泛化主题词只会产生 monitor 级别的信号，因此科普类问题不会被误拦。原因码：`OFFENSIVE_OPERATION_BLOCKED`。

### 4.2 越狱与提示词注入

模式覆盖：覆盖指令（“ignore previous instructions”、“忽略之前的指令”）、角色越狱（DAN、开发者模式）、索取系统提示词、伪造授权（“系统管理员已授权”）、聊天模板标记，以及外传指令（“send customer data”、“导出所有客户数据”）。

输入会先做规范化（NFKC、去除零宽字符、大小写折叠），再分别检查去除分隔符后的形式，并对 base64 做一层解码。这样可以覆盖常见的混淆手段。

在 `enforce` 模式下，这些信号会阻止非只读操作（即除 `read`、`search`、`summarize`、`list` 之外的操作）。只读工作仍然可以完成，因此被投毒的文档可以被总结，但不能触发导出或写入。原因码：`JAILBREAK_BLOCKED`、`PROMPT_INJECTION_BLOCKED`。

在 `monitor` 模式下，信号只记录在决策和审计事件中，除攻击性操作外不阻止任何请求。

### 4.3 输出数据防泄露（DLP）

`AgentComply.guard_output(text)` 会脱敏私钥、AWS 访问密钥、`sk-` 形式的 API 密钥、`key=value` 形式的凭证、中国大陆身份证号，以及通过 Luhn 校验的银行卡号。脱敏结果按类别计数。

### 4.4 局限

模式匹配不是语义理解。它可能漏掉改写、新编码和多轮攻击，也可能产生误报。请把它当作其中一层使用。真正执行访问控制的是确定性规则、任务授权、审批和执行器。在提高阈值之前，应先在带标注的数据集上统计误报率和漏报率。

## 5. 审批与执行令牌

- `require_approval` 返回 `REQUIRE_APPROVAL`。人工批准后，调用 `issue_approval(action, ttl_seconds)` 签发审批令牌，然后带上 `approval=token` 重新授权。令牌经过 HMAC 签名，与操作哈希绑定，最长 1 小时有效，且只能使用一次。
- 允许的决策会在 `authorize()` 的结果中返回 `execution_token`。它经过 HMAC 签名，有效期 60 秒，与操作哈希绑定，且只能使用一次。只有 `TrustedExecutor` 接受该令牌。
- 签名密钥至少 32 字节，应从密钥管理服务加载。若未提供，则每个进程随机生成。
- 重放检测基于内存。多进程部署需要共享存储，例如 Redis。

## 6. 审计

每次决策输出 `authorization_decision` 事件，包含：决策 ID、是否允许、原因码、策略 ID、策略版本哈希、规则 ID、effect、操作哈希、信号类别和 trace ID。执行器在调用工具前输出 `tool_execution` 事件。审计 sink 失败会阻止执行。

事件中不包含 Prompt 原文、参数、命中的文本或任何密钥。

## 7. 使用方式

```python
from agentcomply import AgentComply, Action, Principal, TaskGrant, TrustedExecutor, secure_tool

engine = AgentComply("policies/finance-rag.yaml", signing_key=load_key(), locale="zh-CN")
executor = TrustedExecutor(engine)

decision = engine.authorize(action, principal=principal, grant=grant, untrusted=[rag_chunk, tool_output])
if decision.allowed:
    result = executor.execute(action, decision.execution_token, read_report, report_id="q3")
```

也可以用 `@secure_tool(executor, agent_id=..., tool=..., operation=..., resource=..., principal=..., grant=...)` 直接保护函数。关键字参数会成为操作参数，因此必须可 JSON 序列化。

命令行：

```bash
python -m agentcomply --lang zh-CN check policies/finance-rag.yaml
python -m agentcomply --lang zh-CN screen --text "请忽略之前的所有指令"   # 命中阻断时退出码为 3
```

## 8. 不在 SDK 范围内的边界

- 网络出站控制。请使用 `deploy/kubernetes/` 中的清单，并将 Agent 流量经过受控的出口网关。NetworkPolicy 需要支持它的 CNI。
- 身份验证与任务授权的签发。这些属于你的应用后端与身份提供方。
- 防绕过。SDK 只保护通过 `TrustedExecutor` 或 `@secure_tool` 运行的工具。若工具可以通过其他途径访问，必须在网络层和凭证层封堵。
- Helm Chart、Kubernetes Operator、远程策略服务、LangGraph 与 FastAPI 适配器、基于模型的分类器，都属于路线图项目（提案中的 v0.3 及以后）。

## 9. 测试

`tests/test_guardrails.py` 覆盖检测与混淆处理。`tests/test_v1alpha1.py` 覆盖新 Schema、任务授权、审批与优先级。`tests/test_executor_and_attacks.py` 覆盖执行器，以及提案中的攻击场景 PI-01 至 PI-06 与误报场景 FP-01。`tests/test_i18n.py` 检查中英文消息目录的键是否一致。
