# AgentComply v0.1.0 — 工程设计

[English](ENGINEERING.md) · **简体中文**

状态：v0.1 的 Draft 1 基线。v0.2 在此基础上扩展了 [GUARDRAILS.zh-CN.md](GUARDRAILS.zh-CN.md) 中的功能，两者不一致时以该文档为准。

## 1. 范围

| 维度 | v0.1.0 |
| --- | --- |
| 语言与部署 | Python 3.11+，嵌入式 SDK；评估路径无网络依赖 |
| 规则格式 | 版本化 YAML；`safe_load`；严格字段校验 |
| 访问控制 | 默认拒绝；显式 `deny` 优先于 `allow` |
| 工具保护 | 同步 `execute()` 包装器；宿主 Dispatcher 必须保证所有受保护路径都经过检查 |
| 审计 | 元数据级审计；可插拔同步 sink；审计失败阻止受保护执行 |
| 本地化 | 面向人的文本支持简体中文与英文 |
| 暂不包含 | Dashboard、云服务、模型检测器、MCP 适配、动态角色、正则策略 |

授权数据流：

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

设计原则：模型输出不是可信身份或权限来源。可信应用先完成用户认证和 Agent 身份绑定，执行器再为每次工具调用构建 `AuthorizationRequest`。

## 2. 策略 Schema v1

顶层字段只能是 `version`、`policy_id`、`default`、`rules`。`version` 必须为整数 `1`；`default` 必须为 `deny`。每条规则恰好包含 `id`、`effect`、`users`、`agents`、`tools`、`resources`、`actions`。选择器只能是由非空字符串组成的非空列表，且为精确匹配。不支持通配符、继承和条件表达式。规则 ID 不可重复。

求值语义：

1. 任意匹配的 `deny` 规则 → `DENY`（`EXPLICIT_DENY`）。
2. 无 deny，但存在匹配的 `allow` → `ALLOW`（`RULE_ALLOW`）。
3. 完全未命中 → `DENY`（`DEFAULT_DENY`）。
4. 非法请求 → `DENY`（`INVALID_REQUEST`）；非法策略 → 初始化失败，抛出 `PolicyError`。

规则排列顺序不影响结果。

## 3. Python API

```python
from agentcomply import AgentComply, AuthorizationRequest

security = AgentComply("policies/customer-support.yaml", audit_sink=None, locale="zh-CN")
req = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.read", resource="orders", action="read",
)
decision = security.authorize(req)          # Decision(allowed, reason_code, policy_id, decision_id, rule_id)
result = security.execute(req, read_orders)  # 先授权；仅在允许时调用一次 fn
text = security.explain(decision)            # 本地化解释
```

| 接口 | 行为 |
| --- | --- |
| `AgentComply(policy, audit_sink=None, locale=None)` | 启动时读取并验证策略；失败抛出 `PolicyError`。 |
| `AuthorizationRequest` | 包含 `user_id`、`agent_id`、`tool`、`resource`、`action`；格式在 `authorize()` 中校验。 |
| `authorize(request)` | 返回 `Decision` 并输出一条审计事件。若 sink 抛错则抛出 `AuthorizationDenied`。本身不阻止调用，需由调用方遵守 `decision.allowed`。 |
| `execute(request, fn, *args, **kwargs)` | 先调用 `authorize()`。拒绝或审计失败时抛出 `AuthorizationDenied`，且绝不调用 `fn`；允许时同步调用一次。协程函数会抛出 `TypeError`。 |
| `explain(decision)` | 以实例语言返回可读解释。 |

## 4. 本地化

- 语言解析顺序：参数 `locale=`，然后环境变量 `AGENTCOMPLY_LOCALE`，最后默认 `en`。
- 支持的语言：`en`、`zh-CN`。`zh`、`zh-Hans`、`en-US` 等别名会被规范化。
- 会翻译的内容：异常消息、`explain()` 输出、命令行输出。
- 不会翻译的内容：原因码、审计事件的键与值、策略关键字和标识符。集成方应以这些英文值进行匹配。
- 消息目录位于 `src/agentcomply/i18n.py`。新增语言需要为每个键补充翻译并注册别名；缺失的键回退到英文。

## 5. 审计事件契约

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

禁止记录 Prompt 原文、工具参数、客户资料、密钥或其他 PII。审计记录只能说明授权决策已发生，不代表下游工具操作已经完成。

## 6. 威胁模型与边界

| 威胁 | v0.1.0 控制 | 剩余风险 |
| --- | --- | --- |
| 未授权工具调用 | 工具执行前进行精确规则检查 | 未接入 Dispatcher 的路径可绕过 |
| 权限冒充 | 仅接受宿主传入的身份字段 | SDK 不验证真实认证来源 |
| 数据导出 | 拒绝明确标记为 export 的操作 | 工具别名和其他外传渠道无法自动检测 |
| Prompt Injection | 限制注入后可能请求的工具动作 | 不检测恶意文本的语义 |
| 审计泄露 | 只记录决策基础元数据 | Sink 的存储与传输安全由宿主负责 |
| 策略篡改 | 启动时进行语法及 Schema 校验 | 不支持签名、可信策略分发 |
| TOCTOU | 执行前检查 | 授权后资源或参数变化未被绑定 |

非目标：对已完全控制宿主进程或拥有管理员权限的攻击者提供不可绕过保证；证明 SOC 2、HIPAA 或 GDPR 合规；保证工具操作最终成功。

## 7. 测试标准与发布门槛

| 维度 | 验收标准 |
| --- | --- |
| 正确性 | 拒绝的操作执行 0 次；授权的操作恰好执行 1 次 |
| 求值优先级 | DENY 优先于 ALLOW，且不受规则顺序影响 |
| Fail Closed | 身份缺失或不合法、无匹配规则、策略校验失败均不得获得权限 |
| 审计 | 事件不含 Prompt、工具参数或 Secret；审计故障时不执行工具 |
| 兼容性 | CI 测试 Python 3.11、3.12、3.13 |
| 本地化 | 中英文解释与命令行输出均有测试覆盖 |

正式发布前：Wheel/sdist 安装验证、依赖扫描、边界/属性测试、绕过路径集成测试。

## 8. 仓库结构

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

## 9. 路线图

- **v0.1.0**：本地授权、规则解释、基础审计、同步工具执行保护、中英双语消息。
- **v0.2.0**：可信 Dispatcher 集成、LangGraph/MCP 包装、策略完整性（hash/签名）、属性验证。
- **v0.3.0**：插件化检测器与审计导出、性能指标、更多测试场景。

已知限制与后续步骤：在宣称支持异步之前，为异步工具场景增加单独的契约与测试；建立工具注册表，使 SDK 以受信任 Dispatcher 的方式覆盖所有关键执行路径；增加策略 hash/签名与冲突属性测试；完成真实的 Python 3.11–3.13 CI、打包及第三方依赖检查；以客服 Agent 场景演示“订单可读，客户批量导出被拒绝”的端到端行为。
