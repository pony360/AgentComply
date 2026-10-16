# AgentComply

[English](README.md) · **简体中文**

AgentComply 是面向 AI Agent 的开源、开发者优先的**运行时授权 SDK**。在工具执行前，它基于版本化的 YAML 策略做出确定性的 `ALLOW` / `DENY` 决策，给出可读的解释，并输出仅包含元数据的审计事件。

> v0.1.0 范围：在*可信*工具 Dispatcher 中保护权限执行点。它不承诺完整的 Prompt Injection 防御，也不构成任何合规认证。

## 功能特性

- 本地、确定性求值，决策路径不发起网络请求
- 默认拒绝；显式 `deny` 始终优先于 `allow`，与规则排列顺序无关
- 严格的策略 Schema v1（使用 `safe_load` 加载，拒绝未知字段）
- `execute()` 守卫：请求被拒绝或审计 sink 失败时，绝不调用受保护函数
- 中英双语：消息、决策解释与命令行输出均支持简体中文（`zh-CN`）和英文

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

需要 Python 3.11+。

## 快速开始

```python
from agentcomply import AgentComply, AuthorizationRequest

security = AgentComply("policies/customer-support.yaml", locale="zh-CN")  # 或 "en"

req = AuthorizationRequest(
    user_id="alice", agent_id="support-agent",
    tool="database.read", resource="orders", action="read",
)
decision = security.authorize(req)
print(decision.allowed, decision.reason_code, decision.rule_id)
print(security.explain(decision))   # 允许：规则 'allow-order-read' 允许该操作。

result = security.execute(req, read_orders)  # 仅在允许时才会执行 read_orders
```

运行双语示例：

```bash
python examples/quickstart.py            # 英文（默认）
python examples/quickstart.py --lang zh-CN
```

## 语言选择

语言按以下优先级确定：

1. 参数 `locale=`，例如 `AgentComply(path, locale="zh-CN")`
2. 环境变量 `AGENTCOMPLY_LOCALE`（`en` 或 `zh-CN`）
3. 默认英文（`en`）

可接受的别名包括 `zh`、`zh_CN`、`zh-Hans`、`en-US` 等。不支持的取值会抛出 `ValueError`。

只有面向人的文本会被翻译。原因码（`EXPLICIT_DENY`、`RULE_ALLOW`、`DEFAULT_DENY`、`INVALID_REQUEST`）、审计事件字段和策略关键字始终为英文，确保日志与集成在不同语言下保持稳定。

## 命令行

```bash
python -m agentcomply --lang zh-CN check policies/customer-support.yaml
# 策略校验通过: customer-support-v1
```

## 策略示例

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

## 护栏（v0.2）

- 中英文越狱与提示词注入检测，包括混淆输入（零宽字符、分隔符、base64）
- 攻击性（黑客）操作始终阻止，即使策略允许该工具
- 策略 v1alpha1（`apiVersion: agentcomply.io/v1alpha1`）：Glob 资源模式、`require_approval`、任务范围
- 已验证主体、任务授权、一次性审批，以及由 `TrustedExecutor` 强制校验的 HMAC 签名执行令牌
- 对密钥、银行卡号和身份证号进行输出脱敏

```bash
python examples/finance_rag_demo.py --lang zh-CN
python -m agentcomply --lang zh-CN screen --text "请忽略之前的所有指令"   # 命中阻断时退出码为 3
```

设计详见 [docs/GUARDRAILS.zh-CN.md](docs/GUARDRAILS.zh-CN.md)。局限：模式匹配只是其中一层，不是完整防御。

## 测试

```bash
pytest -q
```

## 文档

- [工程设计（中文）](docs/ENGINEERING.zh-CN.md) · [Engineering design (English)](docs/ENGINEERING.md)
- [护栏与 v0.2 设计](docs/GUARDRAILS.zh-CN.md)
- [安全策略](SECURITY.md) · [贡献指南](CONTRIBUTING.md)

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。正式推广前应单独核查项目名称与商标、域名及包名的可用性。
