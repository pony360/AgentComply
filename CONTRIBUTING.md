# Contributing / 贡献指南

## English

Thanks for helping improve AgentComply.

1. Create a virtual environment and install the dev extras: `pip install -e ".[dev]"`.
2. Run the tests: `pytest -q`. Run the examples in both languages: `python examples/quickstart.py --lang en` and `--lang zh-CN`.
3. Keep changes focused. Security-relevant behavior (fail-closed defaults, deny precedence, audit contents) needs a test.
4. Bilingual rule: any new human-facing message must be added to both `en` and `zh-CN` in `src/agentcomply/i18n.py`. Machine-readable values (reason codes, event fields, policy keys) stay English. User-facing docs should be updated in both languages (`README.md` / `README.zh-CN.md`, `docs/ENGINEERING.md` / `docs/ENGINEERING.zh-CN.md`).
5. Do not record prompt text, tool arguments, customer data or secrets in tests fixtures or audit output.

## 简体中文

感谢你帮助改进 AgentComply。

1. 创建虚拟环境并安装开发依赖：`pip install -e ".[dev]"`。
2. 运行测试：`pytest -q`；分别以两种语言运行示例：`python examples/quickstart.py --lang en` 与 `--lang zh-CN`。
3. 保持改动聚焦。与安全相关的行为（fail-closed 默认值、拒绝优先、审计内容）需要有对应测试。
4. 双语规则：新增的面向用户的消息必须同时添加到 `src/agentcomply/i18n.py` 的 `en` 与 `zh-CN` 中。机器可读的值（原因码、事件字段、策略关键字）保持英文。面向用户的文档应同时更新中英文版本（`README.md` / `README.zh-CN.md`，`docs/ENGINEERING.md` / `docs/ENGINEERING.zh-CN.md`）。
5. 不要在测试夹具或审计输出中记录 Prompt 原文、工具参数、客户数据或密钥。
