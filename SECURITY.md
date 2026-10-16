# Security Policy / 安全策略

## English

AgentComply is a pre-release (v0.1.0) authorization SDK. It is not a production security certification and does not defend against every prompt-injection attack.

To report a vulnerability, please do not open a public issue. Email the maintainers privately with a description, reproduction steps and the affected version. We will acknowledge receipt, investigate, and coordinate a fix and disclosure timeline with you.

In scope: policy evaluation bypasses, `execute()` calling a protected function when it should not, audit events leaking prohibited data, and policy validation accepting invalid input.

Out of scope: attackers who already control the host process or its administrator credentials; the trustworthiness of host-supplied identities; tools that bypass the dispatcher.

## 简体中文

AgentComply 目前为发布前版本（v0.1.0）的授权 SDK。它不是生产级安全认证，也不能防御所有 Prompt Injection 攻击。

请勿通过公开 Issue 报告安全漏洞。请私下发送邮件给维护者，包含问题描述、复现步骤和受影响版本。我们会确认收到，调查问题，并与您协商修复与披露时间表。

范围内：策略求值被绕过、`execute()` 在不应调用时调用了受保护函数、审计事件泄露禁止记录的数据、策略校验接受了非法输入。

范围外：已控制宿主进程或管理员凭据的攻击者；宿主传入身份的可信性；绕过 Dispatcher 的工具路径。
