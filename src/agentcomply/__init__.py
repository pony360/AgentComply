"""AgentComply: runtime authorization and guardrails SDK for AI agent tool calls."""

from .decorators import secure_tool
from .engine import AgentComply, AuthorizationDenied, AuditSink
from .executor import TrustedExecutor
from .guardrails import Guardrails, Signal, redact_output
from .i18n import SUPPORTED_LOCALES, normalize_locale
from .models import (
    REASON_APPROVED,
    REASON_DEFAULT_DENY,
    REASON_EXPLICIT_DENY,
    REASON_INJECTION_BLOCKED,
    REASON_INVALID_REQUEST,
    REASON_JAILBREAK_BLOCKED,
    REASON_OFFENSIVE_BLOCKED,
    REASON_PRINCIPAL_INVALID,
    REASON_REQUIRE_APPROVAL,
    REASON_RULE_ALLOW,
    REASON_TASK_GRANT_DENIED,
    Action,
    AuthorizationRequest,
    Decision,
    Principal,
    TaskGrant,
)
from .policy import PolicyError

__version__ = "0.2.0"

__all__ = [
    "Action",
    "AgentComply",
    "AuditSink",
    "AuthorizationDenied",
    "AuthorizationRequest",
    "Decision",
    "Guardrails",
    "Principal",
    "PolicyError",
    "REASON_APPROVED",
    "REASON_DEFAULT_DENY",
    "REASON_EXPLICIT_DENY",
    "REASON_INJECTION_BLOCKED",
    "REASON_INVALID_REQUEST",
    "REASON_JAILBREAK_BLOCKED",
    "REASON_OFFENSIVE_BLOCKED",
    "REASON_PRINCIPAL_INVALID",
    "REASON_REQUIRE_APPROVAL",
    "REASON_RULE_ALLOW",
    "REASON_TASK_GRANT_DENIED",
    "Signal",
    "SUPPORTED_LOCALES",
    "TaskGrant",
    "TrustedExecutor",
    "normalize_locale",
    "redact_output",
    "secure_tool",
    "__version__",
]
