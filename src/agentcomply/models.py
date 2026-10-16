"""Core data models: requests, actions, principals, grants and decisions."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

IDENT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$"
_IDENT_RE = re.compile(IDENT_PATTERN)
_RESOURCE_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,128}(?:/[A-Za-z0-9_\-.]{1,128}){0,15}$")

# Machine-readable reason codes. These are never translated.
REASON_EXPLICIT_DENY = "EXPLICIT_DENY"
REASON_RULE_ALLOW = "RULE_ALLOW"
REASON_DEFAULT_DENY = "DEFAULT_DENY"
REASON_INVALID_REQUEST = "INVALID_REQUEST"
REASON_PRINCIPAL_INVALID = "PRINCIPAL_INVALID"
REASON_TASK_GRANT_DENIED = "TASK_GRANT_DENIED"
REASON_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
REASON_APPROVED = "APPROVED"
REASON_OFFENSIVE_BLOCKED = "OFFENSIVE_OPERATION_BLOCKED"
REASON_JAILBREAK_BLOCKED = "JAILBREAK_BLOCKED"
REASON_INJECTION_BLOCKED = "PROMPT_INJECTION_BLOCKED"

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECT_REQUIRE_APPROVAL = "require_approval"


def is_identifier(value: object) -> bool:
    """True if ``value`` matches the restricted identifier format."""
    return isinstance(value, str) and _IDENT_RE.fullmatch(value) is not None


def is_resource(value: object) -> bool:
    """True for a concrete, normalized resource path such as ``reports/q3-2026``.

    Wildcards, leading slashes, empty segments and ``.``/``..`` segments are
    rejected, which blocks path traversal before any matching happens.
    """
    if not isinstance(value, str) or _RESOURCE_RE.fullmatch(value) is None:
        return False
    return all(segment not in (".", "..") for segment in value.split("/"))


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


@dataclass(frozen=True)
class AuthorizationRequest:
    """Legacy (v1) request: ``action`` is the operation name."""

    user_id: str
    agent_id: str
    tool: str
    resource: str
    action: str

    def to_action(self) -> "Action":
        return Action(
            agent_id=self.agent_id,
            tool=self.tool,
            operation=self.action,
            resource=self.resource,
        )


@dataclass(frozen=True)
class Action:
    """A normalized tool call proposed by an agent.

    ``parameters`` must be JSON-serializable. They are screened by the
    guardrails and bound to execution tokens through ``action_hash()``.
    """

    agent_id: str
    tool: str
    operation: str
    resource: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    task_id: str | None = None

    def invalid_fields(self) -> list[str]:
        bad = [name for name in ("agent_id", "tool", "operation") if not is_identifier(getattr(self, name))]
        if not is_resource(self.resource):
            bad.append("resource")
        if self.task_id is not None and not is_identifier(self.task_id):
            bad.append("task_id")
        if not isinstance(self.parameters, Mapping):
            bad.append("parameters")
        else:
            try:
                canonical_json(dict(self.parameters))
            except (TypeError, ValueError):
                bad.append("parameters")
        return bad

    def action_hash(self) -> str:
        payload = {
            "agent_id": self.agent_id,
            "tool": self.tool,
            "operation": self.operation,
            "resource": self.resource,
            "parameters": dict(self.parameters),
            "task_id": self.task_id,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    """The verified end user, as established by the trusted application's IdP.

    The SDK never builds a Principal from model output.
    """

    subject: str
    tenant: str | None = None
    roles: tuple[str, ...] = ()
    issuer: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True)
class TaskGrant:
    """Business-level permission for a task, issued by the application backend."""

    grant_id: str
    subject: str
    scopes: frozenset[str]
    resources: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True)
class Decision:
    """Result of an authorization evaluation."""

    allowed: bool
    reason_code: str
    policy_id: str
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str | None = None
    effect: str | None = None
    action_hash: str | None = None
    signal_categories: tuple[str, ...] = ()
    trace_id: str | None = None
    execution_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Metadata-only representation. Never contains parameters or text."""
        return {
            "decision_id": self.decision_id,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "effect": self.effect,
            "action_hash": self.action_hash,
            "signal_categories": list(self.signal_categories),
            "trace_id": self.trace_id,
        }
