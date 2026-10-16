"""AgentComply engine: policy evaluation, guardrails, tokens and audit."""

from __future__ import annotations

import inspect
import secrets
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .guardrails import (
    OFFENSIVE,
    Guardrails,
    Signal,
    categories,
    redact_output,
    tool_is_offensive,
)
from .i18n import normalize_locale, translate
from .models import (
    EFFECT_ALLOW,
    EFFECT_DENY,
    EFFECT_REQUIRE_APPROVAL,
    REASON_APPROVED,
    REASON_DEFAULT_DENY,
    REASON_EXPLICIT_DENY,
    REASON_INVALID_REQUEST,
    REASON_PRINCIPAL_INVALID,
    REASON_REQUIRE_APPROVAL,
    REASON_RULE_ALLOW,
    REASON_TASK_GRANT_DENIED,
    Action,
    AuthorizationRequest,
    Decision,
    Principal,
    TaskGrant,
    canonical_json,
    is_identifier,
)
from .policy import PolicyError, Policy, Rule, compile_resource_pattern, load_policy
from .tokens import TokenSigner

__all__ = ["AgentComply", "AuditSink", "AuthorizationDenied", "PolicyError"]

AuditSink = Callable[[dict[str, Any]], None]
EXECUTION_TTL_SECONDS = 60
MAX_APPROVAL_TTL_SECONDS = 3600


class AuthorizationDenied(RuntimeError):
    """Raised when an action is denied, a token is invalid, or the audit sink fails."""

    def __init__(self, message: str, decision: Decision | None = None) -> None:
        super().__init__(message)
        self.decision = decision


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _grant_covers(
    grant: TaskGrant | None,
    principal: Principal,
    action: Action,
    scopes: frozenset[str],
    now: datetime,
) -> bool:
    if grant is None or grant.subject != principal.subject:
        return False
    if _aware(grant.expires_at) <= now:
        return False
    if not scopes <= grant.scopes:
        return False
    for pattern in grant.resources:
        try:
            if compile_resource_pattern(pattern).fullmatch(action.resource):
                return True
        except ValueError:
            continue
    return False


class AgentComply:
    """Local authorization engine with guardrails.

    Args:
        policy: Path to a YAML policy (``version: 1`` or ``apiVersion: agentcomply.io/v1alpha1``),
            or an already-parsed mapping.
        audit_sink: Optional callable receiving one metadata-only event per decision.
            If it raises, the decision is withheld and ``AuthorizationDenied`` is raised.
        locale: ``"en"`` or ``"zh-CN"``. Defaults to ``AGENTCOMPLY_LOCALE``, then English.
        signing_key: At least 32 bytes. Signs execution and approval tokens. Random if omitted.
        clock: Returns the current aware datetime. Used for expiry checks (for tests).

    Raises:
        PolicyError: If the policy is missing, unparsable, or invalid.
    """

    def __init__(
        self,
        policy: str | Path | Mapping[str, Any],
        audit_sink: AuditSink | None = None,
        locale: str | None = None,
        signing_key: bytes | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._locale = normalize_locale(locale)
        self._audit_sink = audit_sink
        self._clock = clock or _utc_now
        self._policy: Policy = load_policy(policy, self._t)
        self._guard = Guardrails(self._policy.detection.mode)
        self._signer = TokenSigner(signing_key)

    # ----------------------------------------------------------- properties

    @property
    def locale(self) -> str:
        return self._locale

    @property
    def policy_id(self) -> str:
        return self._policy.policy_id

    @property
    def policy_version(self) -> str:
        return self._policy.version_hash

    @property
    def api_version(self) -> str:
        return self._policy.api_version

    def _t(self, key: str, **kwargs: object) -> str:
        return translate(key, self._locale, **kwargs)

    # ------------------------------------------------------------ screening

    def screen(self, text: str, *, source: str = "untrusted", operation: str = "write") -> tuple[Signal, ...]:
        """Screen text and return signals. Also returns the blocking reason via ``blocking_reason``."""
        return self._guard.screen(text, source)

    def blocking_reason(self, signals: Iterable[Signal], operation: str = "write") -> str | None:
        return self._guard.blocking_reason(signals, operation)

    def guard_output(self, text: str) -> tuple[str, dict[str, int]]:
        """Redact secrets and personal identifiers from model output."""
        return redact_output(text)

    def _screen_action(self, action: Action, untrusted: tuple[str, ...]) -> tuple[Signal, ...]:
        signals: list[Signal] = []
        for text in untrusted:
            signals.extend(self._guard.screen(text, "untrusted"))
        signals.extend(self._guard.screen(canonical_json(dict(action.parameters)), "parameters"))
        if tool_is_offensive(action.tool, action.operation):
            signals.append(Signal(OFFENSIVE, "taxonomy.tool", 1.0, "action"))
        return tuple(signals)

    # ------------------------------------------------------------- evaluation

    def _build(
        self,
        *,
        allowed: bool,
        reason: str,
        decision_id: str,
        rule_id: str | None = None,
        effect: str | None = None,
        action_hash: str | None = None,
        signals: Iterable[Signal] = (),
        trace_id: str | None = None,
    ) -> Decision:
        return Decision(
            allowed=allowed,
            reason_code=reason,
            policy_id=self._policy.policy_id,
            decision_id=decision_id,
            rule_id=rule_id,
            effect=effect,
            action_hash=action_hash,
            signal_categories=categories(signals),
            trace_id=trace_id,
        )

    def _with_token(self, decision: Decision, action: Action, now: datetime) -> Decision:
        payload = {
            "kind": "execution",
            "decision_id": decision.decision_id,
            "action_hash": decision.action_hash,
            "agent_id": action.agent_id,
            "tool": action.tool,
            "operation": action.operation,
            "resource": action.resource,
            "policy_id": self._policy.policy_id,
            "exp": int(now.timestamp()) + EXECUTION_TTL_SECONDS,
            "nonce": secrets.token_urlsafe(16),
        }
        return replace(decision, execution_token=self._signer.issue(payload))

    def _evaluate(
        self,
        action: Action,
        principal: Principal | None,
        grant: TaskGrant | None,
        approval: str | None,
        untrusted: tuple[str, ...],
        trace_id: str | None,
    ) -> Decision:
        decision_id = str(uuid.uuid4())
        now = self._clock()
        bad = action.invalid_fields()
        if principal is not None and not is_identifier(principal.subject):
            bad.append("subject")
        if bad:
            return self._build(allowed=False, reason=REASON_INVALID_REQUEST, decision_id=decision_id, trace_id=trace_id)
        if principal is None:
            return self._build(allowed=False, reason=REASON_PRINCIPAL_INVALID, decision_id=decision_id, trace_id=trace_id)
        if principal.expires_at is not None and _aware(principal.expires_at) <= now:
            return self._build(allowed=False, reason=REASON_PRINCIPAL_INVALID, decision_id=decision_id, trace_id=trace_id)

        ahash = action.action_hash()
        signals = self._screen_action(action, untrusted)
        blocked = self._guard.blocking_reason(signals, action.operation)
        if blocked:
            return self._build(
                allowed=False, reason=blocked, decision_id=decision_id,
                action_hash=ahash, signals=signals, trace_id=trace_id,
            )

        matched: list[Rule] = [r for r in self._policy.rules if r.matches(action, principal.subject)]

        for rule in matched:
            if rule.effect == EFFECT_DENY:
                return self._build(
                    allowed=False, reason=REASON_EXPLICIT_DENY, decision_id=decision_id, rule_id=rule.id,
                    effect=EFFECT_DENY, action_hash=ahash, signals=signals, trace_id=trace_id,
                )

        approvals = [r for r in matched if r.effect == EFFECT_REQUIRE_APPROVAL]
        if approvals:
            rule = approvals[0]
            if approval is not None and self._consume_approval(approval, ahash, now):
                decision = self._build(
                    allowed=True, reason=REASON_APPROVED, decision_id=decision_id, rule_id=rule.id,
                    effect=EFFECT_REQUIRE_APPROVAL, action_hash=ahash, signals=signals, trace_id=trace_id,
                )
                return self._with_token(decision, action, now)
            return self._build(
                allowed=False, reason=REASON_REQUIRE_APPROVAL, decision_id=decision_id, rule_id=rule.id,
                effect=EFFECT_REQUIRE_APPROVAL, action_hash=ahash, signals=signals, trace_id=trace_id,
            )

        grant_rejected: Rule | None = None
        for rule in matched:
            if rule.effect != EFFECT_ALLOW:
                continue
            if rule.required_scopes and not _grant_covers(grant, principal, action, rule.required_scopes, now):
                grant_rejected = rule
                continue
            decision = self._build(
                allowed=True, reason=REASON_RULE_ALLOW, decision_id=decision_id, rule_id=rule.id,
                effect=EFFECT_ALLOW, action_hash=ahash, signals=signals, trace_id=trace_id,
            )
            return self._with_token(decision, action, now)

        if grant_rejected is not None:
            return self._build(
                allowed=False, reason=REASON_TASK_GRANT_DENIED, decision_id=decision_id,
                rule_id=grant_rejected.id, effect=EFFECT_ALLOW, action_hash=ahash,
                signals=signals, trace_id=trace_id,
            )
        return self._build(
            allowed=False, reason=REASON_DEFAULT_DENY, decision_id=decision_id,
            action_hash=ahash, signals=signals, trace_id=trace_id,
        )

    @staticmethod
    def _normalize(
        request: object, principal: Principal | None
    ) -> tuple[Action, Principal | None]:
        if isinstance(request, AuthorizationRequest):
            resolved = principal or Principal(subject=request.user_id)
            return request.to_action(), resolved
        if isinstance(request, Action):
            return request, principal
        raise TypeError("request must be an AuthorizationRequest or Action")

    # ----------------------------------------------------------------- audit

    def _emit_raw(self, event: dict[str, Any], decision: Decision | None = None) -> None:
        if not self._policy.audit.enabled or self._audit_sink is None:
            return
        event = dict(event, policy_version=self._policy.version_hash)
        try:
            self._audit_sink(event)
        except Exception as exc:  # noqa: BLE001 - any sink failure must fail closed
            raise AuthorizationDenied(self._t("denied.audit_failed"), decision) from exc

    # ------------------------------------------------------------ public API

    def authorize(
        self,
        request: AuthorizationRequest | Action,
        *,
        principal: Principal | None = None,
        grant: TaskGrant | None = None,
        approval: str | None = None,
        untrusted: Iterable[str] = (),
        trace_id: str | None = None,
    ) -> Decision:
        """Evaluate ``request`` and emit one audit event.

        ``untrusted`` takes text from RAG documents, tool responses or other
        sources the model did not author. It is screened, never trusted.
        Returns a ``Decision``. Callers must honor ``decision.allowed``, or use
        ``TrustedExecutor`` / ``execute()``.

        Raises:
            AuthorizationDenied: If the audit sink raises.
            TypeError: If ``request`` has an unsupported type.
        """
        action, resolved = self._normalize(request, principal)
        texts = tuple(t for t in untrusted if isinstance(t, str))
        decision = self._evaluate(action, resolved, grant, approval, texts, trace_id)
        event = {"event": "authorization_decision", **decision.to_dict()}
        self._emit_raw(event, decision)
        return decision

    def issue_approval(self, action: Action, ttl_seconds: int = 300) -> str:
        """Issue a single-use approval token bound to ``action``. Call after a human approves."""
        if not isinstance(action, Action):
            raise TypeError(self._t("request.not_a_request"))
        if action.invalid_fields():
            raise ValueError(self._t("request.invalid_action"))
        if not 1 <= ttl_seconds <= MAX_APPROVAL_TTL_SECONDS:
            raise ValueError(self._t("approval.ttl_out_of_range"))
        now = int(self._clock().timestamp())
        return self._signer.issue({
            "kind": "approval",
            "action_hash": action.action_hash(),
            "exp": now + ttl_seconds,
            "nonce": secrets.token_urlsafe(16),
        })

    def _consume_approval(self, token: str, action_hash: str | None, now: datetime) -> bool:
        now_epoch = int(now.timestamp())
        payload = self._signer.verify(token, kind="approval", now_epoch=now_epoch)
        if payload is None or payload.get("action_hash") != action_hash:
            return False
        return self._signer.consume(payload["nonce"], payload["exp"], now_epoch)

    def execute(
        self,
        request: AuthorizationRequest,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Authorize (v1 request type) and call ``fn`` exactly once only if allowed.

        ``fn`` is never called on denial or audit failure. Only synchronous callables are supported.
        For the full guarded flow (principal, grant, approval, token checks), use ``TrustedExecutor``.
        """
        if inspect.iscoroutinefunction(fn):
            raise TypeError(self._t("execute.async_not_supported"))
        decision = self.authorize(request)
        if not decision.allowed:
            raise AuthorizationDenied(
                self._t("denied.execution", reason_code=decision.reason_code), decision
            )
        return fn(*args, **kwargs)

    def explain(self, decision: Decision) -> str:
        """Human-readable explanation in this instance's locale."""
        return self._t(f"reason.{decision.reason_code}", rule_id=decision.rule_id or "")

    # ------------------------------------------- internal hooks for executors

    def _verify_execution(self, token: object, action: Action) -> dict[str, Any] | None:
        if action.invalid_fields():
            return None
        now_epoch = int(self._clock().timestamp())
        payload = self._signer.verify(token, kind="execution", now_epoch=now_epoch)
        if payload is None or payload.get("action_hash") != action.action_hash():
            return None
        if payload.get("policy_id") != self._policy.policy_id:
            return None
        return payload

    def _consume_nonce(self, nonce: str, exp: int) -> bool:
        return self._signer.consume(nonce, exp, int(self._clock().timestamp()))

    def _emit_event(self, event: dict[str, Any]) -> None:
        self._emit_raw(event)
