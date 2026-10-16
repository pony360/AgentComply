"""Trusted tool executor (policy enforcement point).

The executor is the only path that calls protected tools. It re-verifies the
execution token, so a token cannot be replayed or moved to another action.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from .engine import AgentComply, AuthorizationDenied
from .models import Action


class TrustedExecutor:
    def __init__(self, engine: AgentComply) -> None:
        self._engine = engine

    @property
    def engine(self) -> AgentComply:
        return self._engine

    def execute(
        self,
        action: Action,
        authorization: str | None,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Verify the token for ``action``, record the event, then call ``fn`` once.

        Fails closed: a missing, forged, expired, mismatched or replayed token
        means ``fn`` is not called. An audit failure also means ``fn`` is not called.
        """
        if not isinstance(action, Action):
            raise TypeError(self._engine._t("request.not_a_request"))
        if inspect.iscoroutinefunction(fn):
            raise TypeError(self._engine._t("execute.async_not_supported"))

        payload = self._engine._verify_execution(authorization, action)
        if payload is None:
            raise AuthorizationDenied(self._engine._t("denied.token_invalid"))
        if not self._engine._consume_nonce(payload["nonce"], int(payload["exp"])):
            raise AuthorizationDenied(self._engine._t("denied.token_replayed"))

        self._engine._emit_event({
            "event": "tool_execution",
            "outcome": "about_to_execute",
            "decision_id": payload["decision_id"],
            "action_hash": payload["action_hash"],
            "tool": action.tool,
            "operation": action.operation,
        })
        return fn(*args, **kwargs)
