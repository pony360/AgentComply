"""``@secure_tool``: guard a Python function with authorization and the trusted executor.

Function keyword arguments become ``Action.parameters``, so they must be JSON-serializable.
Keyword names ``action``, ``authorization`` and ``fn`` are reserved by ``TrustedExecutor.execute``.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterable
from typing import Any

from .engine import AuthorizationDenied
from .executor import TrustedExecutor
from .models import Action, Principal, TaskGrant


def secure_tool(
    executor: TrustedExecutor,
    *,
    agent_id: str,
    tool: str,
    operation: str,
    resource: str | Callable[..., str],
    principal: Principal,
    grant: TaskGrant | None = None,
    untrusted: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    untrusted_texts = tuple(untrusted)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):
            raise TypeError(executor.engine._t("execute.async_not_supported"))

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            resolved_resource = resource(*args, **kwargs) if callable(resource) else resource
            action = Action(
                agent_id=agent_id,
                tool=tool,
                operation=operation,
                resource=resolved_resource,
                parameters=dict(kwargs),
            )
            decision = executor.engine.authorize(
                action, principal=principal, grant=grant, untrusted=untrusted_texts
            )
            if not decision.allowed or decision.execution_token is None:
                raise AuthorizationDenied(
                    executor.engine._t("denied.execution", reason_code=decision.reason_code),
                    decision,
                )
            return executor.execute(action, decision.execution_token, fn, *args, **kwargs)

        return wrapper

    return decorator
