"""Policy loading and validation.

Two schemas are supported:

* ``version: 1`` (v0.1.0 baseline): exact-match selectors, no wildcards.
* ``apiVersion: agentcomply.io/v1alpha1`` (design proposal): JSON-Schema
  validated, glob resource patterns, ``require_approval`` effect, task scopes,
  detection and audit settings.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import EFFECT_ALLOW, EFFECT_DENY, EFFECT_REQUIRE_APPROVAL, Action, is_identifier

API_VERSION = "agentcomply.io/v1alpha1"
KIND = "AgentSecurityPolicy"
EFFECTS_V1 = (EFFECT_ALLOW, EFFECT_DENY)
EFFECTS_V1ALPHA1 = (EFFECT_ALLOW, EFFECT_DENY, EFFECT_REQUIRE_APPROVAL)
DETECTION_MODES = ("monitor", "enforce")

_TOP_LEVEL_V1 = frozenset({"version", "policy_id", "default", "rules"})
_RULE_V1 = frozenset({"id", "effect", "users", "agents", "tools", "resources", "actions"})
_SELECTORS_V1 = ("users", "agents", "tools", "resources", "actions")
_RESOURCE_PATTERN_RE = re.compile(r"^[A-Za-z0-9_\-.*/]{1,512}$")


class PolicyError(ValueError):
    """Raised when a policy cannot be loaded or fails validation."""


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    users: frozenset[str] | None
    agents: frozenset[str] | None
    tools: frozenset[str]
    operations: frozenset[str]
    resources: tuple[re.Pattern[str], ...]
    required_scopes: frozenset[str]

    def matches(self, action: Action, subject: str) -> bool:
        if self.users is not None and subject not in self.users:
            return False
        if self.agents is not None and action.agent_id not in self.agents:
            return False
        if action.tool not in self.tools or action.operation not in self.operations:
            return False
        return any(pattern.fullmatch(action.resource) for pattern in self.resources)


@dataclass(frozen=True)
class DetectionConfig:
    mode: str = "enforce"
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    redact_secrets: bool = True


@dataclass(frozen=True)
class Policy:
    policy_id: str
    api_version: str
    rules: tuple[Rule, ...]
    detection: DetectionConfig
    audit: AuditConfig
    version_hash: str


@functools.lru_cache(maxsize=2048)
def compile_resource_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a glob resource pattern. ``*`` matches one segment, ``**`` matches any depth.

    Raises ``ValueError`` for unsafe patterns (traversal, empty segments, bad characters).
    """
    if not isinstance(pattern, str) or _RESOURCE_PATTERN_RE.fullmatch(pattern) is None:
        raise ValueError("unsafe resource pattern")
    if any(segment in ("", ".", "..") for segment in pattern.split("/")):
        raise ValueError("unsafe resource pattern")
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(parts))


def _policy_hash(data: Mapping[str, Any]) -> str:
    text = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_policy(source: str | Path | Mapping[str, Any], t: Callable[..., str]) -> Policy:
    """Load a policy from a YAML path or an already-parsed mapping."""
    if isinstance(source, Mapping):
        data: Any = source
    else:
        path = Path(source)
        if not path.is_file():
            raise PolicyError(t("policy.file_not_found", path=str(path)))
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(t("policy.yaml_error", error=str(exc))) from exc
    if not isinstance(data, Mapping):
        raise PolicyError(t("policy.not_a_mapping"))
    vhash = _policy_hash(data)
    if "apiVersion" in data:
        return _load_v1alpha1(data, t, vhash)
    return _load_legacy(data, t, vhash)


# ---------------------------------------------------------------- legacy v1

def _load_legacy(data: Mapping[str, Any], t: Callable[..., str], vhash: str) -> Policy:
    for name in data:
        if name not in _TOP_LEVEL_V1:
            raise PolicyError(t("policy.unknown_field", field=name))
    for name in sorted(_TOP_LEVEL_V1):
        if name not in data:
            raise PolicyError(t("policy.missing_field", field=name))
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise PolicyError(t("policy.invalid_version"))
    if data["default"] != "deny":
        raise PolicyError(t("policy.invalid_default"))
    policy_id = data["policy_id"]
    if not is_identifier(policy_id):
        raise PolicyError(t("policy.invalid_policy_id", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$"))
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise PolicyError(t("policy.rules_not_a_list"))

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules, start=1):
        if not isinstance(raw, Mapping):
            raise PolicyError(t("policy.rule_not_a_mapping", index=index))
        rule = _legacy_rule(raw, t)
        if rule.id in seen:
            raise PolicyError(t("policy.duplicate_rule_id", rule_id=rule.id))
        seen.add(rule.id)
        rules.append(rule)
    return Policy(
        policy_id=policy_id,
        api_version="v1",
        rules=tuple(rules),
        detection=DetectionConfig(),
        audit=AuditConfig(),
        version_hash=vhash,
    )


def _legacy_rule(raw: Mapping[str, Any], t: Callable[..., str]) -> Rule:
    rule_id = raw.get("id")
    display = rule_id if isinstance(rule_id, str) else "?"
    for name in raw:
        if name not in _RULE_V1:
            raise PolicyError(t("policy.rule_unknown_field", rule_id=display, field=name))
    for name in sorted(_RULE_V1):
        if name not in raw:
            raise PolicyError(t("policy.rule_missing_field", rule_id=display, field=name))
    if not is_identifier(rule_id):
        raise PolicyError(t("policy.invalid_rule_id", rule_id=display, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$"))
    effect = raw["effect"]
    if effect not in EFFECTS_V1:
        raise PolicyError(t("policy.invalid_effect", rule_id=rule_id, effects=", ".join(EFFECTS_V1)))

    selectors: dict[str, frozenset[str]] = {}
    for name in _SELECTORS_V1:
        value = raw[name]
        if not isinstance(value, list) or not value or not all(isinstance(v, str) and v.strip() for v in value):
            raise PolicyError(t("policy.invalid_selector", rule_id=rule_id, field=name))
        if name in ("tools", "resources", "actions") and any("*" in v for v in value):
            raise PolicyError(t("policy.wildcard_not_allowed", rule_id=rule_id, field=name))
        selectors[name] = frozenset(value)

    return Rule(
        id=rule_id,
        effect=effect,
        users=selectors["users"],
        agents=selectors["agents"],
        tools=selectors["tools"],
        operations=selectors["actions"],
        resources=tuple(re.compile(re.escape(v)) for v in selectors["resources"]),
        required_scopes=frozenset(),
    )


# ------------------------------------------------------------- v1alpha1

def _schema() -> dict[str, Any]:
    text = resources.files("agentcomply").joinpath("schemas/policy-v1alpha1.schema.json").read_text(encoding="utf-8")
    return json.loads(text)


def _load_v1alpha1(data: Mapping[str, Any], t: Callable[..., str], vhash: str) -> Policy:
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(_schema())
    errors = sorted(validator.iter_errors(data), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise PolicyError(t("policy.schema_error", path=path, message=first.message))

    policy_id = data["metadata"]["name"]
    spec = data["spec"]
    selector = spec.get("selector") or {}
    agents = frozenset(selector["agentIds"]) if "agentIds" in selector else None

    det = spec.get("detection") or {}
    detection = DetectionConfig(mode=det.get("mode", "enforce"), sources=tuple(det.get("sources", ())))
    aud = spec.get("audit") or {}
    audit = AuditConfig(enabled=aud.get("enabled", True), redact_secrets=aud.get("redactSecrets", True))

    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in spec["rules"]:
        rule_id = raw["id"]
        if rule_id in seen:
            raise PolicyError(t("policy.duplicate_rule_id", rule_id=rule_id))
        seen.add(rule_id)
        patterns = []
        for pattern in raw["resourcePatterns"]:
            try:
                patterns.append(compile_resource_pattern(pattern))
            except ValueError as exc:
                raise PolicyError(t("policy.invalid_resource_pattern", rule_id=rule_id, pattern=pattern)) from exc
        rules.append(
            Rule(
                id=rule_id,
                effect=raw["effect"],
                users=None,
                agents=agents,
                tools=frozenset([raw["tool"]]),
                operations=frozenset(raw["operations"]),
                resources=tuple(patterns),
                required_scopes=frozenset(raw.get("requiredTaskScopes", [])),
            )
        )
    return Policy(
        policy_id=policy_id,
        api_version=API_VERSION,
        rules=tuple(rules),
        detection=detection,
        audit=audit,
        version_hash=vhash,
    )
