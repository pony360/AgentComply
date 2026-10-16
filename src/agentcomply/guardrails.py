"""Guardrails against jailbreaks, prompt injection and offensive (hacking) operations.

Layers:

1. Screening: text is normalized (NFKC, zero-width removal, case folding),
   also checked in a separator-free form and after one level of base64
   decoding, so simple obfuscation does not hide the signal.
2. Offensive operations (hacking, malware, credential theft, evasion, DDoS,
   exploitation): always blocked, regardless of policy mode or policy allows.
3. Jailbreak / prompt injection: in ``enforce`` mode, blocks operations that
   are not read-only. In ``monitor`` mode it only records signals.
4. Output DLP: redacts secrets, card numbers and national ID numbers.

Detection never grants permission. It can only add a denial.

Limitations: pattern matching is not semantic understanding. It will miss
paraphrases and novel encodings, and it can produce false positives. Treat it
as one layer on top of deterministic authorization, not as a complete defense.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from .models import REASON_INJECTION_BLOCKED, REASON_JAILBREAK_BLOCKED, REASON_OFFENSIVE_BLOCKED

JAILBREAK = "jailbreak"
PROMPT_INJECTION = "prompt_injection"
OFFENSIVE = "offensive_security"

READ_ONLY_OPERATIONS = frozenset({"read", "search", "summarize", "list"})
DEFAULT_THRESHOLD = 0.8

# (rule_id, category, weight, pattern). Patterns are applied to normalized text.
# Use \s* (not \s+) so that compact, separator-free variants also match.
_RAW_PATTERNS: tuple[tuple[str, str, float, str], ...] = (
    # --- jailbreak (English)
    ("jb.ignore_instructions", JAILBREAK, 0.9,
     r"(?:ignore|disregard|override)\s*(?:(?:all|any|the|your|of)\s*){0,3}(?:previous|prior|above|earlier|system)\s*(?:instructions?|prompts?|rules?|directions?|guidelines?)"),
    ("jb.persona", JAILBREAK, 0.9,
     r"you\s*are\s*now\s*(?:dan|do\s*anything\s*now|in\s*developer\s*mode|unrestricted|unfiltered|jailbroken)"),
    ("jb.dan_mode", JAILBREAK, 0.9, r"\bdan\s*mode\b|do\s*anything\s*now"),
    ("jb.developer_mode", JAILBREAK, 0.9, r"developer\s*mode\s*(?:enabled|on|activated|unlocked)"),
    ("jb.no_restrictions", JAILBREAK, 0.75,
     r"(?:without|no|free\s*from|disable)\s*(?:any\s*)?(?:restrictions|filters|limitations|safety\s*(?:guidelines|rules)|ethical\s*constraints|content\s*policy)"),
    ("jb.keyword", JAILBREAK, 0.8, r"\bjailbreak(?:ing|ed)?\b"),
    # --- jailbreak (Chinese)
    ("jb.zh_ignore", JAILBREAK, 0.9,
     r"(?:忽略|无视|忘记|绕过|覆盖)[之以先前的所有全部你系统上下面]{0,6}(?:指令|指示|提示词|提示|规则|设定|限制)"),
    ("jb.zh_mode", JAILBREAK, 0.9, r"(?:开发者模式|越狱模式|dan模式|无限制模式)"),
    ("jb.zh_no_limit", JAILBREAK, 0.6, r"(?:没有|不受|无)(?:任何)?(?:道德|安全|内容)?(?:限制|约束|过滤)"),
    ("jb.zh_roleplay", JAILBREAK, 0.8, r"扮演.{0,10}(?:没有|不受).{0,6}(?:限制|约束|规则)"),
    # --- prompt injection (English + Chinese)
    ("inj.reveal_prompt", PROMPT_INJECTION, 0.8,
     r"(?:reveal|show|print|output|repeat|leak|dump)\s*(?:me\s*)?(?:your|the)?\s*(?:system\s*)?(?:prompt|instructions)"),
    ("inj.zh_reveal", PROMPT_INJECTION, 0.8, r"(?:输出|泄露|显示|告诉我|重复|打印)(?:你的|系统|完整)?(?:系统)?(?:提示词|系统提示|指令)"),
    ("inj.fake_authority", PROMPT_INJECTION, 0.85,
     r"(?:system\s*administrator|sysadmin|admin|developer|operator)\s*(?:has\s*)?(?:authori[sz]ed|approved|granted|override)"),
    ("inj.zh_fake_authority", PROMPT_INJECTION, 0.85, r"(?:系统管理员|管理员|开发者|运维人员)(?:已|已经)?(?:授权|批准|许可)"),
    ("inj.role_tokens", PROMPT_INJECTION, 0.85, r"<\|im_(?:start|end)\|>|\[/?system\]|<\s*/?\s*system\s*>"),
    ("inj.exfil", PROMPT_INJECTION, 0.9,
     r"(?:send|upload|post|forward|email|exfiltrate)\s*(?:all\s*|the\s*)?(?:customer|user|client|confidential|secret|sensitive)\s*(?:data|records?|information|files?)"),
    ("inj.zh_exfil", PROMPT_INJECTION, 0.9, r"(?:发送|上传|转发|外传|导出|发给)(?:所有|全部)?(?:客户|用户|敏感|机密|内部)(?:数据|资料|信息|记录|文件)|(?:所有|全部)?(?:客户|用户|敏感|机密|内部)(?:数据|资料|信息|记录|文件)(?:导出|发送|上传|转发|外传|发给)"),
    # --- offensive security (English)
    ("off.malware_create", OFFENSIVE, 0.95,
     r"(?:write|create|build|generate|develop|code|make)\s*(?:me\s*)?(?:a|an|some|the)?\s*(?:malware|virus|ransomware|keylogger|rootkit|trojan|botnet|worm|backdoor|spyware|infostealer)"),
    ("off.malware_terms", OFFENSIVE, 0.6, r"\b(?:ransomware|keylogger|rootkit|infostealer|botnet)\b"),
    ("off.c2_shell", OFFENSIVE, 0.9, r"reverse\s*shell|bind\s*shell|command\s*and\s*control\s*(?:server|infrastructure)|\bwebshell\b"),
    ("off.exploit", OFFENSIVE, 0.9,
     r"\bexploit(?:s|ing|ation)?\s*(?:for|against|the|a|an)\b|\bweaponi[sz]e\b|\bcve-\d{4}-\d{4,}\b.{0,30}\b(?:exploit|poc|payload)\b|\bzero[\s-]*day\s*(?:exploit|payload)"),
    ("off.privesc_lateral", OFFENSIVE, 0.9, r"privilege\s*escalation|privesc\b|escalate\s*(?:my\s*|the\s*)?privileges|lateral\s*movement"),
    ("off.credential_theft", OFFENSIVE, 0.95,
     r"(?:dump|harvest|steal|crack|brute[\s-]*force|exfiltrate)\s*(?:(?:the|all|user|their|someone'?s)\s*){0,3}(?:passwords?|credentials?|password\s*hashes|tokens?|cookies|session\s*ids?)|credential\s*stuffing"),
    ("off.phishing", OFFENSIVE, 0.9, r"phishing\s*(?:kit|page|site|email|campaign|template)s?|fake\s*login\s*page|clone\s*(?:a|the)\s*login\s*page"),
    ("off.ddos", OFFENSIVE, 0.9, r"\bddos\b|denial[\s-]*of[\s-]*service\s*attack|\bbotnet\s*(?:attack|for)"),
    ("off.scan_tool_terms", OFFENSIVE, 0.6, r"\b(?:nmap|masscan|sqlmap|metasploit|mimikatz|cobalt\s*strike|hydra)\b"),
    ("off.scan_target", OFFENSIVE, 0.85,
     r"(?:run|use|launch)\s*(?:nmap|masscan|sqlmap|metasploit|mimikatz|hydra)|(?:port|network|vulnerability|host)\s*scan\w*\s*(?:of|on|against|for)?\s*(?:the\s*)?(?:target|victim|someone|their|company|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    ("off.evasion", OFFENSIVE, 0.95,
     r"bypass\s*(?:the\s*|an\s*|any\s*|their\s*)?(?:authentication|authorization|login|mfa|2fa|two[\s-]*factor|antivirus|edr|waf|firewall|sandbox|audit\s*logs?)"),
    ("off.sqli", OFFENSIVE, 0.85, r"sql\s*injection\s*(?:payload|attack|string|query)|'\s*or\s*1\s*=\s*1|union\s*select\b"),
    # --- offensive security (Chinese)
    ("off.zh_intrude", OFFENSIVE, 0.9,
     r"(?:入侵|攻破|攻击|黑进|侵入)\s*(?:别人|他人|目标|某个|某|对方|竞争对手)?\s*(?:的)?\s*(?:网站|服务器|系统|账号|账户|网络|电脑)"),
    ("off.zh_malware", OFFENSIVE, 0.95, r"(?:编写|生成|制作|写一个|写个)(?:一个|一段|些)?\s*(?:木马|勒索软件|病毒|蠕虫|后门程序|键盘记录器|挖矿木马|间谍软件)"),
    ("off.zh_terms", OFFENSIVE, 0.6, r"黑客|木马|勒索软件|键盘记录|后门程序|挖矿木马"),
    ("off.zh_access", OFFENSIVE, 0.85, r"反弹\s*shell|提权|横向移动|撞库|拖库"),
    ("off.zh_credential", OFFENSIVE, 0.95,
     r"(?:盗取|窃取|获取|收集|抓取)\s*(?:他人|别人|用户|员工|管理员)?\s*(?:的)?\s*(?:密码|凭证|凭据|令牌|cookie|会话|账号密码)"),
    ("off.zh_phish_ddos", OFFENSIVE, 0.9, r"钓鱼(?:网站|页面|邮件|套件|网页)|分布式拒绝服务|ddos\s*攻击"),
    ("off.zh_evasion", OFFENSIVE, 0.95,
     r"(?:绕过|规避|破解|突破)\s*(?:登录|认证|验证|身份验证|双因素|二次验证|多因素|杀毒|防火墙|沙箱|审计|安全检测)"),
    ("off.zh_exploit", OFFENSIVE, 0.9, r"漏洞利用|利用漏洞|编写(?:漏洞)?利用(?:代码|脚本|程序)|0day"),
)
_COMPILED = tuple((rid, cat, weight, re.compile(rx)) for rid, cat, weight, rx in _RAW_PATTERNS)

# Tool or operation tokens that identify offensive capabilities, independent of text.
OFFENSIVE_TOOL_TOKENS = frozenset(
    {"exploit", "exploits", "malware", "ransomware", "keylogger", "rootkit", "c2", "phishing",
     "ddos", "bruteforce", "privesc", "portscan", "sqli", "offensive"}
)
_OFFENSIVE_TOOL_SUBSTRINGS = ("credential_dump", "port_scan", "brute_force", "privilege_escalation")

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_SEPARATORS = re.compile(r"[\s\-_.*|/\\,;:'\"`~+]+")
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


@dataclass(frozen=True)
class Signal:
    category: str
    rule_id: str
    weight: float
    source: str


def normalize(text: str) -> str:
    """NFKC, strip zero-width characters, casefold and collapse whitespace."""
    cleaned = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    return re.sub(r"\s+", " ", cleaned.casefold()).strip()


def _variants(text: str) -> list[str]:
    nfkc = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    norm = normalize(nfkc)
    variants = [norm]
    compact = _SEPARATORS.sub("", norm)
    if compact != norm:
        variants.append(compact)
    # One level of base64 decoding. Decode from the case-preserved text.
    for match in list(_BASE64_TOKEN.finditer(nfkc))[:5]:
        token = match.group(0).rstrip("=")
        token += "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        dnorm = normalize(decoded)
        variants.append(dnorm)
        dcompact = _SEPARATORS.sub("", dnorm)
        if dcompact != dnorm:
            variants.append(dcompact)
    return variants


def tool_is_offensive(tool: str, operation: str) -> bool:
    """Capability taxonomy check on tool and operation names."""
    joined = f"{tool}.{operation}".lower()
    tokens = set(re.split(r"[._:\-\s]+", joined))
    return bool(tokens & OFFENSIVE_TOOL_TOKENS) or any(s in joined for s in _OFFENSIVE_TOOL_SUBSTRINGS)


def categories(signals: Iterable[Signal]) -> tuple[str, ...]:
    return tuple(sorted({s.category for s in signals}))


class Guardrails:
    """Screens text and decides whether signals must block an operation."""

    def __init__(self, mode: str = "enforce", threshold: float = DEFAULT_THRESHOLD) -> None:
        if mode not in ("monitor", "enforce"):
            raise ValueError("mode must be 'monitor' or 'enforce'")
        self._mode = mode
        self._threshold = threshold

    @property
    def mode(self) -> str:
        return self._mode

    def screen(self, text: str, source: str) -> tuple[Signal, ...]:
        """Return one signal per matched rule. Text itself is never returned."""
        if not isinstance(text, str) or not text:
            return ()
        seen: set[str] = set()
        out: list[Signal] = []
        for variant in _variants(text):
            for rule_id, category, weight, pattern in _COMPILED:
                if rule_id in seen:
                    continue
                if pattern.search(variant):
                    seen.add(rule_id)
                    out.append(Signal(category, rule_id, weight, source))
        return tuple(out)

    @staticmethod
    def score(signals: Iterable[Signal], category: str) -> float:
        weights = sorted((s.weight for s in signals if s.category == category), reverse=True)
        if not weights:
            return 0.0
        return min(1.0, weights[0] + 0.05 * (len(weights) - 1))

    def blocking_reason(self, signals: Iterable[Signal], operation: str) -> str | None:
        """Return the reason code that must block this operation, or None."""
        signals = tuple(signals)
        if self.score(signals, OFFENSIVE) >= self._threshold:
            return REASON_OFFENSIVE_BLOCKED
        if self._mode != "enforce" or operation in READ_ONLY_OPERATIONS:
            return None
        if self.score(signals, JAILBREAK) >= self._threshold:
            return REASON_JAILBREAK_BLOCKED
        if self.score(signals, PROMPT_INJECTION) >= self._threshold:
            return REASON_INJECTION_BLOCKED
        return None


# ------------------------------------------------------------------ output DLP

_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("CREDENTIAL", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*\S+")),
    ("CN_ID_CARD", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
)
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    double = False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def redact_output(text: str) -> tuple[str, dict[str, int]]:
    """Redact secrets and personal identifiers from model output.

    Returns the redacted text and a count per category.
    """
    counts: dict[str, int] = {}
    out = text
    for name, pattern in _SECRET_RULES:
        def repl(match: re.Match[str], name: str = name) -> str:
            counts[name] = counts.get(name, 0) + 1
            return f"[REDACTED:{name}]"

        out = pattern.sub(repl, out)

    def card_repl(match: re.Match[str]) -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            counts["CARD_NUMBER"] = counts.get("CARD_NUMBER", 0) + 1
            return "[REDACTED:CARD_NUMBER]"
        return match.group(0)

    out = _CARD_CANDIDATE.sub(card_repl, out)
    return out, counts
