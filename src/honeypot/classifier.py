"""Pattern-based prompt-injection classifier.

Each rule maps to a tag from `ATTACK_TAGS`. Rules are compiled once at import
time so classification is fast enough to run on every inbound prompt without
adding latency.

Design notes
------------
* Pure regex + heuristics, no model calls. This is intentional: the classifier
  must be deterministic, inspectable, and auditable.
* Every rule has a *named* pattern so the telemetry can record *which* rule
  fired, not just *that* something matched.
* The classifier NEVER decides what the response should be. It only tags.
  The server.py layer enforces a canned refusal on any non-benign tag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable


class Severity(IntEnum):
    """Ordered severity bucket — higher = more dangerous."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


# Tag strings — keep these stable; they're used as keys in dashboards and
# as the public contract for downstream consumers.
TAG_INSTRUCTION_OVERRIDE = "instruction_override"
TAG_SYSTEM_PROMPT_LEAK = "system_prompt_leak"
TAG_ROLE_HIJACK = "role_hijack"
TAG_JAILBREAK_KEYWORD = "jailbreak_keyword"
TAG_PROMPT_LEAK_SECRETS = "prompt_leak_secrets"
TAG_ENCODING_OBFUSCATION = "encoding_obfuscation"
TAG_TOOL_CALL_EXTRACTION = "tool_call_extraction"
TAG_DELIMITER_SMUGGLE = "delimiter_smuggle"
TAG_BENIGN = "benign"

ATTACK_TAGS = frozenset({
    TAG_INSTRUCTION_OVERRIDE,
    TAG_SYSTEM_PROMPT_LEAK,
    TAG_ROLE_HIJACK,
    TAG_JAILBREAK_KEYWORD,
    TAG_PROMPT_LEAK_SECRETS,
    TAG_ENCODING_OBFUSCATION,
    TAG_TOOL_CALL_EXTRACTION,
    TAG_DELIMITER_SMUGGLE,
})


@dataclass(frozen=True)
class Classification:
    """Result of running `classify()` on one prompt."""

    tags: list[str]
    severity: Severity
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return any(t in ATTACK_TAGS for t in self.tags)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule is (tag, severity_when_alone, regex). Severity is the *floor*
# when this rule matches; the final severity is the max across all matches.

_RULES: list[tuple[str, Severity, re.Pattern[str]]] = [
    # instruction_override
    (TAG_INSTRUCTION_OVERRIDE, Severity.HIGH, re.compile(
        r"\b(ignore|disregard|forget|skip|bypass|override)\b"
        r"[\w\s]{0,30}\b(all|any|the|every|previous|prior|above|preceding|earlier)\b"
        r"[\w\s]{0,20}\b(instructions?|prompts?|rules?|context|directives?|messages?)\b",
        re.IGNORECASE,
    )),
    (TAG_INSTRUCTION_OVERRIDE, Severity.HIGH, re.compile(
        r"\b(ignore|disregard|forget|skip|bypass|override)\b"
        r"[\w\s]{0,30}\b(previous|prior|above|preceding|earlier)\b"
        r"(?![\w\s]{0,5}\b(of|that|when|where)\b)",
        re.IGNORECASE,
    )),
    (TAG_INSTRUCTION_OVERRIDE, Severity.HIGH, re.compile(
        r"\b(do\s+not|don'?t)\s+(follow|obey|listen\s+to|comply\s+with)\b"
        r"[\w\s]{0,20}\b(previous|prior|above|earlier|system)\b",
        re.IGNORECASE,
    )),

    # system_prompt_leak
    (TAG_SYSTEM_PROMPT_LEAK, Severity.HIGH, re.compile(
        r"\b(reveal|show|display|print|output|expose|dump|leak|tell\s+me)\b"
        r"[\w\s]{0,30}\b(system|hidden|internal|original|initial)\b"
        r"[\w\s]{0,20}\b(prompt|rules?|instructions?|directives?|configuration|context)\b",
        re.IGNORECASE,
    )),
    (TAG_SYSTEM_PROMPT_LEAK, Severity.HIGH, re.compile(
        r"\bwhat\s+(were\s+you|are\s+you)\s+(told|given|instructed|programmed)\b",
        re.IGNORECASE,
    )),

    # role_hijack
    (TAG_ROLE_HIJACK, Severity.MEDIUM, re.compile(
        r"\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+to\s+be|"
        r"roleplay\s+as|impersonate)\b"
        r"[\w\s]{0,30}\b(DAN|jailbroken|evil|uncensored|unfiltered|unrestricted|"
        r"without\s+(limits|restrictions|filters|guidelines))\b",
        re.IGNORECASE,
    )),

    # jailbreak_keyword
    (TAG_JAILBREAK_KEYWORD, Severity.MEDIUM, re.compile(
        r"\b(jailbreak|jailbroken|jail\s*break)\b", re.IGNORECASE,
    )),
    (TAG_JAILBREAK_KEYWORD, Severity.MEDIUM, re.compile(
        r"\b(developer\s+mode|god\s+mode|sudo\s+mode|admin\s+mode)\b", re.IGNORECASE,
    )),
    (TAG_JAILBREAK_KEYWORD, Severity.MEDIUM, re.compile(
        r"\bdo\s+anything\s+now\b", re.IGNORECASE,
    )),

    # prompt_leak_secrets
    (TAG_PROMPT_LEAK_SECRETS, Severity.HIGH, re.compile(
        r"\b(SECRET[_\s]?KEY|API[_\s]?KEY|ACCESS[_\s]?TOKEN|PRIVATE[_\s]?KEY|"
        r"ADMIN[_\s]?PASSWORD|DATABASE[_\s]?URL)\b", re.IGNORECASE,
    )),
    (TAG_PROMPT_LEAK_SECRETS, Severity.HIGH, re.compile(
        r"\b(what\s+is|give\s+me|show|reveal|tell)\b"
        r"[\w\s]{0,15}\b(the\s+)?(secret|api\s*key|password|token|credential)\b",
        re.IGNORECASE,
    )),

    # tool_call_extraction
        (TAG_TOOL_CALL_EXTRACTION, Severity.HIGH, re.compile(
            r"\b(call|invoke|execute|run|trigger)\b"
            r"[\w\s]{0,15}\b(the\s+)?"
            r"(get_secret|lookup_secret|fetch_password|read_file|exec|shell|bash)\b",
            re.IGNORECASE,
        )),
        (TAG_TOOL_CALL_EXTRACTION, Severity.HIGH, re.compile(
            r"\b(use|using|call|invoke|invoking|run|running|execute|executing|trigger|triggering)\b"
            r"[\w\s]{0,15}\b(the\s+)?"
            r"(lookup_account|get_account|fetch_secret|admin_tool|debug_tool|dev_tool|"
            r"internal_tool|get_password|read_secret|get_secret|fetch_password|"
            r"lookup_secret|read_file|exec|shell|bash)\s*tool\b",
            re.IGNORECASE,
        )),
        (TAG_TOOL_CALL_EXTRACTION, Severity.HIGH, re.compile(
            r"```[a-zA-Z]+\s*(get_secret|lookup_secret|fetch_password|exec|shell)\b",
            re.IGNORECASE,
        )),

    # delimiter_smuggle
    (TAG_DELIMITER_SMUGGLE, Severity.HIGH, re.compile(
        r"<\|im_(start|end)\|>", re.IGNORECASE,
    )),
    (TAG_DELIMITER_SMUGGLE, Severity.HIGH, re.compile(
        r"\[/?INST\]", re.IGNORECASE,
    )),
    (TAG_DELIMITER_SMUGGLE, Severity.HIGH, re.compile(
        r"###\s*(Instruction|Input|Response|System|Prompt):", re.IGNORECASE,
    )),
    (TAG_DELIMITER_SMUGGLE, Severity.HIGH, re.compile(
        r"<</?(SYSTEM|USER|ASSISTANT|HUMAN|AI)>>", re.IGNORECASE,
    )),

    # encoding_obfuscation — large alphanumeric runs (likely base64 / hex)
    (TAG_ENCODING_OBFUSCATION, Severity.MEDIUM, re.compile(
        r"\b[A-Za-z0-9+/]{200,}\b",
    )),
    (TAG_ENCODING_OBFUSCATION, Severity.MEDIUM, re.compile(
        r"\b[A-Fa-f0-9]{180,}\b",
    )),
]


def _all_rules() -> Iterable[tuple[str, Severity, re.Pattern[str]]]:
    return _RULES


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(message: str) -> Classification:
    """Run every rule against `message` and return a Classification.

    The classifier is intentionally conservative: a single match flips the
    result from "benign" to the matched tag. False positives are preferred
    over false negatives because the worst-case downstream effect is a
    canned refusal — never a leaked secret.
    """
    if not message:
        return Classification(tags=[TAG_BENIGN], severity=Severity.NONE)

    text = message.strip()
    matched_tags: dict[str, Severity] = {}
    matched_patterns: list[str] = []

    for tag, base_severity, pattern in _all_rules():
        m = pattern.search(text)
        if m:
            matched_tags[tag] = max(matched_tags.get(tag, Severity.NONE), base_severity)
            matched_patterns.append(pattern.pattern[:80])

    if not matched_tags:
        return Classification(tags=[TAG_BENIGN], severity=Severity.NONE)

    final_severity = max(matched_tags.values())
    tags = sorted(matched_tags.keys())
    return Classification(
        tags=tags,
        severity=final_severity,
        matched_patterns=matched_patterns,
    )