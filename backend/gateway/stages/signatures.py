"""Stage 1: deterministic signature engine.

Fast regex rules for known injection, jailbreak and exfiltration phrasings,
plus *operation detection* (delete / drop / export / escalate ...).

Operation matches are not verdicts. "Delete the employee database" is only
blocked if policy says this principal may not do that, which the policy
engine decides. Injection and jailbreak matches are verdicts.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..models import Finding, Severity, StageResult
from .normalizer import NormalizedText

STAGE = "signatures"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    message: str


def R(id: str, category: str, sev: Severity, rx: str, msg: str) -> Rule:
    return Rule(id, category, sev, re.compile(rx, re.I | re.S), msg)


H, C, M, L = Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM, Severity.LOW

_PREV = r"(?:all\s+|any\s+|the\s+|your\s+|my\s+|these\s+|those\s+)*(?:previous|prior|above|earlier|preceding|original|initial|system|existing|current)?\s*"
_INSTR = r"(?:instructions?|directions?|prompts?|rules?|directives?|guidelines?|guardrails?|constraints?|polic(?:y|ies)|programming|context|orders|commands)"

RULES: list[Rule] = [
    # ---------------- A. direct prompt injection ----------------
    R("INJ_IGNORE_PREVIOUS", "direct_injection", C,
      rf"\b(?:ignore|disregard|forget|skip|bypass|override|overrule|discard|drop|abandon|neglect)\b\s+{_PREV}{_INSTR}",
      "instruction-override phrase"),
    R("INJ_NEW_INSTRUCTIONS", "direct_injection", H,
      r"\b(?:new|updated|real|actual|revised|true)\s+(?:system\s+)?instructions?\s*(?::|are|follow)",
      "attempt to install replacement instructions"),
    R("INJ_FROM_NOW_ON", "direct_injection", H,
      r"\bfrom\s+now\s+on\b.{0,40}\b(?:you\s+(?:will|must|are|shall)|ignore|respond|answer|act)\b",
      "persistent behaviour override"),
    R("INJ_FAKE_ROLE_TAG", "direct_injection", H,
      r"(?:^|\n)\s*(?:\[\s*(?:system|admin|developer)\s*\]|<\|?\s*(?:system|im_start|im_end|endoftext)\s*\|?>|###\s*(?:system|instruction)s?\s*:?|system\s*:\s*you\s+are)",
      "forged system/role delimiter"),
    R("INJ_DO_NOT_FOLLOW", "direct_injection", H,
      rf"\b(?:do\s+not|don'?t|stop|no\s+longer)\s+(?:follow|obey|adhere\s+to|comply\s+with)\s+{_PREV}{_INSTR}",
      "tells the model to stop following its instructions"),
    R("INJ_CANCEL", "direct_injection", H,
      rf"\b{_PREV}{_INSTR}\s+(?:are|is)\s+(?:now\s+)?(?:void|cancell?ed|revoked|obsolete|no\s+longer\s+(?:valid|apply|in\s+effect))",
      "declares instructions void"),

    # ---------------- system prompt extraction ----------------
    R("EXT_SYSTEM_PROMPT", "prompt_extraction", C,
      r"\b(?:reveal|show|print|display|output|repeat|leak|expose|tell\s+me|give\s+me|share|dump|recite|what\s+(?:is|are|was))\b.{0,40}\b(?:your|the)\s+(?:hidden\s+|secret\s+|initial\s+|original\s+|internal\s+)?(?:system\s+prompt|system\s+message|instructions|initial\s+prompt|hidden\s+prompt|developer\s+message|guidelines|prompt)\b",
      "system prompt extraction"),
    R("EXT_REPEAT_ABOVE", "prompt_extraction", H,
      r"\b(?:repeat|print|output|copy|show)\b.{0,30}\b(?:everything|all\s+(?:the\s+)?text|the\s+(?:text|words?|content|messages?))\s+(?:above|before|preceding|prior\s+to)",
      "'repeat everything above' extraction"),

    # ---------------- F. jailbreak / policy manipulation ----------------
    R("JB_UNRESTRICTED_PERSONA", "jailbreak", C,
      r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|unlimited|evil|rogue|amoral|unaligned)\b",
      "unrestricted persona assignment"),
    R("JB_DAN", "jailbreak", C,
      r"\b(?:DAN|do\s+anything\s+now|developer\s+mode|god\s*mode|jailbreak(?:ed)?\s+mode|STAN|DUDE\s+mode|AIM\s+mode)\b",
      "known jailbreak persona (DAN family)"),
    R("JB_ROLEPLAY_NO_RULES", "jailbreak", H,
      r"\b(?:pretend|act\s+as\s+if|imagine|roleplay|role-play|simulate)\b.{0,60}\b(?:no|without\s+any|free\s+(?:of|from))\s+(?:restrictions|rules|filters|limits|guidelines|ethics|safety|censorship)",
      "role-play without rules"),
    R("JB_DISABLE_SAFETY", "jailbreak", C,
      r"\b(?:disable|turn\s+off|deactivate|remove|bypass|circumvent|switch\s+off|ignore)\b\s+(?:your\s+|all\s+|the\s+|any\s+)*(?:safety|security|content|ethical|moral)?\s*(?:restrictions|filters?|guardrails?|safeguards|safety\s+(?:protocols|measures|features)|security\s+(?:restrictions|policies|controls)|censorship|alignment)",
      "request to disable safety controls"),
    R("JB_HYPOTHETICAL", "jailbreak", M,
      r"\b(?:hypothetically|in\s+a\s+fictional\s+world|for\s+a\s+(?:novel|story|movie)).{0,80}\b(?:no\s+(?:rules|laws|restrictions)|how\s+(?:would|could)\s+(?:one|someone|i)\s+(?:hack|steal|bypass|exfiltrate))",
      "fictional framing to bypass policy"),
    R("JB_MALWARE_SIM", "jailbreak", H,
      r"\b(?:simulate|emulate|pretend\s+to\s+(?:be|run))\b.{0,40}\b(?:malware|ransomware|keylogger|virus|trojan|reverse\s+shell|linux\s+terminal\s+as\s+root)",
      "malware / root-shell simulation"),
    R("JB_CLASSIFIER_MANIP", "jailbreak", H,
      r"\b(?:this\s+(?:prompt|message|request)\s+is\s+(?:safe|benign|harmless|approved|authorized)|(?:classify|mark|label|rate)\s+this\s+(?:as\s+)?(?:safe|benign|harmless)|security\s+(?:check|scanner|classifier)\s+(?:has\s+)?(?:approved|passed|cleared))",
      "attempt to manipulate the safety classifier"),
    R("JB_AUTHORITY_CLAIM", "jailbreak", M,
      r"\b(?:i\s+am|i'm|this\s+is)\s+(?:your|the|an?)\s+(?:developer|creator|administrator|admin|owner|openai|anthropic|security\s+team)\b.{0,60}\b(?:authori[sz]e|allow|permit|override|grant|unlock|disable)",
      "false authority claim used to unlock behaviour"),

    # ---------------- persona and extraction tricks ----------------
    R("JB_PERSONA_NO_REFUSAL", "jailbreak", H,
      r"\byou\s+are\s+(?:now\s+)?['\"]?[A-Z]?\w+['\"]?,?\s+(?:an?\s+)?(?:\w+\s+){0,4}?(?:who|which|that)\s+(?:answers\s+anything|never\s+refuses|has\s+no\s+(?:rules|limits|filters)|can\s+do\s+anything|ignores)"
      r"|\b(?:\w+\s+)?never\s+refuses\b|\beven\s+(?:things|what)\s+(?:your|its|his|her)\s+(?:creators|developers|makers|rules)\s+(?:told|say|said)",
      "persona set up to never refuse"),
    R("JB_UNRESTRICTED_AI_VOICE", "jailbreak", H,
      r"\b(?:an?\s+)?(?:ai|assistant|model|chatbot|bot)\s+(?:with\s+no|without\s+(?:any\s+)?)\s*(?:guidelines|rules|restrictions|filters|limits|ethics|safety)\b",
      "asks for the voice of an unrestricted AI"),
    R("EXT_ACROSTIC", "prompt_extraction", C,
      r"\b(?:first|last)\s+(?:letter|word|character)s?\s+of\s+(?:each|every)\s+(?:line|sentence|word|paragraph)\b.{0,40}\b(?:spell|form|encode|contain)",
      "acrostic / steganographic prompt extraction"),
    R("EXT_TRANSFORM_PROMPT", "prompt_extraction", H,
      r"\b(?:translate|summari[sz]e|paraphrase|rewrite|encode|convert|list|tabulate|describe)\b.{0,30}\byour\s+(?:own\s+)?(?:initial\s+|original\s+|system\s+|hidden\s+|full\s+)?(?:instructions|configuration|rules|system\s+prompt|prompt|directives)\b",
      "asks to transform its own instructions (indirect extraction)"),
    R("EXT_TOLD_BEFORE", "prompt_extraction", H,
      r"\bwhat\s+were\s+you\s+(?:told|instructed|given)\b|\b(?:its|your)\s+(?:full\s+|entire\s+|complete\s+)?system\s+prompt\b.{0,30}\b(?:word\s+for\s+word|verbatim|exactly|in\s+full)"
      r"|\b(?:reads?|recites?|reveals?|prints?)\s+(?:out\s+)?(?:its|their)\s+(?:full\s+|entire\s+)?(?:system\s+prompt|instructions)",
      "asks what the model was told before the conversation"),

    # ---------------- non-English overrides (stopgap) ----------------
    # The DeBERTa model is English-focused. These cover the most common phrasings in a few
    # languages; a multilingual classifier is the real fix (see README, "Known limitations").
    R("INJ_MULTILINGUAL_OVERRIDE", "direct_injection", H,
      r"\b(?:ignor(?:ez|e|a|iere|eer)|oubliez|olvida|vergiss|negeer|dimentica|esque[cç]a)\b.{0,30}"
      r"\b(?:instructions?|instrucciones|instru[cç][õo]es|istruzioni|anweisungen|instructies|consignes|r[eè]gles|regeln|reglas)\b"
      r"|(?:निर्देशों|निर्देश).{0,20}(?:अनदेखा|भूल)",
      "instruction override in another language"),
    R("EXT_MULTILINGUAL_PROMPT", "prompt_extraction", H,
      r"\b(?:prompt\s+(?:syst[eè]me|del\s+sistema|di\s+sistema|do\s+sistema)|systemprompt|systeemprompt|system-?prompt)\b|सिस्टम\s*प्रॉम्प्ट",
      "system prompt mentioned in another language"),

    # ---------------- B. indirect injection markers (mainly in documents) ----------------
    R("IND_SYSTEM_OVERRIDE", "indirect_injection", C,
      r"\b(?:system|admin|security|emergency|priority)\s+(?:override|update|notice|instruction|command|directive)\s*[:!]",
      "embedded override banner"),
    R("IND_ADDRESS_AI", "indirect_injection", H,
      r"\b(?:attention|note\s+to|instructions?\s+for|message\s+for|dear|hey|hello)\s*,?\s*(?:the\s+)?(?:ai|assistant|chatbot|llm|language\s+model|agent|copilot|gpt|claude|model)\b",
      "text addressed to the AI rather than the reader"),
    R("IND_IGNORE_REQUEST", "indirect_injection", C,
      r"\b(?:ignore|disregard|forget)\s+(?:the\s+)?(?:user'?s?|original|initial|actual|above)\s+(?:request|question|query|task|prompt)",
      "tells the model to drop the user's request"),
    R("IND_INSTEAD_DO", "indirect_injection", H,
      r"\b(?:instead|rather)\s*,?\s+(?:you\s+(?:must|should|will)\s+|please\s+)?(?:retrieve|send|forward|email|export|collect|output|reply\s+with|respond\s+with|call|execute|run)\b",
      "redirects the model to another task"),
    R("IND_WHEN_SUMMARIZING", "indirect_injection", H,
      r"\b(?:when|if|while)\s+(?:you\s+are\s+)?(?:summari[sz]ing|reading|processing|asked\s+about|answering)\b.{0,60}\b(?:you\s+must|always|instead|also|make\s+sure\s+to|include|append|send)\b",
      "conditional instruction planted for the model"),
    R("IND_HIDDEN_FROM_USER", "indirect_injection", C,
      r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\s+(?:this\s+to\s+)?(?:the\s+)?(?:user|human|employee|reader|anyone)",
      "asks the model to hide actions from the user"),
    R("IND_TOOL_INVOCATION", "indirect_injection", H,
      r"\b(?:call|invoke|use|execute|run|trigger)\s+(?:the\s+)?(?:tool|function|api|plugin|action)\s*[`'\"]?\w+",
      "document tries to invoke a tool"),
    R("IND_MD_IMAGE_EXFIL", "exfiltration", C,
      r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*(?:\{|%7B|data=|q=|secret|token|key|d=)",
      "markdown image beacon used to exfiltrate data"),

    # ---------------- C. dangerous operational commands (policy-evaluated) ----------------
    R("OP_DESTRUCTIVE_BULK", "op_destructive", H,
      r"\b(?:delete|remove|erase|wipe|purge|destroy|truncate|drop)\b\s+(?:all|every|each|the\s+entire|entire|whole|the\s+whole)\b.{0,40}\b(?:records?|rows?|data|database|db|tables?|customers?|employees?|users?|accounts?|files?|logs?|backups?)",
      "bulk destructive operation"),
    R("OP_DROP_DB", "op_destructive", C,
      r"\b(?:drop|truncate|delete|destroy|wipe)\s+(?:the\s+)?(?:\w+\s+)?(?:database|db|table|schema|collection|bucket)\b",
      "drop/truncate database object"),
    R("OP_SQL_DESTRUCTIVE", "op_destructive", C,
      r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*(?:;|$)|rm\s+-rf\s+/|format\s+c:)",
      "raw destructive SQL / shell"),
    R("OP_SENSITIVE_MODIFY", "op_sensitive_modification", H,
      r"\b(?:modify|change|update|alter|edit|set|increase|decrease|raise)\b.{0,30}\b(?:payroll|salary|salaries|compensation|bank\s+(?:details|account)|ifsc|tax\s+details|bonus(?:es)?|wage)",
      "sensitive financial/HR modification"),
    R("OP_SECURITY_BYPASS", "op_security_bypass", C,
      r"\b(?:disable|turn\s+off|stop|delete|clear|wipe|bypass|tamper\s+with)\b.{0,20}\b(?:audit\s+(?:log(?:ging|s)?|trail)|logging|monitoring|siem|alert(?:s|ing)?|firewall|antivirus|edr|mfa|2fa|two-factor)",
      "security control bypass"),
    R("OP_PRIV_ESC", "op_privilege_escalation", C,
      r"\b(?:create|add|make|grant|give|promote|elevate|assign)\b.{0,30}\b(?:admin(?:istrator)?|root|superuser|sudo|owner|domain\s+admin)\b.{0,20}(?:account|user|access|rights|privileges?|role|permissions?)?",
      "privilege escalation"),
    R("OP_EXFIL_EXPORT", "op_data_exfiltration", H,
      r"\b(?:export|dump|download|extract|copy|scrape|pull|retrieve|collect|list)\b\s+(?:all|every|the\s+(?:entire|whole|full|complete)|entire|full|complete)\b.{0,50}\b(?:customers?|employees?|users?|records?|data(?:base)?|financial|payroll|salar(?:y|ies)|pii|personal|credit\s+cards?|accounts?|passwords?|credentials)",
      "bulk data extraction"),
    R("OP_EXFIL_SEND_EXTERNAL", "op_data_exfiltration", C,
      r"\b(?:send|email|e-mail|forward|upload|post|transfer|share|leak|mail|transmit)\b.{0,80}\b(?:to\s+)?(?:[\w.+-]+@(?!acme\.(?:com|internal)\b)[\w-]+\.[\w.]+|https?://(?!(?:[\w-]+\.)*acme\.(?:com|internal)\b)\S+|external(?:ly)?|outside\s+(?:the\s+)?(?:company|organi[sz]ation)|personal\s+(?:email|gmail|account)|pastebin|webhook|third[\s-]party)",
      "send data to an external destination"),
    R("OP_CREDENTIALS", "op_data_exfiltration", H,
      r"\b(?:show|give|list|dump|reveal|print|send|export)\b.{0,30}\b(?:passwords?|credentials|api\s+keys?|secret\s+keys?|access\s+tokens?|private\s+keys?|ssh\s+keys?|connection\s+strings?)\b",
      "credential harvesting"),
]

# Letters-only rules for the "compact" view (character-split attacks lose word boundaries)
COMPACT_RULES: list[Rule] = [
    R("CMP_IGNORE_PREVIOUS", "direct_injection", C, r"(?:ignore|disregard|forget)(?:all|any|the|your)*(?:previous|prior|above|earlier)(?:instruction|direction|rule|prompt)", "split-letter instruction override"),
    R("CMP_SYSTEM_PROMPT", "prompt_extraction", C, r"(?:reveal|show|print|repeat|leak)\w{0,40}(?:systemprompt|systemmessage|everythingabove|initialinstructions)", "split-letter prompt extraction"),
    R("CMP_JAILBREAK", "jailbreak", C, r"(?:youarenow(?:an?)?(?:unrestricted|unfiltered|dan)|developermode|doanythingnow|disable(?:your|all)*(?:safety|security)(?:restrictions|filters))", "split-letter jailbreak"),
]

# Questions *about* an operation ("how do I change my bank account?") are not commands.
INFO_QUESTION = re.compile(
    r"^\s*(?:what(?:'s|\s+is|\s+are|\s+does|\s+do)?|how\s+(?:do|does|can|should|to)|why|when|where|which|who|is|are|does|explain|describe|tell\s+me\s+about)\b",
    re.I)

OP_CATEGORIES = {
    "op_destructive", "op_sensitive_modification", "op_security_bypass",
    "op_privilege_escalation", "op_data_exfiltration",
}
ATTACK_CATEGORIES = {"direct_injection", "prompt_extraction", "jailbreak", "indirect_injection", "exfiltration"}


def _snippet(text: str, m: re.Match, pad: int = 25) -> str:
    s = max(0, m.start() - pad)
    e = min(len(text), m.end() + pad)
    return ("…" if s else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


def scan(norm: NormalizedText, *, stage_name: str = STAGE) -> StageResult:
    t0 = time.perf_counter()
    findings: list[Finding] = []
    hit_ids: set[str] = set()
    info_question = bool(INFO_QUESTION.search(norm.normalized)) and len(norm.normalized) < 300
    for view_name, text in norm.all_views():
        for rule in (COMPACT_RULES if view_name == "compact" else RULES):
            if rule.id in hit_ids:
                continue
            m = rule.pattern.search(text)
            if m:
                hit_ids.add(rule.id)
                sev = rule.severity
                if rule.category in OP_CATEGORIES and info_question and view_name == "normalized":
                    findings.append(Finding(stage=stage_name, category="op_question", rule_id=rule.id, severity=Severity.LOW,
                                            message=rule.message + " (asked as a question, not a command)",
                                            evidence=_snippet(text, m)[:160], view=view_name))
                    continue
                # an attack hidden behind an encoding/obfuscation is more suspicious, not less
                if view_name != "normalized" and rule.category in ATTACK_CATEGORIES and sev != Severity.CRITICAL:
                    sev = Severity.CRITICAL if sev == Severity.HIGH else Severity.HIGH
                findings.append(Finding(
                    stage=stage_name, category=rule.category, rule_id=rule.id, severity=sev,
                    message=rule.message + ("" if view_name == "normalized" else f" (found in {view_name} view)"),
                    evidence=_snippet(text, m)[:160], view=view_name,
                ))
    attack = [f for f in findings if f.category in ATTACK_CATEGORIES]
    risk = max((f.severity.weight for f in attack), default=0.0)
    # operations alone carry moderate risk; policy decides whether they are allowed
    ops = [f for f in findings if f.category in OP_CATEGORIES]
    if ops:
        risk = max(risk, 0.5)
    if len(attack) >= 2:
        risk = min(1.0, risk + 0.1)
    return StageResult(
        name=stage_name, risk=round(risk, 3), findings=findings,
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        details={"rules_evaluated": len(RULES), "views_scanned": [v for v, _ in norm.all_views()],
                 "operations": sorted({f.category for f in ops})},
    )
