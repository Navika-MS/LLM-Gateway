"""Input normalization: turn obfuscated text into views the detectors can read.

Attackers hide instructions with encodings, look-alike characters, invisible
characters, markup and spacing tricks. Instead of guessing which one is used,
we produce several *views* of the input and every detector scans all of them.

Decoding is never a reason to block on its own: decoded content is only
*inspected*. The original text is preserved untouched for the audit trail.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from ..models import Finding, Severity

STAGE = "normalization"

ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎‪‫‬‭‮⁦⁧⁨⁩"),
    None,
)
# Unicode "tag" characters (U+E0000 block) are used to smuggle invisible ASCII.
TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")

# Common Cyrillic / Greek homoglyphs that NFKC does not fold to Latin.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_HTML = re.compile(
    r"<(\w+)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?))[^>]*>(.*?)</\1>",
    re.S | re.I,
)
MD_LINK_TITLE = re.compile(r"\[[^\]]*\]\([^)\s]*\s+\"([^\"]+)\"\)")
MD_REF_COMMENT = re.compile(r"^\s*\[//\]:\s*#\s*\((.*?)\)\s*$", re.M)
HTML_TAG = re.compile(r"<[^>]+>")
B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
B64URL_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-=])([A-Za-z0-9_\-]{20,}={0,2})(?![A-Za-z0-9_\-=])")
HEX_TOKEN = re.compile(r"\b((?:[0-9a-fA-F]{2}){10,})\b")
URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
# "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e"
SPLIT_CHARS = re.compile(r"\b(?:[A-Za-z][\s.\-_*/]{1,3}){3,}[A-Za-z]\b")
MULTISPACE = re.compile(r"[ \t\f\v]+")
MANY_NEWLINES = re.compile(r"\n{3,}")


@dataclass
class NormalizedText:
    original: str
    normalized: str
    views: dict[str, str] = field(default_factory=dict)  # view name -> text
    findings: list[Finding] = field(default_factory=list)
    flags: dict[str, int] = field(default_factory=dict)

    def all_views(self) -> list[tuple[str, str]]:
        return [("normalized", self.normalized), *self.views.items()]


_COMMON_WORDS = {"the", "and", "all", "you", "your", "to", "of", "a", "is", "me", "tell", "previous", "instructions",
                 "ignore", "system", "prompt", "reveal", "password", "admin", "show", "give", "now", "are", "with"}


def _english_score(s: str) -> int:
    return sum(1 for w in re.findall(r"[a-z]+", s.lower()) if w in _COMMON_WORDS)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _looks_like_text(s: str) -> bool:
    # decoded payload must be mostly printable and contain real words
    return len(s) >= 6 and _printable_ratio(s) > 0.9 and bool(re.search(r"[A-Za-z]{3,}", s)) and " " in s.strip()


def _try_b64(token: str) -> str | None:
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = decoder(padded)
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(text) or (_printable_ratio(text) == 1.0 and re.fullmatch(r"[A-Za-z0-9+/_\-]{16,}={0,2}", text)):
            return text  # readable text, or another base64 layer to unwrap
    return None


def _decode_layers(text: str, max_depth: int = 3) -> list[tuple[str, str]]:
    """Return [(encoding, decoded_text)] for every decodable segment, recursively."""
    out: list[tuple[str, str]] = []
    frontier = [text]
    for depth in range(max_depth):
        nxt = []
        for t in frontier:
            seen = set()
            for rx, name in ((B64_TOKEN, "base64"), (B64URL_TOKEN, "base64url")):
                for m in rx.finditer(t):
                    tok = m.group(1)
                    if tok in seen or tok.isalpha() and tok.islower():
                        continue  # plain long lowercase words are not base64
                    seen.add(tok)
                    dec = _try_b64(tok)
                    if dec:
                        out.append((name if depth == 0 else f"{name}(layer{depth + 1})", dec))
                        nxt.append(dec)
            for m in HEX_TOKEN.finditer(t):
                try:
                    dec = bytes.fromhex(m.group(1)).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                if _looks_like_text(dec):
                    out.append(("hex", dec))
                    nxt.append(dec)
            for m in URLENC.finditer(t):
                dec = urllib.parse.unquote(m.group(0))
                if dec != m.group(0) and _printable_ratio(dec) > 0.9:
                    out.append(("url_encoded", dec))
                    nxt.append(dec)
        if not nxt:
            break
        frontier = nxt
    return out


def normalize(text: str) -> NormalizedText:
    findings: list[Finding] = []
    flags: dict[str, int] = {}
    views: dict[str, str] = {}

    def flag(rule: str, sev: Severity, msg: str, count: int = 1):
        flags[rule] = flags.get(rule, 0) + count
        findings.append(Finding(stage=STAGE, category="obfuscation", rule_id=rule, severity=sev, message=msg))

    t = text

    # 1. invisible characters
    zw = sum(1 for c in t if ord(c) in ZERO_WIDTH)
    tags = TAG_CHARS.findall(t)
    if tags:
        # tag chars map 1:1 onto ASCII; recover the smuggled text as its own view
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in tags)
        views["unicode_tags_decoded"] = smuggled
        flag("OBF_UNICODE_TAGS", Severity.HIGH, f"{len(tags)} invisible Unicode tag characters (ASCII smuggling)")
        t = TAG_CHARS.sub("", t)
    if zw:
        flag("OBF_ZERO_WIDTH", Severity.MEDIUM if zw > 2 else Severity.LOW, f"{zw} zero-width/bidi control characters removed", zw)
        t = t.translate(ZERO_WIDTH)

    # 2. Unicode compatibility folding (fullwidth, math alphanumerics, ligatures)
    nfkc = unicodedata.normalize("NFKC", t)
    if nfkc != t:
        flag("OBF_UNICODE_COMPAT", Severity.LOW, "Unicode compatibility characters folded (NFKC)")
    t = nfkc

    # 3. homoglyphs: only meaningful when mixed with Latin text
    folded = t.translate(HOMOGLYPHS)
    if folded != t and re.search(r"[A-Za-z]", t):
        n = sum(1 for a, b in zip(t, folded) if a != b)
        flag("OBF_HOMOGLYPH", Severity.MEDIUM if n > 2 else Severity.LOW, f"{n} look-alike Cyrillic/Greek characters mapped to Latin")
        t = folded

    # 4. hidden markup: extract and inspect separately (don't silently drop)
    hidden_parts = [m.strip() for m in HTML_COMMENT.findall(t)]
    hidden_parts += [m[1].strip() for m in HIDDEN_HTML.findall(t)]
    hidden_parts += MD_LINK_TITLE.findall(t) + MD_REF_COMMENT.findall(t)
    hidden_parts = [h for h in hidden_parts if h]
    if hidden_parts:
        views["hidden_markup"] = "\n".join(hidden_parts)
        flag("OBF_HIDDEN_MARKUP", Severity.MEDIUM, f"{len(hidden_parts)} hidden HTML/Markdown segment(s) extracted")
    visible = HTML_COMMENT.sub(" ", t)
    if HTML_TAG.search(visible):
        # keep the un-stripped text as a view: chat-template tokens like <|im_start|> look like tags
        views["raw_markup"] = MULTISPACE.sub(" ", t).strip()
        visible = html.unescape(HTML_TAG.sub(" ", visible))

    # 5. whitespace
    ws_before = len(visible)
    visible = MULTISPACE.sub(" ", visible)
    visible = MANY_NEWLINES.sub("\n\n", visible).strip()
    if ws_before - len(visible) > 200:
        flag("OBF_WHITESPACE_PADDING", Severity.LOW, "excessive whitespace padding collapsed")

    # 6. encodings: decode-and-inspect
    for enc, dec in _decode_layers(visible):
        key = f"{enc}_decoded"
        views[key] = (views.get(key, "") + "\n" + unicodedata.normalize("NFKC", dec).translate(ZERO_WIDTH)).strip()
        flag(f"OBF_ENCODED_{enc.split('(')[0].upper()}", Severity.LOW, f"{enc} payload decoded for inspection")

    # 7. character splitting
    def _join(m: re.Match) -> str:
        return re.sub(r"[\s.\-_*/]+", "", m.group(0))

    despaced = SPLIT_CHARS.sub(_join, visible)
    if despaced != visible:
        views["despaced"] = despaced
        # word boundaries are lost when letters are split, so also keep a letters-only view
        views["compact"] = re.sub(r"[^a-z]", "", despaced.lower())
        flag("OBF_CHAR_SPLIT", Severity.LOW, "character-split words re-joined for inspection")

    # 8. ROT13: only kept when the rotated text reads clearly more like English than the original
    rot = codecs.decode(visible, "rot13")
    if _english_score(rot) >= 3 and _english_score(rot) > 2 * _english_score(visible):
        views["rot13_decoded"] = rot
        flag("OBF_ROT13", Severity.LOW, "ROT13 text decoded for inspection")

    # 9. leetspeak view (cheap; only kept when it changes something)
    leet = visible.lower().translate(LEET)
    if leet != visible.lower() and re.search(r"[a-z][0-9@$!|][a-z]", visible.lower()):
        views["deleet"] = leet

    return NormalizedText(original=text, normalized=visible, views=views, findings=findings, flags=flags)
