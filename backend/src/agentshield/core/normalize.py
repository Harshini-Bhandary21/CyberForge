"""Canonicalise untrusted text the way a capable LLM would read it.

The shield must analyse what the model *sees*, not the raw bytes: invisible characters are
dropped, HTML is flattened (hidden text kept), and base64 blobs are decoded and appended.
Detectors and taint attribution both run on this view, so obfuscation does not hide an
attacker's recipient address or command.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

_INVISIBLE = re.compile("[​‌‍⁠﻿­\U000e0000-\U000e007f]")
_TAGS = re.compile(r"<[^>]+>")
_HIDDEN_HTML = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0"
    r"|color\s*:\s*(#fff(?:fff)?\b|white\b))",
    re.I,
)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class Normalized:
    text: str
    invisible_chars: int = 0
    hidden_html: bool = False
    decoded_blobs: list[str] = field(default_factory=list)


def _decode_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    return text if text and printable / len(text) > 0.95 else None


def normalize(text: str) -> Normalized:
    invisible = len(_INVISIBLE.findall(text))
    out = _INVISIBLE.sub("", text)
    hidden = bool(_HIDDEN_HTML.search(out))
    if "<" in out:
        out = html.unescape(_TAGS.sub(" ", out))
    out = unicodedata.normalize("NFKC", out)
    decoded = [d for m in _B64.finditer(out) if (d := _decode_b64(m.group(0)))]
    if decoded:
        out = out + "\n" + "\n".join(decoded)
    return Normalized(
        text=out, invisible_chars=invisible, hidden_html=hidden, decoded_blobs=decoded
    )
