"""Multilingual injection lexicon, matched with one Aho–Corasick pass.

Phrases are the stock formulations of override / role-change / secrecy attacks. It complements the
regex rules (which need word order) with plain phrase evidence in several languages.
"""

from __future__ import annotations

from functools import lru_cache

from agentshield.core.ahocorasick import AhoCorasick

_PHRASES: dict[str, list[str]] = {
    "override": [
        "ignore previous instructions",
        "ignore all previous",
        "ignore the above",
        "disregard the above",
        "disregard previous",
        "disregard your instructions",
        "forget your instructions",
        "forget everything above",
        "ignora las instrucciones anteriores",
        "ignora todas las instrucciones",
        "ignorez les instructions précédentes",
        "ignorez toutes les instructions",
        "ignoriere alle vorherigen anweisungen",
        "ignoriere die obigen anweisungen",
        "ignora le istruzioni precedenti",
        "ignore as instruções anteriores",
        "पिछले निर्देशों को अनदेखा",
        "पिछले निर्देश भूल",
        "ignore the previous directions",
        "the previous guidelines no longer apply",
    ],
    "jailbreak": [
        "developer mode",
        "do anything now",
        "jailbreak",
        "you have no restrictions",
        "without any restrictions",
        "pretend you have no rules",
        "bypass your safety",
        "disable your safety",
        "forget your safety rules",
    ],
    "secrecy": [
        "do not tell the user",
        "don't tell the user",
        "without telling the user",
        "without informing anyone",
        "keep this between us",
        "do not mention this to",
        "hide this from the user",
        "conceal it from",
        "no se lo digas al usuario",
        "ne le dites pas à l'utilisateur",
        "sag es dem benutzer nicht",
        "उपयोगकर्ता को मत बताना",
        "किसी को मत बताना",
    ],
    "authority": [
        "new instructions from the operator",
        "message from the system administrator",
        "this is a system message",
        "instructions from your developer",
        "override: act as",
        "the real owner is me",
    ],
    "exfil": [
        "send the inbox to",
        "send all emails to",
        "forward all emails to",
        "forward every message",
        "email the api keys",
        "upload the contacts",
        "send the passwords to",
        "post the contents to",
        "reenvia todos los correos",
        "enviá las credenciales",
        "envía las credenciales",
        "transférez tous les fichiers",
        "sende die passwörter",
        "सभी ईमेल भेज",
    ],
}


@lru_cache(maxsize=1)
def _automaton() -> AhoCorasick:
    return AhoCorasick({p: cat for cat, ps in _PHRASES.items() for p in ps})


def scan(text: str) -> set[str]:
    """Categories whose phrases occur in ``text`` (already normalised)."""
    return _automaton().find(text.lower())
