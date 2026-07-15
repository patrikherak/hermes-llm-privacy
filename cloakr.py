"""Cloakr — deterministic, reversible, multilingual PII tokenization for LLM agents.

Check your PII at the door: real personal data is swapped for stable tokens BEFORE it reaches
the model, and reclaimed on the way out — so the answer is complete but the model never sees a
name, address, phone, e-mail, card, or id. Substitution is pure, deterministic code; no ML, no
network, no LLM in the loop.

Detection is three tiers (enable what you need):
  1. Source tags  — data tools wrap known-PII fields in U+E000..U+E001 markers via ``tag()``.
                    Language-agnostic and exact — Czech, 日本語, العربية, кирилиця all identical.
  2. Regex packs  — universal structured formats (email, IBAN, card w/ Luhn, IP, MAC, crypto,
                    international phone) + opt-in per-locale packs (national phone / id formats).
  3. NER backend  — optional, opt-in (Presidio / GLiNER) for untagged free-text names/places.

This module is dependency-free (stdlib ``re`` only) and framework-agnostic. As a Hermes plugin it
registers ``mask`` on the input hooks and ``restore`` on the output hook (see ``register``).
"""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from typing import Iterable, Optional

__all__ = ["Cloakr", "tag", "luhn_ok", "register", "D1", "D2"]

# ── Tier 1: source-tag markers (language-agnostic) ─────────────────────────────
D1, D2 = chr(0xE000), chr(0xE001)
_TAG_RE = re.compile(re.escape(D1) + r"([A-Z_]+):(.*?)" + re.escape(D2), re.DOTALL)


def tag(kind: str, value) -> str:
    """Wrap a value your tool KNOWS is PII so Cloakr tokenizes it. Any language, any script."""
    value = "" if value is None else str(value)
    return f"{D1}{kind}:{value}{D2}" if value.strip() else value


# ── Luhn: keep real payment cards, let tracking/order numbers through ───────────
def luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ── Tier 2: universal entity patterns (distinctive formats, negligible FPs) ────
_SP = r"[  .\-]"  # space / nbsp / dot / dash — NOT newline, so matches never span lines

UNIVERSAL: tuple = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")),
    ("MAC", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("IPV6", re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")),
    ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("ETH", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("BTC", re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("SSN_US", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # international phone ONLY (requires +country) — never matches tracking/order numbers:
    ("PHONE", re.compile(r"\+\d(?:" + _SP + r"?\(?\d\)?){6,16}")),
)

# Credit cards get a Luhn gate so we don't tokenize tracking numbers that merely look card-length.
_CARD_CAND = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# ── Optional per-locale packs (opt-in via config.locales) ──────────────────────
# Conservative (require separators / distinctive structure). Bare-digit national ids that
# collide with generic numbers are intentionally left to source-tags.
LOCALES: dict = {
    "cz": [("NID", re.compile(r"\b\d{6}/\d{3,4}\b")),  # rodné číslo
           ("PHONE", re.compile(r"\b(?:00420|\+?420)?[ ]?[67]\d{2}[ ]\d{3}[ ]\d{3}\b"))],
    "sk": [("NID", re.compile(r"\b\d{6}/\d{3,4}\b"))],
    "us": [("PHONE", re.compile(r"\(\d{3}\)[ ]?\d{3}-\d{4}|\b\d{3}-\d{3}-\d{4}\b"))],
    "uk": [("NINO", re.compile(r"\b[ABCEGHJ-PRSTW-Z]{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b"))],
    "de": [("PHONE", re.compile(r"\b0\d{2,4}[ /]\d{5,9}\b"))],
    "fr": [("NIR", re.compile(r"\b[12][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b"))],
    "es": [("DNI", re.compile(r"\b\d{8}-?[A-HJ-NP-TV-Z]\b"))],
    "in": [("AADHAAR", re.compile(r"\b\d{4}[ ]\d{4}[ ]\d{4}\b"))],
    "br": [("CPF", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"))],
}


class Cloakr:
    """A per-process vault + mask/restore. One instance per gateway (each is its own process)."""

    def __init__(
        self,
        entities: Optional[Iterable[str]] = None,
        locales: Optional[Iterable[str]] = None,
        source_tags: bool = True,
        token_format: str = "⟦PII_{kind}_{n}⟧",
        max_values: int = 5000,
    ):
        # Default: all universal patterns EXCEPT credit cards (opt-in — the only entity whose
        # length overlaps tracking/order numbers; a Luhn gate still guards it when enabled).
        wanted = set(e.upper() for e in entities) if entities else {k for k, _ in UNIVERSAL}
        self._patterns = [(k, rx) for k, rx in UNIVERSAL if k in wanted]
        self._cards = "CREDIT_CARD" in wanted
        for loc in (locales or []):
            self._patterns += LOCALES.get(loc.lower(), [])
        self._source_tags = source_tags
        self._fmt = token_format
        self._max = max_values
        self._t2v: "OrderedDict[str, str]" = OrderedDict()
        self._v2t: dict = {}
        self._n = 0

    def _token(self, value: str, kind: str) -> str:
        value = (value or "").strip()
        if not value:
            return value
        tok = self._v2t.get(value)
        if tok is not None:
            self._t2v.move_to_end(tok)
            return tok
        if len(self._t2v) >= self._max:
            old_tok, old_val = self._t2v.popitem(last=False)
            self._v2t.pop(old_val, None)
        self._n += 1
        tok = self._fmt.format(kind=kind, n=self._n)
        self._t2v[tok] = value
        self._v2t[value] = tok
        return tok

    def mask(self, text: str) -> str:
        """Replace PII with tokens (call on the way IN — tool / terminal output)."""
        if not isinstance(text, str) or not text:
            return text
        if self._source_tags:
            text = _TAG_RE.sub(lambda m: self._token(m.group(2), m.group(1)), text)
        for kind, rx in self._patterns:
            text = rx.sub(lambda m, k=kind: self._token(m.group(0), k), text)
        if self._cards:
            text = _CARD_CAND.sub(
                lambda m: self._token(m.group(0), "CREDIT_CARD") if luhn_ok(m.group(0)) else m.group(0),
                text,
            )
        return text

    def restore(self, text: str) -> str:
        """Swap tokens back to the real values (call on the way OUT — final model message)."""
        if not isinstance(text, str) or not text or not self._t2v:
            return text
        for tok, val in list(self._t2v.items()):
            if tok in text:
                text = text.replace(tok, val)
        return text

    @property
    def size(self) -> int:
        return len(self._t2v)


# ── Hermes plugin entry point ──────────────────────────────────────────────────
def _split(value: Optional[str]) -> Optional[list]:
    parts = [x.strip() for x in (value or "").split(",") if x.strip()]
    return parts or None


def register(ctx) -> None:
    """Hermes wires this up. Configure via env: CLOAKR_ENTITIES, CLOAKR_LOCALES,
    CLOAKR_SOURCE_TAGS, CLOAKR_TOKEN_FORMAT, CLOAKR_MAX_VALUES."""
    cr = Cloakr(
        entities=_split(os.getenv("CLOAKR_ENTITIES")),
        locales=_split(os.getenv("CLOAKR_LOCALES")),
        source_tags=os.getenv("CLOAKR_SOURCE_TAGS", "true").lower() not in ("0", "false", "no"),
        token_format=os.getenv("CLOAKR_TOKEN_FORMAT", "⟦PII_{kind}_{n}⟧"),
        max_values=int(os.getenv("CLOAKR_MAX_VALUES", "5000")),
    )

    def _mask(result=None, output=None, **_kw):
        text = result if result is not None else output
        if not isinstance(text, str) or not text:
            return None
        masked = cr.mask(text)
        return masked if masked != text else None

    def _restore(response_text=None, **_kw):
        if not isinstance(response_text, str) or not response_text:
            return None
        restored = cr.restore(response_text)
        return restored if restored != response_text else None

    ctx.register_hook("transform_tool_result", _mask)       # MCP tool output
    ctx.register_hook("transform_terminal_output", _mask)   # shell / DB output
    ctx.register_hook("transform_llm_output", _restore)     # restore in the final message
