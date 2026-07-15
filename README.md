# Cloakr

**Deterministic, reversible, multilingual PII tokenization for [Hermes Agent](https://github.com/NousResearch/hermes-agent).**

Check your PII at the door. Cloakr swaps real personal data — names, addresses, phones,
e-mails, cards, ids — for stable tokens **before** anything reaches the model, and reclaims the
real values **after**, in the final message. The answer is complete, but the model never sees a
single piece of personal data. Substitution is pure, deterministic code: no ML, no network, no
second LLM call.

```
tool result:   Jan Novák · jan.novak@example.com · +420 601 111 222 · order 80-5550001234
model sees:    ⟦PII_NAME_1⟧ · ⟦PII_EMAIL_2⟧ · ⟦PII_PHONE_3⟧ · order 80-5550001234
user gets:     Jan Novák · jan.novak@example.com · +420 601 111 222 · order 80-5550001234
```

Order and tracking numbers stay visible — they aren't PII. Czech, 日本語, العربية and кирилиця
names are masked identically, because detection doesn't depend on the language.

## What it does

Cloakr registers three Hermes hooks:

| Hook | Direction | Action |
|---|---|---|
| `transform_tool_result` | in | mask PII in MCP-tool output before the model context |
| `transform_terminal_output` | in | mask PII in shell / DB output (the terminal tool) |
| `transform_llm_output` | out | restore the real values in the model's final message |

Masked values are held in a bounded, in-process vault keyed by the value, so the same input
always yields the same token (stable across a session) and nothing leaves the machine.

## Detection — three tiers, enable what you need

| Tier | Catches | Languages | Deps |
|---|---|---|---|
| **1 · Source tags** | anything your data layer knows is PII (`NAME`, `ADDRESS`, `PHONE`, …) | **all** — script-agnostic | none |
| **2 · Regex packs** | e-mail, IBAN, card (Luhn-gated), IPv4/IPv6, MAC, ETH, BTC, international phone; opt-in per-locale national phone/id packs | per locale | none |
| **3 · NER backend** | untagged free-text names/places | model-bound (Presidio / GLiNER) | opt-in |

Tier 1 is where Cloakr differs from NER-based redactors: instead of *guessing* PII in text
(which is unreliable on non-English names and transliterations), your tools **tag** the fields
they already know are PII. Exact, not probabilistic — and multilingual for free.

## Install

```bash
# as a Hermes plugin (recommended)
hermes plugins install patrikherak/cloakr --enable

# or via pip (auto-discovered on next start)
pip install cloakr

# or manually: drop this repo into ~/.hermes/plugins/cloakr and enable it
```

Enable/disable later with `hermes plugins enable cloakr` / `hermes plugins disable cloakr`, or in
`~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - cloakr
```

## Configure

All configuration is via environment variables (sensible defaults; nothing required):

| Env var | Default | Effect |
|---|---|---|
| `CLOAKR_SOURCE_TAGS` | `true` | honor `tag()` markers from your tools (Tier 1) |
| `CLOAKR_ENTITIES` | all universal except `CREDIT_CARD` | comma-list of regex entities to mask (Tier 2) |
| `CLOAKR_LOCALES` | *(none)* | comma-list of locale packs, e.g. `cz,sk,de,us,in,br` |
| `CLOAKR_TOKEN_FORMAT` | `⟦PII_{kind}_{n}⟧` | token template the model sees |
| `CLOAKR_MAX_VALUES` | `5000` | vault size cap (LRU) |

Credit-card masking is opt-in (`CLOAKR_ENTITIES=...,credit_card`) — it's the one entity whose
length overlaps tracking/order numbers, and even then a Luhn check guards it.

### Tag PII at the source (Tier 1)

In your own query tool / DB wrapper, wrap the columns you *know* are PII. Language never enters
into it:

```python
from cloakr import tag

row = {
    "order":   "80-5550001234",              # kept — not PII
    "name":    tag("NAME", customer.name),   # 田中太郎, Řehoř Žížala, محمد — all masked
    "email":   tag("EMAIL", customer.email),
    "address": tag("ADDRESS", format_address(customer)),
}
```

`tag()` wraps the value in `U+E000 … U+E001` markers that Cloakr tokenizes at the hook boundary
and strips from the model's view entirely.

**Tell the model about placeholders.** Add a line to your agent's system prompt so it passes
tokens through verbatim instead of treating them as missing data:

> Some values arrive as placeholders like `⟦PII_EMAIL_1⟧` — they stand for real data shielded
> from you on purpose. Keep them verbatim in your reply; they are restored before the user sees
> them. Never say a value is missing or alter a placeholder.

## What it does **not** mask

Non-PII passes through untouched — order numbers, tracking numbers, UUIDs, SHA-256 hashes, ISO
dates, prices, ISBNs, versions, hex colors. The regex net is deliberately conservative: phone
matching requires an international `+country` prefix (national formats are left to Tier-1 tags),
and cards require a valid Luhn — so a 14-digit tracking number is never mistaken for a card.

**One honest limit:** a token is opaque, so the model can't paste a value *into* a follow-up
tool call. Guide it to filter in the same query (a subquery), or add an upstream
`transform_tool_args` hook to de-tokenize arguments for cross-tool chaining.

## How it works

`cloakr.py` is a single, dependency-free module (`Cloakr` engine + `tag()` + `register()`). The
plugin's `register(ctx)` builds one `Cloakr` from the env config and wires `mask` onto the two
input hooks and `restore` onto the output hook. That's the whole plugin.

## Files

```
cloakr/
├─ plugin.yaml          manifest (name, hooks)
├─ __init__.py          re-exports register() for the Hermes loader
├─ cloakr.py            the engine: mask / restore / vault, tag(), regex packs, register()
├─ tests/test_cloakr.py the test stack (89 cases; python3 tests/test_cloakr.py)
├─ pyproject.toml       pip packaging + entry point (hermes_agent.plugins)
└─ LICENSE              MIT
```

## Development

```bash
python3 tests/test_cloakr.py
```

The suite proves masking + lossless round-trip across 21 scripts/languages (Czech, German,
French, Vietnamese, Russian, Ukrainian, Greek, Chinese, Japanese, Korean, Arabic, Hebrew, Thai,
Hindi, …), every entity type, opt-in locale packs, false-positive safety (tracking/order numbers
survive), the Luhn gate, token stability, and vault eviction. **All test data is synthetic** —
generic placeholder names, `example.*` domains, and public test vectors; nothing real.

## License

MIT © 2026 Patrik Herák
