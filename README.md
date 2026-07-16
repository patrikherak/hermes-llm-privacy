# hermes-llm-privacy

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-135%20passing-brightgreen.svg)](tests/test_llm_privacy.py)
[![No dependencies](https://img.shields.io/badge/dependencies-none-lightgrey.svg)](hermes_llm_privacy.py)

**A privacy layer for [Hermes Agent](https://github.com/NousResearch/hermes-agent): deterministic, reversible, multilingual PII tokenization.**

Real personal data — names, addresses, phones, e-mails, cards, national ids — is swapped for
stable tokens **before** anything reaches the model, and the real values are restored **after**,
in the final message. The answer stays complete, but the model never sees a single piece of
personal data. Substitution is pure, deterministic code: no ML, no network, no second LLM call.

```
tool result:   Jan Novák · jan.novak@example.com · +420 601 111 222 · order 80-5550001234
model sees:    ⟦PII_NAME_1⟧ · ⟦PII_EMAIL_2⟧ · ⟦PII_PHONE_3⟧ · order 80-5550001234
user gets:     Jan Novák · jan.novak@example.com · +420 601 111 222 · order 80-5550001234
```

Order and tracking numbers stay visible — they aren't PII. Czech, 日本語, العربية and кирилиця
names are masked identically, because detection doesn't depend on the language.

> Not on Hermes? The same engine is available as an LLM-agnostic Agent Skill:
> **[llm-privacy](https://github.com/patrikherak/llm-privacy)** — works in Claude Code and any
> agent that reads `SKILL.md`.

## How it works

The plugin registers three Hermes hooks around the model:

| Hook | Direction | Action |
|---|---|---|
| `transform_tool_result` | in | mask PII in MCP-tool output before it enters model context |
| `transform_terminal_output` | in | mask PII in shell / DB output (the terminal tool) |
| `transform_llm_output` | out | restore the real values in the model's final message |

Masked values are held in a bounded, in-process vault keyed by value, so the same input always
yields the same token (stable across a session) and nothing ever leaves the machine.

## Detection — three tiers, enable what you need

| Tier | Catches | Languages | Deps |
|---|---|---|---|
| **1 · Source tags** | anything your data layer knows is PII (`NAME`, `ADDRESS`, `PHONE`, …) | **all** — script-agnostic | none |
| **2 · Regex packs** | e-mail, IBAN, card (Luhn-gated), IPv4/IPv6, MAC, ETH, BTC, international phone; opt-in per-locale national phone + national-id packs for **48 countries** | per locale | none |
| **3 · NER backend** | untagged free-text names/places | model-bound (Presidio / GLiNER) | opt-in |

Tier 1 is where this plugin differs from NER-based redactors: instead of *guessing* PII in text
(unreliable on non-English names and transliterations), your tools **tag** the fields they
already know are PII. Exact, not probabilistic — and multilingual for free.

National ids that are bare digit runs (PESEL, CPF, TCKN, Aadhaar, …) are **checksum-gated** — only
a *valid* id masks, never a random number of the same length. Full coverage for all 48 locales,
every entity, and the false-positive characteristics are documented in **[SPECS.md](SPECS.md)**.

## Installation

```bash
# as a Hermes plugin (recommended)
hermes plugins install patrikherak/hermes-llm-privacy --enable

# or via pip (auto-discovered on next start)
pip install hermes-llm-privacy

# or manually: drop this repo into ~/.hermes/plugins/hermes-llm-privacy and enable it
```

Enable/disable later with `hermes plugins enable hermes-llm-privacy` /
`hermes plugins disable hermes-llm-privacy`, or in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - hermes-llm-privacy
```

## Configuration

Everything is configured via environment variables — sensible defaults, nothing required:

| Env var | Default | Effect |
|---|---|---|
| `LLM_PRIVACY_SOURCE_TAGS` | `true` | honor `tag()` markers from your tools (Tier 1) |
| `LLM_PRIVACY_ENTITIES` | all universal except `CREDIT_CARD` | comma-list of regex entities to mask (Tier 2) |
| `LLM_PRIVACY_LOCALES` | *(none)* | comma-list of locale packs, e.g. `cz,sk,de,us,in,br` |
| `LLM_PRIVACY_TOKEN_FORMAT` | `⟦PII_{kind}_{n}⟧` | token template the model sees |
| `LLM_PRIVACY_MAX_VALUES` | `5000` | vault size cap (LRU) |

Credit-card masking is opt-in (`LLM_PRIVACY_ENTITIES=...,credit_card`) — it's the one entity
whose length overlaps tracking/order numbers, and even then a Luhn check guards it.

### Tag PII at the source (Tier 1)

In your own query tool / DB wrapper, wrap the columns you *know* are PII. Language never enters
into it:

```python
from hermes_llm_privacy import tag

row = {
    "order":   "80-5550001234",              # kept — not PII
    "name":    tag("NAME", customer.name),   # 田中太郎, Řehoř Žížala, محمد — all masked
    "email":   tag("EMAIL", customer.email),
    "address": tag("ADDRESS", format_address(customer)),
}
```

`tag()` wraps the value in `U+E000 … U+E001` markers that are tokenized at the hook boundary and
stripped from the model's view entirely.

**Tell the model about placeholders.** Add a line to your agent's system prompt so it passes
tokens through verbatim instead of treating them as missing data:

> Some values arrive as placeholders like `⟦PII_EMAIL_1⟧` — they stand for real data shielded
> from you on purpose. Keep them verbatim in your reply; they are restored before the user sees
> them. Never say a value is missing or alter a placeholder.

## What it does *not* mask

Non-PII passes through untouched — order numbers, tracking numbers, UUIDs, SHA-256 hashes, ISO
dates, prices, ISBNs, versions, hex colors. The regex net is deliberately conservative: phone
matching requires an international `+country` prefix (national formats are left to locale packs
or Tier-1 tags), and cards require a valid Luhn — so a 14-digit tracking number is never mistaken
for a card.

**One honest limit:** a token is opaque, so the model can't paste a real value *into* a follow-up
tool call. Guide it to filter in the same query (a subquery), or add an upstream
`transform_tool_args` hook to de-tokenize arguments for cross-tool chaining.

## Repository layout

```
hermes-llm-privacy/
├─ plugin.yaml                  manifest (name, hooks)
├─ __init__.py                  re-exports register() for the Hermes loader
├─ hermes_llm_privacy.py        the engine: mask/restore vault, tag(), regex packs, checksums, register()
├─ SPECS.md                     full coverage: entities, 48 locales, checksum table, FP notes
├─ tests/test_llm_privacy.py    test stack — 135 cases
├─ pyproject.toml               pip packaging + entry point (hermes_agent.plugins)
└─ LICENSE                      MIT
```

`hermes_llm_privacy.py` is a single dependency-free module (`PrivacyVault` engine + `tag()` +
`register()`). The plugin's `register(ctx)` builds one `PrivacyVault` from the env config and
wires `mask` onto the two input hooks and `restore` onto the output hook. That's the whole plugin.

## Development

```bash
python3 tests/test_llm_privacy.py
```

135 cases prove masking + lossless round-trip across 21 scripts/languages (Czech, German, French,
Vietnamese, Russian, Ukrainian, Greek, Chinese, Japanese, Korean, Arabic, Hebrew, Thai, Hindi, …),
every universal entity, national ids for 16 countries with real checksums (Spanish DNI, Brazilian
CPF/CNPJ, Polish PESEL, Turkish TCKN, Indian Aadhaar/Verhoeff, …) — valid ids mask, bad-checksum
numbers survive — national phone formats, false-positive safety (tracking/order numbers survive),
the Luhn gate, token stability, and vault eviction. **All test data is synthetic** — generic
placeholder names, `example.*` domains, and public test vectors; nothing real.

## Related

- **[llm-privacy](https://github.com/patrikherak/llm-privacy)** — the same engine packaged as an
  LLM-agnostic Agent Skill (`SKILL.md`), usable in Claude Code and any agent that reads skills.
- [Hermes Agent](https://github.com/NousResearch/hermes-agent) — the agent framework this plugin
  targets.

## License

[MIT](LICENSE) © 2026 Patrik Herák
