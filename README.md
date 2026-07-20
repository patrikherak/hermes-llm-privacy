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

> ⚠️ **The `NAME`/`ADDRESS` masking above needs wiring — it does not happen on a bare install.**
> Names and addresses have no reliable universal pattern, so they are masked via **source tags**
> (Tier 1): your tools must call `tag()` / emit the markers (see [Tag PII at the source](#tag-pii-at-the-source-tier-1)),
> or you supply them via the **custom-terms** list, or enable a **NER** backend (Tier 3). A fresh
> install with none of those runs **Tier 2 (regex: e-mail, IBAN, phone, IP, card…) + Tier 1.5
> (custom terms)** only — structured PII is caught, but **free-text names/addresses are not**. The
> example above assumes the data layer tags its known-PII columns (the common case for a DB agent).

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

## Detection — layered, enable what you need

| Tier | Catches | Languages | Deps |
|---|---|---|---|
| **1 · Source tags** | anything your data layer knows is PII (`NAME`, `ADDRESS`, `PHONE`, …) | **all** — script-agnostic | none |
| **1.5 · Custom terms** | a caller-supplied wordlist of exact strings — personal names, internal codenames, account handles — inline or from a hot-reloaded file | **all** — literal match | none |
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
| `LLM_PRIVACY_MAX_VALUES` | `5000` | per-session vault size cap (LRU) |
| `LLM_PRIVACY_MAX_SESSIONS` | `200` | concurrent session vaults kept (LRU) |
| `LLM_PRIVACY_TERMS` | *(none)* | comma-list of literal terms to always mask (Tier 1.5) |
| `LLM_PRIVACY_TERMS_FILE` | *(none)* | path to a wordlist file, hot-reloaded on change (Tier 1.5) |
| `LLM_PRIVACY_TERMS_KIND` | `TERM` | default token kind for terms without an explicit one |
| `LLM_PRIVACY_TERMS_IGNORE_CASE` | `true` | match terms case-insensitively (restore stays exact) |

Credit-card masking is opt-in (`LLM_PRIVACY_ENTITIES=...,credit_card`) — it's the one entity
whose length overlaps tracking/order numbers, and even then a Luhn check guards it.

### Mask a custom wordlist (Tier 1.5)

Regex can't know that `Jane Roe` is a person or `PROJECT-ORION` a codename. When your app already
has that list — a roster, a table of account handles, internal project names — point the plugin at
it and every occurrence in tool/terminal output is tokenized before the model sees it:

```bash
export LLM_PRIVACY_TERMS="Widget Alpha,Project Orion"     # inline
export LLM_PRIVACY_TERMS_FILE=/etc/llm-privacy/terms.txt  # or a file (recommended for long lists)
```

The file is one term per line, with an optional `term<TAB>KIND` to control the token label; blank
lines and `#` comments are ignored:

```
# terms.txt — all synthetic
Jane Roe	PERSON
Roe	PERSON
PROJECT-ORION	CODE
acme-internal	ORG
```

- **Longest-first**: `Jane Roe` masks as one token before the bare `Roe` ever matches.
- **Boundary-safe**: `Roe` masks `Roe`, never the `Roe` inside `Roebuck`.
- **Hot-reloaded**: regenerate the file from a cron/job and the change is picked up on the next
  message — no restart. Ideal when the list is refreshed from a database.
- **Lossless**: matching is case-insensitive by default, but the *exact* original text (case and
  all) is restored in the model's final reply.

The list itself never leaves your machine — the plugin only ever reads it locally to build the
matcher; it is not sent anywhere.

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

## Threat model & guarantees

This plugin is **enforced, not advisory**: the hooks run in code at the gateway, between every
tool result and the model — the model *cannot* see the raw values regardless of how it behaves,
what it's told, or whether a jailbreak succeeds. Because masking happens before context, the
values are never sent to the LLM provider and never appear in conversation transcripts; the
vault is in-process and nothing leaves the machine.

**Session isolation:** vaults are per-session — a token minted from a tool result in one
conversation can only be restored in that same conversation, so on a multi-channel gateway
nobody can extract another channel's values by echoing its tokens. Tokens are numbered from a
process-wide counter, so tokens from different sessions can never collide. (Terminal output
carries no session context upstream in Hermes, so terminal-minted tokens live in a shared vault
that restore also consults — single-session gateways are unaffected.)

Honest boundaries:

- **Covered:** MCP tool output and terminal/shell output — the two input hooks
  (`transform_tool_result`, `transform_terminal_output`).
- **Ingress, per-path — not egress.** Masking runs as data *enters* context, per hook. Any tool
  or path that reaches model context **without firing those hooks bypasses masking** — e.g. a
  tool dispatched inline, or a sub-agent whose (already-restored) output is handed to a parent
  agent. Masking at ingress means every new inbound path is a potential new hole. The airtight
  design is to mask at **egress** — one chokepoint just before the request goes to the provider,
  so nothing can bypass by construction. Hermes today exposes only an *observe-only*
  `pre_api_request` hook (used for tracing), so true egress masking needs a mutable pre-send hook
  upstream or an LLM proxy at the network edge. Until then, keep the agent's tool surface narrow
  (every PII-bearing tool must go through one of the two input hooks).
- **After `restore()` the text is real PII again.** `transform_llm_output` is the last hook that
  can change the text; anything downstream of it — auto-title generation, memory storage,
  observability plugins — handles the real values. If auto-title/summarisation calls *another*
  LLM, that call is a fresh provider request (and would itself need masking). The plugin cannot
  reach past the restore hook.
- **Not covered:** text the *user themselves* types into the chat — inbound human messages are
  not intercepted. Don't paste PII at the model and expect the plugin to save you.
- **Nothing retroactive:** the plugin protects from installation onward; whatever entered
  context before it was enabled has already been sent.
- **Turn-N replay is masked** (conversation history is written before `restore()` runs, so stored
  history keeps the tokens) — but that is ordering in the host, not a guarantee this plugin
  enforces; pin it with an integration test in your deployment.
### Egress masking (experimental, opt-in) — closes the ingress gaps

Set `LLM_PRIVACY_EGRESS=1` and the plugin re-masks **tool-result content at the single provider
chokepoint** — so tool output that reached the model via a path that bypassed the input hooks
(inline-dispatched tools, sub-agent output) is masked too, by construction. `tool_use`/`tool_result`
structure and ids are preserved, and already-minted tokens don't re-match (it composes with the
ingress hooks as a safety net).

It deliberately does **not** mask the human's own input: the user must still be able to hand the
model a value (an e-mail, an id) and have it use that value in a tool call — masking user input
would tokenize it and break value-passing. So egress covers *tool output*, not user-typed text.

**No host core change needed.** The plugin monkeypatches the one function every provider request
funnels through (`agent.chat_completion_helpers.interruptible_api_call`) at load — so `pip install`
+ the env var is enough, on any Hermes install. It's best-effort/version-pinned: if that internal
moves, egress **silently no-ops** (ingress hooks keep working — it never breaks the request path).
⚠️ It rewrites every provider request; validate on a non-critical agent first. Details in
[`deploy/EGRESS.md`](deploy/EGRESS.md).

- If you can't run a gateway hook layer at all, the same engine exists as a best-effort,
  instruction-based Agent Skill: [llm-privacy](https://github.com/patrikherak/llm-privacy) —
  see its README for the (weaker) guarantees that apply there.

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
