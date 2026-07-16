# hermes-llm-privacy — coverage specs

What hermes-llm-privacy detects, by tier. Everything here is round-trip **reversible** and, for numeric ids,
**checksum-gated** where a checksum exists (so a random number of the same length does not mask).

## Tier 1 — source tags (language-agnostic, exact)

Your data tools wrap known-PII fields with `tag(KIND, value)`. Detection is by the marker, never
by the text, so it is **script- and language-agnostic** — it works identically for every language.
Any `KIND` you like (`NAME`, `ADDRESS`, `PHONE`, `EMAIL`, `DOB`, `IBAN`, `NOTE`, …).

Verified round-trip across 21 scripts/languages in the test stack: Czech, German, French, Spanish,
Polish, Vietnamese, Turkish, Russian, Ukrainian, Greek, Bulgarian, Chinese, Japanese, Korean,
Arabic, Hebrew, Thai, Hindi, plus mixed/emoji. This is the recommended tier — it is exact.

## Tier 2a — universal entities (on by default, no locale needed)

| Entity | Matches | Gate |
|---|---|---|
| `EMAIL` | standard addresses (incl. sub-domains, `+tag`) | — |
| `IBAN` | every IBAN country (`CC` + 2 check + BBAN) | — |
| `IPV4` / `IPV6` | IP addresses | — |
| `MAC` | MAC addresses | — |
| `ETH` / `BTC` | Ethereum + Bitcoin (legacy + bech32) addresses | — |
| `SSN_US` | US SSN `NNN-NN-NNNN` | — |
| `PHONE` | **international `+country` numbers — every country** | — |
| `CREDIT_CARD` | 13–19 digit PANs | **Luhn**, opt-in |

National (non-`+`) phone formats live in the locale packs below; the universal `PHONE` covers the
international form for all countries.

## Tier 2b — locale packs (opt-in via `LLM_PRIVACY_LOCALES=cz,de,…`)

48 locales. **✓ = checksum-verified** (only a valid id masks); **fmt = format/structure only**.
Every locale includes its national phone format.

### Europe
| Locale | Country | National id(s) |
|---|---|---|
| `cz` | Czechia | rodné číslo (fmt) |
| `sk` | Slovakia | rodné číslo (fmt) |
| `de` | Germany | — |
| `at` | Austria | — |
| `ch` | Switzerland | AHV (fmt) |
| `fr` | France | NIR / INSEE ✓ |
| `es` | Spain | DNI / NIE ✓ |
| `it` | Italy | codice fiscale (fmt) |
| `pl` | Poland | PESEL ✓ |
| `nl` | Netherlands | BSN ✓ |
| `be` | Belgium | — |
| `pt` | Portugal | — |
| `uk` | United Kingdom | NINO (fmt), NHS ✓ |
| `ie` | Ireland | — |
| `se` | Sweden | personnummer (fmt) |
| `no` | Norway | — |
| `dk` | Denmark | CPR (fmt) |
| `fi` | Finland | HETU (fmt) |
| `gr` | Greece | — |
| `ro` | Romania | CNP ✓ |
| `bg` | Bulgaria | EGN ✓ |
| `hu` | Hungary | — |
| `ru` | Russia | — |
| `ua` | Ukraine | — |
| `tr` | Turkey | TCKN ✓ |

### Americas
| Locale | Country | National id(s) |
|---|---|---|
| `us` | United States | EIN (fmt) · SSN is universal |
| `ca` | Canada | SIN ✓ (Luhn) |
| `br` | Brazil | CPF ✓, CNPJ ✓ |
| `mx` | Mexico | CURP (fmt) |
| `ar` | Argentina | — |

### Asia / Pacific
| Locale | Country | National id(s) |
|---|---|---|
| `cn` | China | resident id (fmt) |
| `jp` | Japan | — |
| `kr` | South Korea | RRN ✓ |
| `in` | India | Aadhaar ✓ (Verhoeff), PAN (fmt) |
| `id` | Indonesia | — |
| `th` | Thailand | — |
| `vn` | Vietnam | — |
| `ph` | Philippines | — |
| `sg` | Singapore | NRIC (fmt) |
| `my` | Malaysia | MyKad (fmt) |
| `au` | Australia | TFN ✓ |
| `nz` | New Zealand | — |

### Middle East / Africa
| Locale | Country | National id(s) |
|---|---|---|
| `il` | Israel | Teudat Zehut ✓ (Luhn) |
| `ae` | United Arab Emirates | Emirates ID (fmt) |
| `sa` | Saudi Arabia | — |
| `za` | South Africa | SA ID ✓ (Luhn) |
| `ng` | Nigeria | — |
| `eg` | Egypt | — |

## Precision & false positives — read this

- **Checksum-gated ids** (✓ above) only mask when the number passes its real check digits, so a
  random same-length number rarely matches. There is still a residual rate: a single check digit
  passes ~1 in 10 random numbers, two check digits ~1 in 100. So enabling `pl` (PESEL, one check
  digit) can occasionally mask an unrelated 11-digit number. It is **reversible** (restored
  correctly in the output) and **opt-in per locale**, but for exactness prefer Tier-1 tags.
- **Format-only ids** (fmt) rely on a distinctive shape (separators, letter blocks). They don't
  collide with plain digit runs, but they aren't validated.
- **Not masked, by design:** order numbers, tracking numbers, UUIDs, hashes, dates, prices, ISBNs,
  versions, hex colors — the universal net is conservative (phones require `+country`, cards
  require Luhn). Verified in the test stack.

## Configuring

```yaml
# ~/.hermes/config.yaml (or env: LLM_PRIVACY_LOCALES, LLM_PRIVACY_ENTITIES, …)
plugins:
  enabled: [hermes-llm-privacy]
```
```bash
LLM_PRIVACY_LOCALES=cz,sk,de,pl,tr        # turn on the national packs you need
LLM_PRIVACY_ENTITIES=email,iban,phone,credit_card   # narrow the universal set (optional)
```
Tier-1 source tags are always on unless `LLM_PRIVACY_SOURCE_TAGS=false`.
