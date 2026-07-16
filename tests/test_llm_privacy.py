#!/usr/bin/env python3
"""Big test stack for PrivacyVault — proves masking works, restores losslessly, and doesn't eat
non-PII, across many languages/scripts and every entity type. Pure stdlib.
Run from the repo root:  python3 tests/test_llm_privacy.py

ALL DATA BELOW IS SYNTHETIC. Names are generic placeholders (the local "John/Jane Doe"), e-mails
use reserved example domains, IBAN/card/crypto values are the well-known public test vectors, and
order/tracking numbers are made up. Nothing here comes from any real system or person.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hermes_llm_privacy import PrivacyVault, tag, luhn_ok, D1, D2  # noqa: E402

P = {"ok": 0, "fail": 0, "fails": []}


def check(name, cond, detail=""):
    if cond:
        P["ok"] += 1
    else:
        P["fail"] += 1
        P["fails"].append(f"{name} — {detail}")


def unwrap(text):
    """The plain form of a tagged string — markers replaced by their values (what restore yields)."""
    return re.sub(re.escape(D1) + r"[A-Z_]+:(.*?)" + re.escape(D2), r"\1", text, flags=re.DOTALL)


# ── 1. Tier-1 source tags across scripts/languages (the versatility proof) ─────
NAMES = [
    ("Czech", "Jan Novák"), ("Czech-diacritics", "Řehoř Žížala"),
    ("German", "Erika Mustermann"), ("French", "Jean Dupont"),
    ("Spanish", "Juan Español"), ("Polish", "Jan Kowalski"),
    ("Vietnamese", "Nguyễn Văn A"), ("Turkish", "Şükrü Gülağ"),
    ("Russian", "Иван Иванов"), ("Ukrainian", "Олена Ковальчук"),
    ("Greek", "Γιώργος Παπαδόπουλος"), ("Bulgarian", "Иван Иванов"),
    ("Chinese", "张伟"), ("Japanese", "山田太郎"), ("Korean", "홍길동"),
    ("Arabic", "فلان الفلاني"), ("Hebrew", "ישראל ישראלי"), ("Thai", "สมชาย ใจดี"),
    ("Hindi", "आम आदमी"), ("Greek-address", "Λεωφόρος Τεστ 12"),
    ("emoji-adjacent", "Test 🌸 User"),
]
for lang, name in NAMES:
    hx = PrivacyVault()
    src = f"Row: {tag('NAME', name)} | id 80-000"
    m = hx.mask(src)
    ok = name not in m and "⟦PII_" in m and hx.restore(m) == unwrap(src)
    check(f"lang:{lang}", ok, f"masked={m!r}")

# ── 2. Universal structured entities (each masked + round-trip) ────────────────
ENTITIES = [
    ("EMAIL", "jane.doe@example.com"),
    ("EMAIL-plus", "a.b+tag@mail.example.co.uk"),
    ("IBAN-CZ", "CZ65 0800 0000 1920 0014 5399"),
    ("IBAN-DE", "DE89 3704 0044 0532 0130 00"),
    ("IPV4", "192.0.2.254"),
    ("IPV6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("MAC", "00:1A:2B:3C:4D:5E"),
    ("ETH", "0x52908400098527886E0F7030069857D2E4169EE7"),
    ("BTC", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
    ("SSN_US", "123-45-6789"),
    ("PHONE-cz", "+420 601 111 222"),
    ("PHONE-de", "+49 151 2345 6789"),
    ("PHONE-us", "+1 (415) 555-0132"),
    ("PHONE-jp", "+81 90-1234-5678"),
    ("PHONE-in", "+91 98765 43210"),
    ("PHONE-br", "+55 11 91234-5678"),
]
for kind, val in ENTITIES:
    hx = PrivacyVault()
    doc = f"contact: {val} end"
    m = hx.mask(doc)
    check(f"entity:{kind}:masked", val not in m and "⟦PII_" in m, f"m={m!r}")
    check(f"entity:{kind}:restore", hx.restore(m) == doc, f"restored={hx.restore(m)!r}")

# ── 3. Credit cards: Luhn gate (opt-in) — standard public test numbers ─────────
hx = PrivacyVault(entities=["CREDIT_CARD", "EMAIL"])
for label, card, should_mask in [
    ("visa-test", "4111 1111 1111 1111", True),
    ("mc-test", "5500 0000 0000 0004", True),
    ("amex-test", "3400 0000 0000 009", True),
    ("bad-luhn", "1234 5678 9012 3456", False),
]:
    m = hx.mask(f"card {card} .")
    did = card not in m and "⟦PII_CREDIT_CARD" in m
    check(f"card:{label}", did == should_mask, f"masked={did} want={should_mask} luhn={luhn_ok(card)}")

# ── 4. FP-safety: non-PII must pass through UNTOUCHED (all invented) ────────────
hx = PrivacyVault(entities=["CREDIT_CARD", "EMAIL", "IBAN", "PHONE", "IPV4", "MAC"])
SAFE = [
    ("order-number", "5550001234"),
    ("tracking-generic", "99887766554433"),
    ("tracking-ups-shape", "1Z999AA10123456784"),
    ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("iso-date", "2026-06-25T14:33:02Z"),
    ("price", "4 676,00 Kč"),
    ("isbn", "978-3-16-148410-0"),
    ("version", "v2.14.0-rc3"),
    ("hex-color", "#0b7c74"),
    ("bignum-16-nonluhn", "1111222233334445"),
]
for label, val in SAFE:
    m = hx.mask(f"value: {val} ok")
    check(f"safe:{label}", val in m and "⟦PII_" not in m, f"m={m!r}")

# ── 5. Stability: same value → same token; different values → different tokens ─
hx = PrivacyVault()
a1 = hx.mask(tag("EMAIL", "x@example.com")).strip()
a2 = hx.mask("again " + tag("EMAIL", "x@example.com")).replace("again ", "").strip()
b = hx.mask(tag("EMAIL", "z@example.com")).strip()
check("stable:same-value-same-token", a1 == a2, f"{a1!r} vs {a2!r}")
check("stable:distinct-values-distinct-tokens", a1 != b, f"{a1!r} vs {b!r}")

# ── 6. Round-trip losslessness on a big mixed-language document (all synthetic) ─
hx = PrivacyVault(entities=["EMAIL", "IBAN", "PHONE", "IPV4", "MAC", "ETH", "SSN_US", "BTC"])
BIG = (
    "Objednávka pro " + tag("NAME", "Řehoř Žížala") + " <jane.doe@example.com>, +420 601 111 222,\n"
    "adresa " + tag("ADDRESS", "Testovací 42, Nové Město") + ".\n"
    "Bestellung für " + tag("NAME", "Erika Mustermann") + " <erika@example.de>, +49 151 2345 6789.\n"
    "注文 " + tag("NAME", "山田太郎") + " taro@example.jp, +81 90-1234-5678, IBAN DE89 3704 0044 0532 0130 00.\n"
    "server 192.0.2.5 mac 00:1A:2B:3C:4D:5E wallet 0x52908400098527886E0F7030069857D2E4169EE7\n"
    "order 80-5550001234 tracking 99887766554433 (must survive)"
)
m = hx.mask(BIG)
check("big:no-raw-pii-name", "Řehoř Žížala" not in m and "山田太郎" not in m and "Erika Mustermann" not in m, "name leaked")
check("big:no-raw-email", "jane.doe@example.com" not in m and "erika@example.de" not in m and "taro@example.jp" not in m, "email leaked")
check("big:no-raw-phone", "+420 601 111 222" not in m and "+81 90-1234-5678" not in m, "phone leaked")
check("big:tracking-survives", "99887766554433" in m and "80-5550001234" in m, "non-PII got masked")
check("big:lossless-roundtrip", hx.restore(m) == unwrap(BIG), "restore != de-tagged original")

# ── 7. Per-locale packs (opt-in) — invented ids in each country's format ───────
hx = PrivacyVault(entities=["EMAIL"], locales=["cz", "us", "in", "br"])
for label, val in [
    ("cz-rodne-cislo", "000101/1234"),
    ("us-phone-national", "(415) 555-0132"),
    ("in-aadhaar", "2345 6789 0124"),
    ("br-cpf", "123.456.789-09"),
]:
    m = hx.mask(f"id {val} .")
    check(f"locale:{label}", val not in m and "⟦PII_" in m and hx.restore(m) == f"id {val} .",
          f"m={m!r} restored={hx.restore(m)!r}")

# ── 8. Correct entity labelling (no MAC↔IPv6 confusion) ────────────────────────
hx = PrivacyVault(entities=["MAC", "IPV6"])
check("label:mac-not-ipv6", "PII_MAC" in hx.mask("00:1A:2B:3C:4D:5E"), "mac mislabelled")
check("label:ipv6", "PII_IPV6" in hx.mask("2001:db8::8a2e:370:7334"), "ipv6 missed")

# ── 9. Edge cases ──────────────────────────────────────────────────────────────
hx = PrivacyVault()
check("edge:empty", hx.mask("") == "", "empty broke")
check("edge:none-tag", tag("NAME", None) == "", "None tag not empty")
check("edge:no-pii-unchanged", hx.mask("just a plain sentence") == "just a plain sentence", "changed clean text")
adj = hx.mask(tag("NAME", "Alice") + tag("NAME", "Bob"))
check("edge:adjacent-tags", "Alice" not in adj and "Bob" not in adj and adj.count("⟦PII_") == 2, f"adj={adj!r}")
check("edge:restore-idempotent", hx.restore(hx.restore(hx.mask(tag("EMAIL", "e@example.com")))) == "e@example.com", "double-restore broke")
special = "O'Brien-Müller & Co. <a@example.com>"
mm = hx.mask(tag("NAME", special))
check("edge:special-chars", hx.restore(mm) == special, f"special roundtrip {mm!r}")

# ── 10. Vault bound + eviction ─────────────────────────────────────────────────
hx = PrivacyVault(max_values=50)
for i in range(200):
    hx.mask(tag("EMAIL", f"user{i}@example.com"))
check("vault:bounded", hx.size <= 50, f"size={hx.size}")
last = hx.mask(tag("EMAIL", "user199@example.com"))
check("vault:recent-restorable", hx.restore(last) == "user199@example.com", "recent evicted")

# ── 11. National IDs — checksum-gated (valid masks; bad checksum survives) ──────
# All values synthetic: documented public test vectors or algorithmically-valid throwaways.
IDVEC = [
    ("es", "DNI", "12345678Z", "12345678A"),
    ("br", "CPF", "111.444.777-35", "111.444.777-34"),
    ("br", "CNPJ", "11.222.333/0001-81", "11.222.333/0001-80"),
    ("pl", "PESEL", "44051401359", "44051401358"),
    ("tr", "TCKN", "10000000146", "10000000145"),
    ("bg", "EGN", "7523169263", "7523169264"),
    ("uk", "NHS", "943 476 5919", "943 476 5918"),
    ("nl", "BSN", "111222333", "111222334"),
    ("ro", "CNP", "1960121400012", "1960121400011"),
    ("ca", "SIN", "046 454 286", "046 454 287"),
    ("za", "SAID", "8001015009087", "8001015009088"),
    ("au", "TFN", "123 456 782", "123 456 783"),
    ("fr", "NIR", "255080730404804", "255080730404805"),
    ("kr", "RRN", "970101-3001239", "970101-3001238"),
    ("in", "AADHAAR", "2345 6789 0124", "2345 6789 0125"),
    ("il", "TZ", "120000005", "120000006"),
]
for loc, kind, valid, invalid in IDVEC:
    hx = PrivacyVault(entities=["EMAIL"], locales=[loc])
    mvr = hx.mask(f"id {valid} .")
    check(f"id:{loc}:{kind}:valid-masked",
          valid not in mvr and f"⟦PII_{kind}" in mvr and hx.restore(mvr) == f"id {valid} .",
          f"m={mvr!r}")
    mi = PrivacyVault(entities=["EMAIL"], locales=[loc]).mask(f"id {invalid} .")
    check(f"id:{loc}:{kind}:bad-checksum-survives", invalid in mi and "⟦PII_" not in mi, f"m={mi!r}")

# ── 12. Format-based national ids (structure, no checksum) ─────────────────────
FMT = [
    ("cz", "NID", "000101/1234"),
    ("in", "PAN", "ABCDE1234F"),
    ("it", "CF", "RSSMRA85M01H501Z"),
    ("sg", "NRIC", "S1234567D"),
    ("se", "PNR", "990101-1234"),
]
for loc, kind, val in FMT:
    hx = PrivacyVault(entities=["EMAIL"], locales=[loc])
    m = hx.mask(f"id {val} .")
    check(f"idfmt:{loc}:{kind}", val not in m and "⟦PII_" in m and hx.restore(m) == f"id {val} .", f"m={m!r}")

# ── 13. National phone formats (sampling of the locale packs) ──────────────────
PH = [
    ("cz", "608 111 222"), ("de", "0151 23456789"), ("fr", "06 12 34 56 78"),
    ("br", "(11) 91234-5678"), ("in", "98765 43210"), ("jp", "090-1234-5678"),
    ("kr", "010-1234-5678"), ("au", "0412 345 678"),
]
for loc, val in PH:
    hx = PrivacyVault(entities=["EMAIL"], locales=[loc])
    m = hx.mask(f"tel {val} .")
    check(f"natphone:{loc}", val not in m and "PII_PHONE" in m and hx.restore(m) == f"tel {val} .", f"m={m!r}")

# ── 14. Locale coverage sanity ─────────────────────────────────────────────────
from hermes_llm_privacy import LOCALES  # noqa: E402
check("locales:>=40", len(LOCALES) >= 40, f"only {len(LOCALES)}")

# ── report ─────────────────────────────────────────────────────────────────────
total = P["ok"] + P["fail"]
print(f"\n{'='*62}\nLLM-PRIVACY TEST STACK — {P['ok']}/{total} passed\n{'='*62}")
if P["fails"]:
    print("FAILURES:")
    for f in P["fails"]:
        print("  x", f)
    sys.exit(1)
print("all green  (scripts, entities, locales, FP-safety, vault, edges)")
