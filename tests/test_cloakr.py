#!/usr/bin/env python3
"""Big test stack for Cloakr — proves masking works, restores losslessly, and doesn't eat
non-PII, across many languages/scripts and every entity type. Pure stdlib.
Run from the repo root:  python3 tests/test_cloakr.py

ALL DATA BELOW IS SYNTHETIC. Names are generic placeholders (the local "John/Jane Doe"), e-mails
use reserved example domains, IBAN/card/crypto values are the well-known public test vectors, and
order/tracking numbers are made up. Nothing here comes from any real system or person.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cloakr import Cloakr, tag, luhn_ok, D1, D2  # noqa: E402

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
    cr = Cloakr()
    src = f"Row: {tag('NAME', name)} | id 80-000"
    m = cr.mask(src)
    ok = name not in m and "⟦PII_" in m and cr.restore(m) == unwrap(src)
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
    cr = Cloakr()
    doc = f"contact: {val} end"
    m = cr.mask(doc)
    check(f"entity:{kind}:masked", val not in m and "⟦PII_" in m, f"m={m!r}")
    check(f"entity:{kind}:restore", cr.restore(m) == doc, f"restored={cr.restore(m)!r}")

# ── 3. Credit cards: Luhn gate (opt-in) — standard public test numbers ─────────
cr = Cloakr(entities=["CREDIT_CARD", "EMAIL"])
for label, card, should_mask in [
    ("visa-test", "4111 1111 1111 1111", True),
    ("mc-test", "5500 0000 0000 0004", True),
    ("amex-test", "3400 0000 0000 009", True),
    ("bad-luhn", "1234 5678 9012 3456", False),
]:
    m = cr.mask(f"card {card} .")
    did = card not in m and "⟦PII_CREDIT_CARD" in m
    check(f"card:{label}", did == should_mask, f"masked={did} want={should_mask} luhn={luhn_ok(card)}")

# ── 4. FP-safety: non-PII must pass through UNTOUCHED (all invented) ────────────
cr = Cloakr(entities=["CREDIT_CARD", "EMAIL", "IBAN", "PHONE", "IPV4", "MAC"])
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
    m = cr.mask(f"value: {val} ok")
    check(f"safe:{label}", val in m and "⟦PII_" not in m, f"m={m!r}")

# ── 5. Stability: same value → same token; different values → different tokens ─
cr = Cloakr()
a1 = cr.mask(tag("EMAIL", "x@example.com")).strip()
a2 = cr.mask("again " + tag("EMAIL", "x@example.com")).replace("again ", "").strip()
b = cr.mask(tag("EMAIL", "z@example.com")).strip()
check("stable:same-value-same-token", a1 == a2, f"{a1!r} vs {a2!r}")
check("stable:distinct-values-distinct-tokens", a1 != b, f"{a1!r} vs {b!r}")

# ── 6. Round-trip losslessness on a big mixed-language document (all synthetic) ─
cr = Cloakr(entities=["EMAIL", "IBAN", "PHONE", "IPV4", "MAC", "ETH", "SSN_US", "BTC"])
BIG = (
    "Objednávka pro " + tag("NAME", "Řehoř Žížala") + " <jane.doe@example.com>, +420 601 111 222,\n"
    "adresa " + tag("ADDRESS", "Testovací 42, Nové Město") + ".\n"
    "Bestellung für " + tag("NAME", "Erika Mustermann") + " <erika@example.de>, +49 151 2345 6789.\n"
    "注文 " + tag("NAME", "山田太郎") + " taro@example.jp, +81 90-1234-5678, IBAN DE89 3704 0044 0532 0130 00.\n"
    "server 192.0.2.5 mac 00:1A:2B:3C:4D:5E wallet 0x52908400098527886E0F7030069857D2E4169EE7\n"
    "order 80-5550001234 tracking 99887766554433 (must survive)"
)
m = cr.mask(BIG)
check("big:no-raw-pii-name", "Řehoř Žížala" not in m and "山田太郎" not in m and "Erika Mustermann" not in m, "name leaked")
check("big:no-raw-email", "jane.doe@example.com" not in m and "erika@example.de" not in m and "taro@example.jp" not in m, "email leaked")
check("big:no-raw-phone", "+420 601 111 222" not in m and "+81 90-1234-5678" not in m, "phone leaked")
check("big:tracking-survives", "99887766554433" in m and "80-5550001234" in m, "non-PII got masked")
check("big:lossless-roundtrip", cr.restore(m) == unwrap(BIG), "restore != de-tagged original")

# ── 7. Per-locale packs (opt-in) — invented ids in each country's format ───────
cr = Cloakr(entities=["EMAIL"], locales=["cz", "us", "in", "br"])
for label, val in [
    ("cz-rodne-cislo", "000101/1234"),
    ("us-phone-national", "(415) 555-0132"),
    ("in-aadhaar", "1234 5678 9012"),
    ("br-cpf", "123.456.789-09"),
]:
    m = cr.mask(f"id {val} .")
    check(f"locale:{label}", val not in m and "⟦PII_" in m and cr.restore(m) == f"id {val} .",
          f"m={m!r} restored={cr.restore(m)!r}")

# ── 8. Correct entity labelling (no MAC↔IPv6 confusion) ────────────────────────
cr = Cloakr(entities=["MAC", "IPV6"])
check("label:mac-not-ipv6", "PII_MAC" in cr.mask("00:1A:2B:3C:4D:5E"), "mac mislabelled")
check("label:ipv6", "PII_IPV6" in cr.mask("2001:db8::8a2e:370:7334"), "ipv6 missed")

# ── 9. Edge cases ──────────────────────────────────────────────────────────────
cr = Cloakr()
check("edge:empty", cr.mask("") == "", "empty broke")
check("edge:none-tag", tag("NAME", None) == "", "None tag not empty")
check("edge:no-pii-unchanged", cr.mask("just a plain sentence") == "just a plain sentence", "changed clean text")
adj = cr.mask(tag("NAME", "Alice") + tag("NAME", "Bob"))
check("edge:adjacent-tags", "Alice" not in adj and "Bob" not in adj and adj.count("⟦PII_") == 2, f"adj={adj!r}")
check("edge:restore-idempotent", cr.restore(cr.restore(cr.mask(tag("EMAIL", "e@example.com")))) == "e@example.com", "double-restore broke")
special = "O'Brien-Müller & Co. <a@example.com>"
mm = cr.mask(tag("NAME", special))
check("edge:special-chars", cr.restore(mm) == special, f"special roundtrip {mm!r}")

# ── 10. Vault bound + eviction ─────────────────────────────────────────────────
cr = Cloakr(max_values=50)
for i in range(200):
    cr.mask(tag("EMAIL", f"user{i}@example.com"))
check("vault:bounded", cr.size <= 50, f"size={cr.size}")
last = cr.mask(tag("EMAIL", "user199@example.com"))
check("vault:recent-restorable", cr.restore(last) == "user199@example.com", "recent evicted")

# ── report ─────────────────────────────────────────────────────────────────────
total = P["ok"] + P["fail"]
print(f"\n{'='*62}\nCLOAKR TEST STACK — {P['ok']}/{total} passed\n{'='*62}")
if P["fails"]:
    print("FAILURES:")
    for f in P["fails"]:
        print("  x", f)
    sys.exit(1)
print("all green  (scripts, entities, locales, FP-safety, vault, edges)")
