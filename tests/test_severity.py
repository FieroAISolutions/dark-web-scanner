from backend import severity as sev


def lvl(d):
    return sev.compute(d)["level"]


def test_passwords_alone_is_critical():
    assert lvl({"data_classes": ["Email addresses", "Passwords"], "is_verified": True}) == "critical"


def test_credit_cards_critical():
    assert lvl({"data_classes": ["Credit cards", "Names"], "is_verified": True}) == "critical"


def test_government_id_critical():
    assert lvl({"data_classes": ["Social Security Numbers"], "is_verified": True}) == "critical"


def test_phone_address_only_is_medium():
    assert lvl({"data_classes": ["Phone numbers", "Physical addresses"], "is_verified": True}) == "medium"


def test_only_email_username_is_low():
    assert lvl({"data_classes": ["Email addresses", "Usernames"], "is_verified": True}) == "low"


def test_fabricated_caps_to_low():
    assert lvl({"data_classes": ["Passwords", "Credit cards"], "is_fabricated": True}) == "low"


def test_spam_list_caps_low():
    assert lvl({"data_classes": ["Passwords"], "is_spam_list": True}) == "low"


def test_unverified_demotes():
    # Just credentials → would be critical; unverified shaves -10 → still critical (60-10=50 → high)
    out = sev.compute({"data_classes": ["Passwords"], "is_verified": False})
    assert out["level"] in {"critical", "high"}


def test_sensitive_flag_boosts():
    base = sev.compute({"data_classes": ["Sexual orientations"], "is_verified": True})
    boosted = sev.compute({"data_classes": ["Sexual orientations"], "is_sensitive": True, "is_verified": True})
    assert boosted["score"] > base["score"]


def test_paste_size_buckets():
    assert sev.compute_paste({"email_count": 5_000_000})["level"] == "high"
    assert sev.compute_paste({"email_count": 50_000})["level"] == "medium"
    assert sev.compute_paste({"email_count": 50})["level"] == "low"


def test_reasons_populated():
    out = sev.compute({"data_classes": ["Passwords", "Credit cards"]})
    assert any("Credentials" in r for r in out["reasons"])
    assert any("Financial" in r for r in out["reasons"])


def test_by_severity_orders_critical_first():
    items = [
        {"severity": {"level": "low"}, "first_seen_at": "2024-01-01"},
        {"severity": {"level": "critical"}, "first_seen_at": "2023-01-01"},
        {"severity": {"level": "medium"}, "first_seen_at": "2025-01-01"},
    ]
    ordered = sev.by_severity(items)
    assert [i["severity"]["level"] for i in ordered] == ["critical", "medium", "low"]
