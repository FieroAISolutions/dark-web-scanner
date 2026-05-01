from backend import db


def test_init_creates_default_config():
    cfg = dict(db.get_config_row())
    assert cfg["id"] == 1
    assert cfg["interval_hours"] == 6
    assert cfg["hibp_rpm"] == 10


def test_add_and_list_emails():
    added, skipped = db.add_emails(["alice@example.com", "bob@example.com"])
    assert set(added) == {"alice@example.com", "bob@example.com"}
    assert skipped == []
    listed = db.list_emails()
    assert {e["email"] for e in listed} == {"alice@example.com", "bob@example.com"}


def test_duplicate_emails_skipped():
    db.add_emails(["alice@example.com"])
    added, skipped = db.add_emails(["alice@example.com", "bob@example.com"])
    assert added == ["bob@example.com"]
    assert skipped == ["alice@example.com"]


def test_remove_email():
    db.add_emails(["x@y.com"])
    assert db.remove_email("x@y.com") is True
    assert db.remove_email("x@y.com") is False
    assert db.list_emails() == []


def test_breach_first_seen_tracking():
    db.add_emails(["a@b.com"])
    sample = {
        "Name": "ExampleBreach", "Title": "Example",
        "Domain": "example.com", "BreachDate": "2024-01-01",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
    }
    db.upsert_breach(sample)
    assert db.link_email_breach("a@b.com", "ExampleBreach") is True
    assert db.link_email_breach("a@b.com", "ExampleBreach") is False  # already linked

    findings = db.list_findings()
    assert len(findings) == 1
    assert findings[0]["email"] == "a@b.com"
    assert findings[0]["severity"]["level"] == "critical"


def test_dashboard_stats_and_severity_counts():
    db.add_emails(["a@b.com"])
    db.upsert_breach({"Name": "B1", "DataClasses": ["Passwords"], "IsVerified": True})
    db.upsert_breach({"Name": "B2", "DataClasses": ["Email addresses"], "IsVerified": True})
    db.link_email_breach("a@b.com", "B1")
    db.link_email_breach("a@b.com", "B2")

    stats = db.dashboard_stats()
    assert stats["monitored_count"] == 1
    assert stats["unique_breaches"] == 2
    assert stats["total_breach_findings"] == 2

    sc = db.severity_counts()
    assert sc["critical"] == 1
    assert sc["low"] == 1


def test_scan_run_lifecycle():
    rid = db.create_run(email_count=3, persist=True)
    assert rid > 0
    db.finish_run(rid, new_breaches=2, new_pastes=1, status="ok")
    row = db.get_run(rid)
    assert row["status"] == "ok"
    assert row["new_breaches"] == 2
    assert row["new_pastes"] == 1
    assert row["finished_at"] is not None
