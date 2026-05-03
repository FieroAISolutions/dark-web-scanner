"""Tests for groups (segmentation) — DB layer + HTTP layer."""

import pytest

from backend import db


def test_default_group_created_on_init():
    groups = db.list_groups()
    names = [g["name"] for g in groups]
    assert "Default" in names


def test_create_and_list_groups():
    gid = db.create_group("Acme Corp", "MSP client #1")
    assert gid > 0
    groups = db.list_groups()
    names = {g["name"] for g in groups}
    assert {"Default", "Acme Corp"} <= names


def test_group_uniqueness_enforced():
    db.create_group("Personal")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.create_group("Personal")


def test_email_lands_in_default_group_by_default():
    db.add_emails(["alice@example.com"])
    listed = db.list_emails()
    assert listed[0]["group_name"] == "Default"


def test_email_can_be_added_to_specific_group():
    gid = db.create_group("Work")
    db.add_emails(["bob@example.com"], group_id=gid)
    listed = db.list_emails(group_id=gid)
    assert [e["email"] for e in listed] == ["bob@example.com"]


def test_email_can_be_moved_between_groups():
    work = db.create_group("Work")
    home = db.create_group("Home")
    db.add_emails(["x@y.com"], group_id=work)
    assert db.set_email_group("x@y.com", home) is True
    assert [e["email"] for e in db.list_emails(group_id=home)] == ["x@y.com"]
    assert db.list_emails(group_id=work) == []


def test_get_emails_filtered_by_group():
    work = db.create_group("Work")
    home = db.create_group("Home")
    db.add_emails(["a@w.com"], group_id=work)
    db.add_emails(["b@h.com"], group_id=home)
    assert db.get_emails(group_id=work) == ["a@w.com"]
    assert db.get_emails(group_id=home) == ["b@h.com"]
    assert set(db.get_emails()) == {"a@w.com", "b@h.com"}


def test_findings_filtered_by_group():
    work = db.create_group("Work")
    home = db.create_group("Home")
    db.add_emails(["a@w.com"], group_id=work)
    db.add_emails(["b@h.com"], group_id=home)
    db.upsert_breach({"Name": "B1", "Title": "Breach 1",
                      "DataClasses": ["Passwords"], "IsVerified": True})
    db.link_email_breach("a@w.com", "B1")
    db.link_email_breach("b@h.com", "B1")

    work_findings = db.list_findings(group_id=work)
    assert len(work_findings) == 1
    assert work_findings[0]["email"] == "a@w.com"

    home_findings = db.list_findings(group_id=home)
    assert len(home_findings) == 1
    assert home_findings[0]["email"] == "b@h.com"

    assert len(db.list_findings()) == 2  # no filter → both


def test_severity_counts_filtered_by_group():
    work = db.create_group("Work")
    home = db.create_group("Home")
    db.add_emails(["a@w.com"], group_id=work)
    db.add_emails(["b@h.com"], group_id=home)
    db.upsert_breach({"Name": "B1", "DataClasses": ["Passwords"], "IsVerified": True})
    db.upsert_breach({"Name": "B2", "DataClasses": ["Email addresses"], "IsVerified": True})
    db.link_email_breach("a@w.com", "B1")  # critical
    db.link_email_breach("b@h.com", "B2")  # low

    assert db.severity_counts(group_id=work)["critical"] == 1
    assert db.severity_counts(group_id=work)["low"] == 0
    assert db.severity_counts(group_id=home)["low"] == 1


def test_dashboard_stats_filtered_by_group():
    work = db.create_group("Work")
    db.add_emails(["a@w.com", "b@w.com"], group_id=work)
    db.add_emails(["c@elsewhere.com"])  # default group
    stats = db.dashboard_stats(group_id=work)
    assert stats["monitored_count"] == 2


def test_delete_group_refuses_default():
    default_id = next(g["id"] for g in db.list_groups() if g["name"] == "Default")
    ok, err = db.delete_group(default_id)
    assert ok is False
    assert "Default" in err


def test_delete_group_refuses_when_non_empty():
    gid = db.create_group("Acme")
    db.add_emails(["c@acme.com"], group_id=gid)
    ok, err = db.delete_group(gid)
    assert ok is False
    assert "email" in err.lower()


def test_delete_empty_group_succeeds():
    gid = db.create_group("Throwaway")
    ok, err = db.delete_group(gid)
    assert ok is True
    assert err == ""


def test_rename_group():
    gid = db.create_group("Old Name")
    db.update_group(gid, name="New Name")
    assert db.get_group(gid)["name"] == "New Name"


# ── HTTP layer ────────────────────────────────────────────────────────────────

def test_list_groups_endpoint(client):
    r = client.get("/api/groups")
    assert r.status_code == 200
    data = r.json()
    assert any(g["name"] == "Default" for g in data["groups"])


def test_create_group_endpoint(client):
    r = client.post("/api/groups", json={"name": "Acme", "description": "client"})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Acme"


def test_create_group_rejects_duplicate(client):
    client.post("/api/groups", json={"name": "Dup"})
    r = client.post("/api/groups", json={"name": "Dup"})
    assert r.status_code == 409


def test_create_group_rejects_empty_name(client):
    r = client.post("/api/groups", json={"name": "  "})
    assert r.status_code == 400


def test_patch_group(client):
    r = client.post("/api/groups", json={"name": "X"})
    gid = r.json()["id"]
    r = client.patch(f"/api/groups/{gid}", json={"name": "X-renamed"})
    assert r.status_code == 200
    assert r.json()["name"] == "X-renamed"


def test_delete_group_endpoint(client):
    r = client.post("/api/groups", json={"name": "GoneSoon"})
    gid = r.json()["id"]
    r = client.delete(f"/api/groups/{gid}")
    assert r.status_code == 200


def test_add_emails_into_group(client):
    r = client.post("/api/groups", json={"name": "Team Alpha"})
    gid = r.json()["id"]
    r = client.post("/api/emails", json={"emails": ["a@team.com"], "group_id": gid})
    assert r.status_code == 200
    r = client.get(f"/api/emails?group_id={gid}")
    assert [e["email"] for e in r.json()["emails"]] == ["a@team.com"]


def test_move_email_between_groups(client):
    g1 = client.post("/api/groups", json={"name": "G1"}).json()["id"]
    g2 = client.post("/api/groups", json={"name": "G2"}).json()["id"]
    client.post("/api/emails", json={"emails": ["m@x.com"], "group_id": g1})
    r = client.patch("/api/emails/m@x.com/group", json={"group_id": g2})
    assert r.status_code == 200
    r = client.get(f"/api/emails?group_id={g2}")
    assert len(r.json()["emails"]) == 1


def test_groups_endpoint_requires_auth(anon_client):
    assert anon_client.get("/api/groups").status_code == 401
    assert anon_client.post("/api/groups", json={"name": "x"}).status_code == 401


def test_dashboard_filtered_by_group(client):
    g = client.post("/api/groups", json={"name": "F"}).json()["id"]
    client.post("/api/emails", json={"emails": ["x@f.com"], "group_id": g})
    client.post("/api/emails", json={"emails": ["y@other.com"]})
    r = client.get(f"/api/dashboard?group_id={g}")
    assert r.status_code == 200
    assert r.json()["monitored_count"] == 1


def test_scan_with_unknown_group_id(client):
    r = client.post("/api/scan", json={"group_id": 99999})
    assert r.status_code == 400
    assert "unknown" in r.json()["detail"].lower()
