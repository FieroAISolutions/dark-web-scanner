"""Tests for the HTML report renderer + endpoint."""

from datetime import datetime, timedelta, timezone

import pytest

from backend import db, reports


def test_parse_since_accepts_date_only():
    out = reports.parse_since("2026-01-15")
    assert out.startswith("2026-01-15")


def test_parse_since_accepts_iso_datetime():
    out = reports.parse_since("2026-01-15T10:30:00")
    assert "2026-01-15" in out


def test_parse_since_accepts_iso_with_z():
    out = reports.parse_since("2026-01-15T10:30:00Z")
    assert "2026-01-15" in out


def test_parse_since_rejects_garbage():
    with pytest.raises(ValueError):
        reports.parse_since("not-a-date")


def test_default_since_is_in_the_past():
    out = reports.default_since(days=7)
    parsed = datetime.strptime(out, "%Y-%m-%d %H:%M:%S")
    delta = datetime.utcnow() - parsed
    # Allow 8 days slack
    assert timedelta(days=6) < delta < timedelta(days=8)


def test_gather_report_data_for_group():
    work = db.create_group("Work")
    db.add_emails(["alice@work.com", "bob@work.com"], group_id=work)
    db.upsert_breach({"Name": "B1", "Title": "BreachOne",
                      "DataClasses": ["Passwords", "Email addresses"],
                      "IsVerified": True, "BreachDate": "2024-01-01"})
    db.link_email_breach("alice@work.com", "B1")

    data = reports.gather_report_data(group_id=work, since="")
    assert data["group"]["name"] == "Work"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["email"] == "alice@work.com"
    assert data["severity_counts"]["critical"] == 1
    assert len(data["monitored"]) == 2


def test_gather_report_data_for_all_groups():
    db.add_emails(["x@example.com"])
    data = reports.gather_report_data(group_id=None, since="")
    assert data["group"] is None
    assert len(data["monitored"]) >= 1


def test_gather_report_data_filters_by_since():
    db.add_emails(["a@y.com"])
    db.upsert_breach({"Name": "Old", "DataClasses": ["Passwords"],
                      "IsVerified": True})
    db.link_email_breach("a@y.com", "Old")
    future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    data = reports.gather_report_data(group_id=None, since=future)
    # Linking just happened — first_seen_at is "now", strictly < future
    assert len(data["findings"]) == 0


def test_render_includes_group_name_and_severity_counts():
    work = db.create_group("Acme")
    db.add_emails(["a@acme.com"], group_id=work)
    db.upsert_breach({"Name": "B1", "Title": "BreachOne",
                      "DataClasses": ["Credit cards"], "IsVerified": True,
                      "BreachDate": "2024-06-01"})
    db.link_email_breach("a@acme.com", "B1")

    data = reports.gather_report_data(group_id=work, since="")
    html = reports.render(data)
    assert "Acme" in html
    assert "BreachOne" in html
    assert "critical" in html.lower()
    assert "a@acme.com" in html


def test_render_handles_empty_state():
    db.create_group("Empty")
    g = db.get_group_by_name("Empty")
    data = reports.gather_report_data(group_id=g["id"], since="")
    html = reports.render(data)
    assert "No breach findings" in html
    assert "No paste mentions" in html


def test_render_includes_print_button():
    data = reports.gather_report_data(group_id=None, since="")
    html = reports.render(data)
    assert "window.print()" in html
    assert "@media print" in html


# ── HTTP endpoint ─────────────────────────────────────────────────────────────


def test_report_endpoint_requires_auth(anon_client):
    r = anon_client.get("/api/report")
    assert r.status_code == 401


def test_report_endpoint_returns_html(client):
    r = client.get("/api/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in r.text.lower()


def test_report_endpoint_filtered_by_group(client):
    g = client.post("/api/groups", json={"name": "ReportGroup"}).json()["id"]
    client.post("/api/emails", json={"emails": ["target@x.com"], "group_id": g})
    client.post("/api/emails", json={"emails": ["other@y.com"]})  # default group

    r = client.get(f"/api/report?group_id={g}")
    assert r.status_code == 200
    assert "target@x.com" in r.text
    assert "other@y.com" not in r.text


def test_report_endpoint_unknown_group(client):
    r = client.get("/api/report?group_id=99999")
    assert r.status_code == 400


def test_report_endpoint_invalid_since(client):
    r = client.get("/api/report?since=not-a-date")
    assert r.status_code == 400


def test_report_endpoint_with_since(client):
    r = client.get("/api/report?since=2024-01-01")
    assert r.status_code == 200
    assert "Since 2024-01-01" in r.text


def test_report_endpoint_default_30_day_window(client):
    r = client.get("/api/report")  # no since, no days → default 30
    assert r.status_code == 200
    assert "Since" in r.text  # "Since YYYY-MM-DD …"


def test_report_response_relaxes_csp_for_inline_print_button(client):
    """The 'Print / Save as PDF' button uses an inline onclick handler. The
    response must ship a CSP that allows inline scripts so the button works
    when opened in a new tab (otherwise the SPA's strict CSP would block it)."""
    r = client.get("/api/report")
    csp = r.headers.get("content-security-policy", "")
    assert csp, "report response must set its own CSP"
    assert "'unsafe-inline'" in csp
    assert "script-src" in csp
    assert "frame-ancestors 'none'" in csp


def test_report_response_disables_caching(client):
    r = client.get("/api/report")
    assert "no-store" in r.headers.get("cache-control", "").lower()
