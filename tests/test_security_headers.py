def test_security_headers_present_on_index(anon_client):
    r = anon_client.get("/")
    assert "Content-Security-Policy" in r.headers
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Referrer-Policy" in r.headers
    assert "Permissions-Policy" in r.headers


def test_security_headers_present_on_api(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
