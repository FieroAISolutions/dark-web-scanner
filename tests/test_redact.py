import logging

from backend.log_redact import EmailRedactFilter, _redact, install


def test_redact_basic():
    out = _redact("user alice@example.com had an issue")
    assert "alice@example.com" not in out
    assert "a***@e***.com" in out


def test_redact_multiple():
    out = _redact("alice@example.com bob@other.org")
    assert "alice@example.com" not in out
    assert "bob@other.org" not in out


def test_redact_filter_applied_to_record():
    f = EmailRedactFilter()
    rec = logging.LogRecord(
        name="t", level=logging.INFO, pathname="", lineno=0,
        msg="scanning %s now", args=("alice@example.com",), exc_info=None,
    )
    f.filter(rec)
    assert "alice@example.com" not in (rec.getMessage() if not rec.args else (rec.msg % rec.args))


def test_install_attaches_to_root():
    install()
    root = logging.getLogger()
    assert any(isinstance(f, EmailRedactFilter) for f in root.filters)


def test_no_email_unchanged():
    assert _redact("nothing to redact here") == "nothing to redact here"
