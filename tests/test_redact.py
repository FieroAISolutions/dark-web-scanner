import logging
import sys

import httpx
import pytest
from uvicorn.logging import AccessFormatter

from backend import log_redact
from backend.log_redact import EmailRedactFilter, _redact, install, register_secret


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


@pytest.mark.parametrize("name", ["token", "ticket", "api_key", "access_token"])
def test_query_credentials_redacted_with_other_diagnostics_preserved(name):
    result = _redact(f"GET /ws?{name}=synthetic-secret&mode=debug HTTP/1.1")
    assert "synthetic-secret" not in result
    assert "&mode=debug HTTP/1.1" in result


@pytest.mark.parametrize("url", [
    "https://hooks.slack.com/services/TEAM/CHANNEL/SYNTHETIC_SECRET",
    "https://discord.com/api/webhooks/123/SYNTHETIC_SECRET",
    "https://discordapp.com/api/v10/webhooks/123/SYNTHETIC_SECRET",
    "https://user:SYNTHETIC_SECRET@example.invalid/status",
])
def test_common_secret_urls_redacted_without_registration(url):
    assert "SYNTHETIC_SECRET" not in _redact("failed: " + url)


def test_ordinary_url_diagnostics_are_retained():
    message = "GET https://example.invalid/health?page=2 returned 503"
    assert _redact(message) == message


def test_httpx_url_object_argument_is_redacted():
    record = logging.LogRecord("httpx", logging.INFO, "", 0,
                               "HTTP Request: %s %s %d",
                               ("GET", httpx.URL("https://example.invalid/?token=secret"), 200), None)
    EmailRedactFilter().filter(record)
    assert "token=secret" not in record.getMessage()
    assert record.args[2] == 200


def test_uvicorn_access_formatter_keeps_structured_arguments():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                               '%s - "%s %s HTTP/%s" %d',
                               ("127.0.0.1:1234", "GET", "/?token=synthetic-secret", "1.1", 303), None)
    EmailRedactFilter().filter(record)
    output = AccessFormatter('%(client_addr)s "%(request_line)s" %(status_code)s',
                             use_colors=False).format(record)
    assert "synthetic-secret" not in output
    assert "303" in output


def test_exception_chain_and_stack_text_are_redacted():
    register_secret("SYNTHETIC_REGISTERED_VALUE")
    try:
        try:
            raise ValueError("https://example.invalid/?token=synthetic-query")
        except ValueError as exc:
            raise RuntimeError("SYNTHETIC_REGISTERED_VALUE") from exc
    except RuntimeError:
        record = logging.LogRecord("dws", logging.ERROR, "", 0,
                                   "operation failed", (), sys.exc_info())
        record.stack_info = "stack contains SYNTHETIC_REGISTERED_VALUE"
        EmailRedactFilter().filter(record)
        output = logging.Formatter().format(record)
    assert "SYNTHETIC_REGISTERED_VALUE" not in output
    assert "synthetic-query" not in output
    assert "ValueError" in output and "RuntimeError" in output
    assert "operation failed" in output


def test_registered_secret_store_is_bounded(monkeypatch):
    from collections import OrderedDict
    monkeypatch.setattr(log_redact, "_secret_values", OrderedDict())
    for idx in range(log_redact._MAX_SECRET_VALUES + 10):
        register_secret(f"synthetic-rotation-{idx:04d}")
    assert len(log_redact._secret_values) <= log_redact._MAX_SECRET_VALUES
    assert _redact(f"synthetic-rotation-{idx:04d}") == "[redacted]"
