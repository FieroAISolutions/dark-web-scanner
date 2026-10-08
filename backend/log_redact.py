"""
Logging filter for email addresses, authentication URL parameters, and
configured secrets. Normal messages, status codes and non-secret URLs remain
useful for diagnostics; exceptions are scrubbed before a formatter emits them.
"""

import logging
import re
import threading
from collections import OrderedDict
from urllib.parse import quote

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9])[A-Za-z0-9.-]*\.([A-Za-z]{2,24})\b")
QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|ticket|access_token|api_key|apikey|key|password|secret)=)[^&\s\"'<>]*"
)
USERINFO_RE = re.compile(r"(?i)(https?://)[^/\s@]+@")
WEBHOOK_RE = re.compile(
    r"(?i)(https?://(?:hooks\.slack\.com/services|(?:canary\.|ptb\.)?"
    r"discord(?:app)?\.com/api(?:/v\d+)?/webhooks)/)[^\s\"'<>]+"
)
AUTH_HEADER_RE = re.compile(r"(?i)(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+")
_secret_values: OrderedDict[str, None] = OrderedDict()
_secret_lock = threading.Lock()
_MAX_SECRET_VALUES = 128


def register_secret(value: str) -> None:
    """Remember a bounded set of secrets before operations may log them.

    Very short strings cannot safely be replaced globally (e.g. an API key
    entered as 'a' would destroy ordinary diagnostics). Contextual URL/header
    redaction still handles short credentials in those locations.
    """
    if not isinstance(value, str) or len(value) < 8:
        return
    with _secret_lock:
        for candidate in (value, quote(value, safe="")):
            _secret_values[candidate] = None
            _secret_values.move_to_end(candidate)
        while len(_secret_values) > _MAX_SECRET_VALUES:
            _secret_values.popitem(last=False)


def _redact(s: str) -> str:
    with _secret_lock:
        values = tuple(_secret_values)
    for value in sorted(values, key=len, reverse=True):
        s = s.replace(value, "[redacted]")
    s = WEBHOOK_RE.sub(r"\1[redacted]", s)
    s = USERINFO_RE.sub(r"\1[redacted]@", s)
    s = QUERY_SECRET_RE.sub(r"\1[redacted]", s)
    s = AUTH_HEADER_RE.sub(r"\1[redacted]", s)
    return EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}***.{m.group(3)}", s)


def _redact_arg(value):
    # Preserve positional structure/numeric types: Uvicorn's AccessFormatter
    # inspects its five arguments, including the integer status code.
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, tuple):
        return tuple(_redact_arg(v) for v in value)
    if isinstance(value, dict):
        return {k: _redact_arg(v) for k, v in value.items()}
    return _redact(str(value))


class EmailRedactFilter(logging.Filter):
    """Legacy class name retained for callers; redacts PII and credentials."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _redact(str(record.msg))
            if record.args:
                record.args = _redact_arg(record.args)
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = _redact(record.exc_text)
            if record.stack_info:
                record.stack_info = _redact(record.stack_info)
        except Exception:
            pass
        return True


def install() -> None:
    """Attach the redaction filter to the root logger and known handlers."""
    f = EmailRedactFilter()
    root = logging.getLogger()
    if not any(isinstance(existing, EmailRedactFilter) for existing in root.filters):
        root.addFilter(f)
    for h in root.handlers:
        if not any(isinstance(existing, EmailRedactFilter) for existing in h.filters):
            h.addFilter(f)
    # Common loggers we know spew through their own handlers
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "httpx", "httpcore",
                 "dws", "dws.scanner"):
        lg = logging.getLogger(name)
        if not any(isinstance(existing, EmailRedactFilter) for existing in lg.filters):
            lg.addFilter(f)
        for h in lg.handlers:
            if not any(isinstance(existing, EmailRedactFilter) for existing in h.filters):
                h.addFilter(f)
