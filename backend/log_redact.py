"""
Logging filter that redacts email addresses to avoid spilling PII into
log files. `alice@example.com` becomes `a***@e***.com`. Domains are
preserved at TLD-level so operational issues remain debuggable.
"""

import logging
import re

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9])[A-Za-z0-9.-]*\.([A-Za-z]{2,24})\b")


def _redact(s: str) -> str:
    return EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}***.{m.group(3)}", s)


class EmailRedactFilter(logging.Filter):
    """Redacts email addresses in log messages and any string args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: _redact(v) if isinstance(v, str) else v
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        _redact(a) if isinstance(a, str) else a
                        for a in record.args
                    )
        except Exception:
            pass
        return True


def install() -> None:
    """Attach the redaction filter to the root logger and known handlers."""
    f = EmailRedactFilter()
    root = logging.getLogger()
    root.addFilter(f)
    for h in root.handlers:
        h.addFilter(f)
    # Common loggers we know spew through their own handlers
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "dws", "dws.scanner"):
        lg = logging.getLogger(name)
        lg.addFilter(f)
        for h in lg.handlers:
            h.addFilter(f)
