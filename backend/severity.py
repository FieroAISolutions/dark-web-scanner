"""
Severity scoring for breach findings.

Maps HIBP breach metadata to a four-tier severity (critical / high / medium / low)
plus a numeric score (0–100+) and human-readable reasons. Designed to be
deterministic and cheap so it can be recomputed on every read.
"""

from typing import Iterable

# HIBP DataClass strings — names kept verbatim to match the API. A few synonyms
# are included to cover historical variants HIBP has used.

CREDENTIALS = {
    "Passwords",
    "Password hashes",
    "Encrypted passwords",
    "Historical passwords",
    "Auth tokens",
    "Mnemonic phrases",
    "Private keys",
    "Encrypted keys",
}

FINANCIAL = {
    "Bank account numbers",
    "Banking PINs",
    "Credit cards",
    "Credit card CVV",
    "Financial transactions",
    "Payment histories",
    "Payment methods",
    "Taxation records",
}

GOV_ID = {
    "Social Security Numbers", "SSN",
    "Passport numbers",
    "Drivers licenses", "Driver's licenses",
    "Government issued IDs",
    "Voter registration details",
}

HIGH_PII = {
    "Security questions and answers",
    "Mothers' maiden names", "Mother's maiden names",
    "Partial credit card data",
    "Health insurance information",
    "Personal health data",
    "HIV statuses",
    "Sexual orientations",
    "Sexual fetishes",
    "Sexual preferences",
    "Biometric data",
    "Private messages",
    "Email messages",
    "Chat logs",
    "SMS messages",
    "Password hints",
    "GPS locations",
}

MEDIUM_PII = {
    "Phone numbers", "Partial phone numbers",
    "Physical addresses",
    "Geographic locations",
    "Dates of birth", "Partial dates of birth",
    "IP addresses",
    "Recovery email addresses",
    "Employers", "Job titles",
    "Income levels", "Net worths",
    "Marital statuses",
    "Family members' names", "Names of family members",
    "Vehicle details",
    "MAC addresses", "IMEI numbers", "IMSI numbers",
    "Photos", "Audio recordings",
    "Device information",
    "Utility bills",
    "Home ownership statuses", "Home loan information",
    "Account balances",
    "Religions",
    "Political views", "Political donations",
}

LEVELS = ("critical", "high", "medium", "low")
COLORS = {"critical": "#f85149", "high": "#d29922", "medium": "#bb8009", "low": "#8b949e"}


def _summary(classes: set, hits: set, max_show: int = 3) -> str:
    sorted_hits = sorted(hits)
    if len(sorted_hits) <= max_show:
        return ", ".join(sorted_hits)
    return ", ".join(sorted_hits[:max_show]) + f" +{len(sorted_hits) - max_show} more"


def compute(breach: dict) -> dict:
    """Return {level, score, reasons} for a breach.

    Accepts either HIBP-style keys (DataClasses, IsSensitive, …) or our
    DB row keys (data_classes, is_sensitive, …).
    """
    classes = set(breach.get("data_classes") or breach.get("DataClasses") or [])
    is_sensitive  = bool(breach.get("is_sensitive")  or breach.get("IsSensitive"))
    is_verified   = bool(breach.get("is_verified")   or breach.get("IsVerified"))
    is_fabricated = bool(breach.get("is_fabricated") or breach.get("IsFabricated"))
    is_spam_list  = bool(breach.get("is_spam_list")  or breach.get("IsSpamList"))
    is_retired    = bool(breach.get("is_retired")    or breach.get("IsRetired"))

    reasons: list[str] = []
    score = 0

    cred = classes & CREDENTIALS
    if cred:
        score += 60
        reasons.append(f"Credentials exposed ({_summary(classes, cred)})")

    fin = classes & FINANCIAL
    if fin:
        score += 55
        reasons.append(f"Financial data ({_summary(classes, fin)})")

    gov = classes & GOV_ID
    if gov:
        score += 55
        reasons.append(f"Government IDs ({_summary(classes, gov)})")

    if is_sensitive:
        score += 30
        reasons.append("HIBP-flagged sensitive breach")

    high = classes & HIGH_PII
    if high:
        score += 25
        reasons.append(f"Sensitive PII ({_summary(classes, high)})")

    med = classes & MEDIUM_PII
    if med:
        score += 12
        reasons.append(f"Personal info ({_summary(classes, med)})")

    if is_fabricated:
        score = min(score, 10)
        reasons.append("HIBP marks this fabricated")
    if is_spam_list:
        score = min(score, 15)
        reasons.append("Spam-list source (low confidence)")
    if not is_verified and score > 10:
        score -= 10
        reasons.append("Unverified breach")
    if is_retired and score > 10:
        score -= 5
        reasons.append("Retired listing")

    score = max(0, score)

    if score >= 55:
        level = "critical"
    elif score >= 30:
        level = "high"
    elif score >= 12:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("Minimal data exposure (e.g. just email/username)")

    return {"level": level, "score": score, "reasons": reasons}


def compute_paste(paste: dict) -> dict:
    """Pastes don't expose data classes, so severity is based on dump size only."""
    n = paste.get("email_count") or paste.get("EmailCount") or 0
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        n = 0
    if n >= 1_000_000:
        return {"level": "high", "score": 35, "reasons": [f"Mass dump ({n:,} addresses)"]}
    if n >= 10_000:
        return {"level": "medium", "score": 18, "reasons": [f"Large dump ({n:,} addresses)"]}
    return {"level": "low", "score": 5, "reasons": ["Paste mention"]}


def rank(level: str) -> int:
    """Numeric rank for sorting; higher = more severe."""
    return {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(level, 0)


def by_severity(items: Iterable[dict]) -> list[dict]:
    """Sort findings by severity desc, then first_seen_at desc."""
    return sorted(
        items,
        key=lambda f: (rank(f.get("severity", {}).get("level", "low")),
                       f.get("first_seen_at") or ""),
        reverse=True,
    )
