"""
Combines signals from NLP, headers, authentication, URLs, and network
intelligence into a single 0-100 risk score with a full explanation trail.

This is a deterministic, rule-based fusion model — NOT a trained classifier,
and it makes no claim about measured accuracy/precision/recall. Those numbers
only belong in tests/eval once real evaluation has been run against labeled
data (see PHASE 4 / SECTION 13 of the project brief).
"""
from config import get_settings

settings = get_settings()

# Category caps keep any single evidence source from dominating the score,
# and map to the configurable weights in config.py (0-1 fractions of 100).
_CATEGORY_CAP = {
    "nlp": 100 * settings.RISK_WEIGHTS["nlp"],
    "auth": 100 * settings.RISK_WEIGHTS["auth"],
    "url": 100 * settings.RISK_WEIGHTS["url"],
    "header": 100 * settings.RISK_WEIGHTS["header"],
    "network": 100 * settings.RISK_WEIGHTS["network"],
    "attachment": 100 * settings.RISK_WEIGHTS["attachment"],
}

_SIGNAL_CATEGORY = {
    "reply_to_mismatch": "header", "return_path_mismatch": "header",
    "missing_message_id": "header", "no_received_headers": "header",
    "message_id_domain_mismatch": "header", "duplicate_headers": "header",
    "x_originating_ip_private": "header", "automated_mailer_signature": "header",
    "dkim_signature_domain_mismatch": "header", "date_far_future": "header", "date_unparseable": "header",
    "spf_fail": "auth", "dkim_fail": "auth", "dmarc_fail": "auth",
    "dkim_alignment_issue": "auth", "no_authentication_data": "auth",
    "lookalike_domain": "url", "ip_based_url": "url", "url_shortener": "url",
    "visible_text_mismatch": "url", "excessive_subdomains": "url", "unusual_port": "url",
    "sender_domain_lookalike": "url",
    "ip_abuse_reports": "network", "vpn_proxy_tor_infrastructure": "network",
    "nlp_content_classification": "nlp", "keyword_heuristic_match": "nlp",
    "suspicious_attachment_extension": "attachment", "double_extension_attachment": "attachment",
    "macro_enabled_attachment": "attachment",
}


def fuse_signals(all_signals: list[dict]) -> tuple[int, list[dict]]:
    """Sums signal weights per category, caps each category at its configured
    share of 100, then sums the capped categories. Returns (score, signals)."""
    per_category: dict[str, float] = {}
    for sig in all_signals:
        cat = _SIGNAL_CATEGORY.get(sig["name"], "header")
        per_category[cat] = per_category.get(cat, 0) + sig["weight"]

    capped_total = 0.0
    for cat, total in per_category.items():
        capped_total += min(total, _CATEGORY_CAP.get(cat, total))

    score = max(0, min(100, round(capped_total)))
    return score, all_signals


def classify_from_score(score: int, nlp_label: str, url_signals: list[dict], auth: dict) -> str:
    """Deterministic classification bucket. Conservative: requires the score
    threshold AND at least one supporting category before naming a specific
    threat type, otherwise falls back to a generic 'suspicious'."""
    if score < 25:
        return "benign"
    if score < 50:
        return "suspicious"

    has_lookalike = any(s["name"] == "lookalike_domain" for s in url_signals)
    has_url_risk = bool(url_signals)
    auth_failed = auth.get("dmarc") == "fail" or auth.get("spf") == "fail"

    if has_lookalike and auth_failed:
        return "phishing"
    if has_url_risk and score >= 65:
        return "phishing"
    if auth_failed and not has_url_risk:
        return "impersonation"
    return "suspicious"


def confidence_from_signals(signal_count: int, score: int) -> int:
    """More corroborating signals + a decisive score → higher confidence.
    This is a heuristic, not a calibrated probability — labeled as such."""
    base = min(60, 15 * signal_count)
    decisiveness = abs(score - 50)  # further from the ambiguous midpoint = more decisive
    return max(30, min(95, base + decisiveness // 2))
