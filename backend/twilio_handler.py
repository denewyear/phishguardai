"""
twilio_handler.py
Formats phishing analysis results as concise SMS text and wraps
them in TwiML XML for Twilio to deliver back to the sender.
"""

from twilio.twiml.messaging_response import MessagingResponse


# ── Emoji / label maps ────────────────────────────────────────────
RISK_EMOJI = {
    "HIGH RISK":   "🚨",
    "MEDIUM RISK": "⚠️",
    "LOW RISK":    "✅",
}

RISK_ACTION = {
    "HIGH RISK":   "DO NOT click links or reply to this message.",
    "MEDIUM RISK": "Proceed with caution. Verify the sender directly.",
    "LOW RISK":    "Looks relatively safe. Stay alert for unexpected requests.",
}


def format_sms_response(result: dict, stats: dict | None = None) -> str:
    """
    Build a concise SMS-friendly string from an analysis result.

    Keeps total length under ~320 chars (2 SMS segments) so it
    arrives as a single readable message on most carriers.

    Args:
        result: dict returned by detect.analyze_message()
                Keys: risk_score, classification, patterns_detected,
                      recommendation, color
        stats:  optional dict with keys high, medium, low, total
                (from database.get_user_stats) — appended as a
                one-line summary when provided

    Returns:
        Formatted plain-text string ready to be put in a <Message> tag.
    """
    classification = result.get("classification", "UNKNOWN")
    score          = result.get("risk_score", 0)
    patterns       = result.get("patterns_detected", [])

    emoji = RISK_EMOJI.get(classification, "ℹ️")

    # Line 1 — risk level + score
    lines = [f"{emoji} {classification} ({score}/100)"]

    # Line 2 — top detected patterns (max 2, truncated to keep SMS short)
    if patterns:
        top = patterns[:2]
        pattern_str = ", ".join(top)
        if len(pattern_str) > 60:
            pattern_str = pattern_str[:57] + "..."
        lines.append(f"Detected: {pattern_str}")

    # Line 3 — short actionable recommendation
    action = RISK_ACTION.get(classification, result.get("recommendation", ""))
    lines.append(action)

    # Line 4 (optional) — user stats summary
    if stats:
        total = stats.get("total") or 0
        high  = stats.get("high")  or 0
        if total and int(total) > 0:
            lines.append(f"\nYour totals: {total} analyzed, {high} high-risk caught.")

    return "\n".join(lines)


def handle_incoming_sms(from_number: str, message_body: str,
                         result: dict, stats: dict | None = None) -> str:
    """
    Build a complete TwiML XML response string for Twilio.

    Twilio POSTs the inbound SMS details to our /sms endpoint.
    This function takes the parsed fields and the analysis result,
    formats the reply text, and wraps it in TwiML so Twilio knows
    to send it back as an SMS to `from_number`.

    Args:
        from_number:  Sender's E.164 phone number e.g. "+15558675309"
        message_body: Raw text the user sent (used only for logging here)
        result:       Analysis dict from detect.analyze_message()
        stats:        Optional per-user stats dict for the footer line

    Returns:
        TwiML XML string, e.g.:
        <?xml version="1.0" encoding="UTF-8"?>
        <Response>
            <Message>🚨 HIGH RISK (85/100)\n...</Message>
        </Response>
    """
    response_text = format_sms_response(result, stats=stats)

    resp = MessagingResponse()
    resp.message(response_text)

    return str(resp)


def handle_help_command() -> str:
    """
    Return TwiML for the HELP / INFO / ? command.
    Explains what PhishGuard does and lists available commands.
    """
    text = (
        "📱 PhishGuard AI\n"
        "Forward any suspicious SMS or text here.\n"
        "I'll analyse it and tell you if it's a scam.\n\n"
        "Commands:\n"
        "HELP  — this message\n"
        "STATS — your analysis history"
    )
    resp = MessagingResponse()
    resp.message(text)
    return str(resp)


def handle_stats_command(stats: dict) -> str:
    """
    Return TwiML for the STATS command.
    Shows the user's personal analysis totals.

    Args:
        stats: dict from database.get_user_stats() or a phone-scoped
               equivalent — expects keys: total, high, medium, low, avg_score
    """
    total     = stats.get("total")     or 0
    high      = stats.get("high")      or 0
    medium    = stats.get("medium")    or 0
    low       = stats.get("low")       or 0
    avg_score = stats.get("avg_score") or 0

    text = (
        f"📊 Your PhishGuard Stats\n"
        f"Total analysed : {total}\n"
        f"🚨 High risk   : {high}\n"
        f"⚠️  Medium risk : {medium}\n"
        f"✅ Low / safe  : {low}\n"
        f"Avg risk score : {avg_score}/100"
    )
    resp = MessagingResponse()
    resp.message(text)
    return str(resp)


def handle_rate_limit(count: int, limit: int, window: str = "hour") -> str:
    """
    Return TwiML when a sender has exceeded the rate limit.

    Args:
        count:  Number of messages sent in the current window
        limit:  The cap (e.g. 10)
        window: Human-readable window label e.g. "hour" or "day"
    """
    text = (
        f"⏰ Rate limit reached ({count}/{limit} per {window}).\n"
        "Please wait before sending more messages.\n"
        "Reply HELP for instructions."
    )
    resp = MessagingResponse()
    resp.message(text)
    return str(resp)
