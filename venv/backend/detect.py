import re

SUSPICIOUS_DOMAINS = [".tk", ".ml", ".cf", ".ga", ".gq", "bit.ly", "tinyurl.com",
                      "t.co", "goo.gl", "ow.ly", "short.link", "rebrand.ly"]
URGENCY_KEYWORDS   = ["urgent", "act now", "immediately", "verify", "suspended",
                      "expires", "limited time", "account locked", "unusual activity",
                      "security alert", "click here", "confirm now", "validate"]
GENERIC_GREETINGS  = ["dear customer", "dear user", "dear valued", "dear account holder",
                      "dear member", "hello user"]
FINANCIAL_BAIT     = ["won", "winner", "prize", "reward", "gift card", "cash",
                      "refund", "lottery", "claim", "free", r"\$\d+"]
ACCOUNT_THREATS    = ["suspended", "terminated", "blocked", "unauthorized",
                      "compromised", "hacked", "locked", "disabled"]
PERSONAL_INFO      = ["ssn", "social security", "password", "credit card",
                      "cvv", "pin", "bank account", "routing number", "otp",
                      "one-time", "login credentials"]
BRAND_IMPERSONATION = ["amazon", "paypal", "apple", "microsoft", "google", "irs",
                        "fedex", "ups", "usps", "netflix", "bank of america",
                        "chase", "wells fargo", "citibank"]


def analyze_message(text: str) -> dict:
    score = 0
    patterns = []
    lower = text.lower()

    # URL detection
    urls = re.findall(r"https?://\S+|www\.\S+", lower)
    if urls:
        score += 15
        patterns.append("Contains URL")
        for url in urls:
            if any(d in url for d in SUSPICIOUS_DOMAINS):
                score += 30
                patterns.append("Suspicious shortened/free domain URL")
                break

    # Urgency
    matched = [k for k in URGENCY_KEYWORDS if k in lower]
    if matched:
        score += 20
        patterns.append(f"Urgency language ({', '.join(matched[:2])})")

    # Generic greeting
    if any(g in lower for g in GENERIC_GREETINGS):
        score += 10
        patterns.append("Generic/impersonal greeting")

    # Financial bait
    fin_matched = [k for k in FINANCIAL_BAIT if re.search(k, lower)]
    if fin_matched:
        score += 20
        patterns.append(f"Financial incentive language ({fin_matched[0]})")

    # Account threats
    if any(t in lower for t in ACCOUNT_THREATS):
        score += 15
        patterns.append("Account threat language")

    # Personal info request
    if any(p in lower for p in PERSONAL_INFO):
        score += 25
        patterns.append("Requests sensitive personal information")

    # Brand impersonation
    brands = [b for b in BRAND_IMPERSONATION if b in lower]
    if brands:
        score += 10
        patterns.append(f"Possible brand impersonation ({brands[0].title()})")

    # Excessive caps
    alpha = [c for c in text if c.isalpha()]
    if alpha and sum(1 for c in alpha if c.isupper()) / len(alpha) > 0.5:
        score += 10
        patterns.append("Excessive capitalization")

    score = min(score, 100)

    if score >= 60:
        classification = "HIGH RISK"
        recommendation = "Do not click any links or provide personal information. Verify directly with the official organisation."
        color = "red"
    elif score >= 30:
        classification = "MEDIUM RISK"
        recommendation = "Exercise caution. Verify the sender's identity through official channels before taking any action."
        color = "orange"
    else:
        classification = "LOW RISK"
        recommendation = "No major red flags detected. Still be cautious with unexpected messages."
        color = "green"

    return {
        "risk_score": score,
        "classification": classification,
        "recommendation": recommendation,
        "patterns_detected": patterns,
        "color": color,
    }
