
import re
from urllib.parse import urlparse

SCAM_RULES = {
    "Job Scam": {
        "phrases": [
            "registration fee",
            "pay to get job",
            "job guaranteed",
            "processing fee",
            "work from home earn",
            "pay for interview",
        ],
        "weight": 25,
    },
    "UPI / Payment Fraud": {
        "phrases": [
            "share your upi pin",
            "enter your upi pin",
            "send money to receive",
            "pay to unlock",
            "collect request",
            "refund processing fee",
        ],
        "weight": 35,
    },
    "Phishing / Credential Theft": {
        "phrases": [
            "share your otp",
            "tell me your otp",
            "share your password",
            "verify your account immediately",
            "account will be blocked",
            "click here to claim",
        ],
        "weight": 30,
    },
    "Impersonation / Prize Scam": {
        "phrases": [
            "you have won a prize",
            "lottery winner",
            "claim your reward",
            "send otp to receive",
            "pretending to be bank",
        ],
        "weight": 20,
    },
}

URGENT_PHRASES = [
    "act now",
    "immediately",
    "limited time",
    "urgent",
    "account suspended",
    "last chance",
]

def analyze_message(message):
    text = message.lower()
    findings = []
    categories = []
    score = 0

    for category, rule in SCAM_RULES.items():
        matches = [
            phrase for phrase in rule["phrases"]
            if phrase in text
        ]

        if matches:
            categories.append(category)
            score += rule["weight"]
            for phrase in matches:
                findings.append({
                    "category": category,
                    "phrase": phrase,
                    "reason": (
                        f"This phrase may indicate "
                        f"{category.lower()}."
                    ),
                })

    urgent_matches = [
        phrase for phrase in URGENT_PHRASES
        if phrase in text
    ]

    if urgent_matches:
        score += min(10, len(urgent_matches) * 5)
        for phrase in urgent_matches:
            findings.append({
                "category": "Urgency",
                "phrase": phrase,
                "reason": (
                    "Pressure to act quickly can be "
                    "a warning sign."
                ),
            })

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        message,
        flags=re.IGNORECASE,
    )

    suspicious_urls = []

    for raw_url in urls:
        cleaned = raw_url.rstrip(".,!?;:)]}")
        candidate = (
            cleaned if "://" in cleaned
            else "https://" + cleaned
        )

        try:
            parsed = urlparse(candidate)
            host = parsed.hostname or ""
            reasons = []

            if not host or "." not in host:
                reasons.append("Unusual domain structure")

            if parsed.scheme != "https":
                reasons.append("Link does not use HTTPS")

            if host and re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}", host
            ):
                reasons.append("URL uses an IP address")

            if "xn--" in host:
                reasons.append("Internationalized domain")

            if reasons:
                suspicious_urls.append({
                    "url": cleaned,
                    "reasons": reasons,
                })
                score += 15

        except ValueError:
            suspicious_urls.append({
                "url": cleaned,
                "reasons": ["URL could not be parsed"],
            })
            score += 15

    score = min(score, 100)

    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    if findings or suspicious_urls:
        advice = [
            "Do not share OTPs, passwords, or UPI PINs.",
            "Verify the sender through an official channel.",
            "Do not pay fees to claim an unverified job or prize.",
        ]
    else:
        advice = [
            "No configured warning patterns were detected.",
            "This does not prove the message is safe.",
            "Verify unexpected requests independently.",
        ]

    return {
        "score": score,
        "level": level,
        "categories": categories,
        "findings": findings,
        "suspicious_urls": suspicious_urls,
        "advice": advice,
    }
