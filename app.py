
import re
from urllib.parse import urlparse
import streamlit as st

# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="ScamShield",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CUSTOM DESIGN ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #eef2ff, #ffffff);
}
.block-container {
    max-width: 1100px;
    padding-top: 2rem;
}
.hero {
    background: linear-gradient(120deg, #101a35, #3155a6);
    padding: 35px;
    border-radius: 20px;
    color: white;
    text-align: center;
}
.hero h1 {
    color: white;
    font-size: 44px;
}
.hero p {
    color: #e0e7ff;
    font-size: 18px;
}
.card {
    background: white;
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #e2e8f0;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SCAM DETECTION RULES ----------------

FEE_WORDS = [
    "registration fee",
    "processing fee",
    "security deposit",
    "training fee",
    "upfront payment",
    "refundable fee",
    "pay to confirm",
    "pay to secure",
    "interview fee"
]

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "today only",
    "limited slots",
    "last chance",
    "confirm today",
    "expires today"
]

SENSITIVE_WORDS = [
    "share your otp",
    "send your otp",
    "otp for verification",
    "one-time password",
    "share your password",
    "send your password",
    "share your pin",
    "login credentials"
]

JOB_WORDS = [
    "job offer",
    "selected for a job",
    "work from home",
    "guaranteed job",
    "joining letter",
    "recruitment",
    "job vacancy"
]

PHISHING_WORDS = [
    "account will be blocked",
    "verify your account",
    "account is suspended",
    "update your kyc",
    "claim your prize",
    "click here to verify",
    "verify your bank account"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "shorturl.at",
    "ow.ly"
]

SUSPICIOUS_EXTENSIONS = [
    ".zip",
    ".click",
    ".top",
    ".work",
    ".gq",
    ".tk"
]


def extract_urls(text):
    """Extract URLs without opening or visiting them."""

    pattern = (
        r'(?i)\b(?:https?://|www\.)[^\s<>"\']+'
        r'|\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}'
        r'(?:/[^\s<>"\']*)?'
    )

    urls = re.findall(pattern, text)
    results = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        normalized = url
        if normalized.lower().startswith("www."):
            normalized = "http://" + normalized
        elif not normalized.lower().startswith(
            ("http://", "https://")
        ):
            normalized = "http://" + normalized

        parsed = urlparse(normalized)
        domain = parsed.hostname or ""

        # Ignore malformed and non-domain values.
        if "." in domain and " " not in domain:
            results.append({
                "url": url,
                "domain": domain.lower()
            })

    return results


def analyze_message(message):
    """Detect warning signs using transparent rules."""

    text = message.lower()
    signals = []
    score = 0

    def add_signal(title, explanation, points):
        nonlocal score

        signals.append({
            "title": title,
            "explanation": explanation,
            "points": points
        })
        score += points

    # Check for payment requests.
    if any(word in text for word in FEE_WORDS):
        add_signal(
            "💸 Upfront payment request",
            "The message mentions a fee or payment to obtain "
            "or confirm an opportunity. Verify the employer "
            "before paying anything.",
            4
        )

    # Check for urgent language.
    if any(word in text for word in URGENCY_WORDS):
        add_signal(
            "⏰ Urgency or pressure",
            "The message may be pressuring you to act quickly. "
            "Take time to verify it independently.",
            2
        )

    # Check for OTP/password requests.
    if any(word in text for word in SENSITIVE_WORDS):
        add_signal(
            "🔐 Sensitive information warning",
            "Never share OTPs, passwords, PINs, or login "
            "credentials with unexpected contacts.",
            4
        )

    # Check for job-related messages.
    if any(word in text for word in JOB_WORDS):
        add_signal(
            "💼 Job or recruitment message",
            "This message discusses a job opportunity. "
            "Check the company and recruiter through "
            "official channels.",
            1
        )

    # Check for common phishing language.
    if any(word in text for word in PHISHING_WORDS):
        add_signal(
            "🎣 Possible phishing language",
            "Unexpected account verification, KYC, or prize "
            "messages may lead to fake websites.",
            3
        )

    # Inspect URLs as text only.
    urls = extract_urls(message)

    for item in urls:
        domain = item["domain"]

        if any(domain == s or domain.endswith("." + s)
               for s in SHORTENERS):
            add_signal(
                "🔗 Shortened URL detected",
                "Shortened links hide their final destination. "
                "Check the destination independently.",
                2
            )

        if any(domain.endswith(ext)
               for ext in SUSPICIOUS_EXTENSIONS):
            add_signal(
                "🌐 Unusual domain extension",
                "This domain extension deserves extra checking. "
                "An unusual extension alone does not prove a scam.",
                2
            )

        if domain.startswith("xn--") or ".xn--" in domain:
            add_signal(
                "🌐 Encoded domain detected",
                "Encoded domain names can sometimes disguise "
                "look-alike websites.",
                2
            )

        if domain.count("-") >= 3 or len(domain) > 35:
            add_signal(
                "🔎 Unusual domain structure",
                "The domain is long or contains many hyphens. "
                "Verify that it matches the official website.",
                1
            )

    # Remove duplicate warning titles.
    unique_signals = []
    seen = set()

    for signal in signals:
        if signal["title"] not in seen:
            unique_signals.append(signal)
            seen.add(signal["title"])

    signals = unique_signals
    score = sum(signal["points"] for signal in signals)

    # Determine risk level.
    if score >= 6:
        level = "HIGH"
        color = "#dc2626"
        summary = (
            "Several warning signs were detected. "
            "Do not pay or share sensitive information "
            "until you verify the sender."
        )
    elif score >= 3:
        level = "CAUTION"
        color = "#d97706"
        summary = (
            "Some warning signs were detected. "
            "Pause and verify the message independently."
        )
    else:
        level = "LOW"
        color = "#15803d"
        summary = (
            "Few configured warning signs were detected. "
            "This does not prove the message is safe."
        )

    return {
        "score": score,
        "level": level,
        "color": color,
        "summary": summary,
        "signals": signals,
        "urls": urls
    }


# ---------------- HEADER ----------------

st.markdown("""
<div class="hero">
    <h1>🛡️ ScamShield</h1>
    <p>Pause Before You Pay. Check Before You Trust.</p>
    <p>Explainable Phishing &amp; Job-Scam Checker</p>
</div>
""", unsafe_allow_html=True)

st.write("")

st.info(
    "ScamShield checks messages for possible warning signs "
    "and explains why they matter. It does not guarantee "
    "that a message is genuine or fraudulent."
)

# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.title("🛡️ ScamShield")
    st.write("Your first step toward safer online decisions.")

    st.divider()

    st.subheader("Features")
    st.write("✅ Job-scam warning checks")
    st.write("✅ Phishing-language detection")
    st.write("✅ URL text inspection")
    st.write("✅ Explainable risk score")
    st.write("✅ Safety recommendations")

    st.divider()

    st.subheader("Safety tips")
    st.write("🔐 Never share OTPs or passwords.")
    st.write("💸 Do not pay to secure a job.")
    st.write("🔗 Do not open suspicious links.")
    st.write("🏢 Verify recruiters through official websites.")

    st.caption(
        "Privacy: this application does not intentionally "
        "save submissions to a database."
    )

# ---------------- MAIN INPUT ----------------

st.header("🔍 Analyze a Suspicious Message")

st.write(
    "Paste a suspicious SMS, email, recruitment message, "
    "or website URL below."
)

demo_message = (
    "Congratulations! You are selected for a job. "
    "Pay a registration fee today to confirm your offer. "
    "Reply with your OTP for verification."
)

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

def load_demo():
    st.session_state.message_text = demo_message

message = st.text_area(
    "Message or URL",
    key="message_text",
    height=200,
    placeholder=(
        "Paste your suspicious message here..."
    )
)

col1, col2 = st.columns(2)

with col1:
    analyze_clicked = st.button(
        "🔎 Analyze Message",
        type="primary",
        use_container_width=True
    )

with col2:
    st.button(
        "📝 Load Demo Example",
        on_click=load_demo,
        use_container_width=True
    )

# ---------------- ANALYSIS RESULTS ----------------

if analyze_clicked:

    if not message.strip():
        st.warning("Please enter a message or URL first.")

    else:
        result = analyze_message(message)

        st.divider()
        st.header("📊 Analysis Report")

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Risk Level",
            result["level"]
        )

        c2.metric(
            "Warning Signals",
            len(result["signals"])
        )

        c3.metric(
            "Rule Score",
            result["score"]
        )

        st.markdown(
            f"""
            <div style="
                background:white;
                border-left:7px solid {result['color']};
                padding:20px;
                border-radius:12px;
                margin:15px 0;
                border-top:1px solid #e5e7eb;
                border-right:1px solid #e5e7eb;
                border-bottom:1px solid #e5e7eb;
            ">
                <h3 style="color:{result['color']}">
                    {result['level']} RISK ASSESSMENT
                </h3>
                <p>{result['summary']}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Display detected warning signs.
        st.subheader("🚩 Warning Signals Detected")

        if result["signals"]:

            for signal in result["signals"]:
                with st.container(border=True):
                    st.markdown(
                        f"**{signal['title']}**"
                    )
                    st.write(signal["explanation"])
                    st.caption(
                        f"Rule score: {signal['points']}"
                    )

        else:
            st.success(
                "No configured warning rules were triggered. "
                "Still verify the sender before trusting "
                "the message."
            )

        # Display URLs without opening them.
        st.subheader("🌐 URL Inspection")

        if result["urls"]:
            st.warning(
                "These URLs were inspected as text only. "
                "ScamShield does not open them."
            )

            for item in result["urls"]:
                st.code(
                    f"URL: {item['url']}\n"
                    f"Domain: {item['domain']}"
                )
        else:
            st.write(
                "No obvious URL was found in this message."
            )

        # Recommendations.
        st.subheader("🛡️ Recommended Safe Actions")

        recommendations = [
            "Do not pay upfront fees to obtain a job.",
            "Never share OTPs, passwords, or PINs.",
            "Visit the organisation's official website "
            "by typing its address yourself.",
            "Contact the company using contact details "
            "published on its official website.",
            "Do not open suspicious links or attachments."
        ]

        for item in recommendations:
            st.markdown(f"- {item}")

        st.info(
            "If you lose money to cyber fraud in India, "
            "contact your bank immediately and report it "
            "through helpline 1930 or cybercrime.gov.in."
        )

        st.caption(
            "Disclaimer: ScamShield is a rule-based "
            "educational prototype. It can miss scams or "
            "flag legitimate messages. The score is guidance, "
            "not proof."
        )

# ---------------- SAMPLE TEST CASES ----------------

st.divider()
st.header("🧪 Try Sample Messages")

st.write(
    "Use these examples to demonstrate the application "
    "during your hackathon presentation."
)

with st.expander("Example 1: Suspicious Job Offer"):
    st.code(demo_message)
    st.write(
        "Expected result: HIGH risk because the message "
        "contains a fee request, urgency, and an OTP-related "
        "warning."
    )

with st.expander("Example 2: Ordinary Interview Notice"):
    st.code(
        "Thank you for applying. Please check the interview "
        "schedule on our company careers page. Our recruitment "
        "team will contact you with further details."
    )
    st.write(
        "Expected result: Usually LOW risk under the "
        "configured rules. This is not proof of legitimacy."
    )

with st.expander("Example 3: Possible Phishing Message"):
    st.code(
        "Your account will be blocked today. "
        "Click here to verify your account immediately."
    )
    st.write(
        "Expected result: CAUTION or HIGH depending on "
        "the warning rules triggered."
    )

# ---------------- FOOTER ----------------

st.divider()

st.markdown(
    """
    <div style="text-align:center; padding:20px;">
        <h3>🛡️ ScamShield</h3>
        <p>DETECT • EXPLAIN • GUIDE</p>
        <p>Think Before You Click. Verify Before You Pay.</p>
        <small>
            Hackathon MVP | Built with Python and Streamlit
        </small>
    </div>
    """,
    unsafe_allow_html=True
)
