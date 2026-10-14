
import streamlit as st
import pandas as pd
from datetime import datetime

from scam_engine import analyze_message

# Optional screenshot OCR packages
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="ScamShield | Scam Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ---------------- LIGHT THEME CSS ----------------
st.markdown("""
<style>
/* Main application background */
.stApp {
    background: linear-gradient(135deg, #edf6ff 0%, #f8fbff 55%, #eaf2ff 100%);
    color: #172b4d;
}

/* Main content */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1450px;
}

/* General text visibility */
html, body, [class*="css"] {
    color: #172b4d;
}

p, label, li, .stMarkdown {
    color: #243b53;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #dcecff;
    border-right: 1px solid #bfd7f5;
}

section[data-testid="stSidebar"] * {
    color: #17365d !important;
}

/* Headings */
h1, h2, h3 {
    color: #123c69 !important;
    font-weight: 750 !important;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: #ffffff;
    border: 1px solid #c8ddf5;
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 4px 12px rgba(29, 78, 137, 0.08);
}

div[data-testid="stMetricLabel"] {
    color: #405d7a !important;
}

div[data-testid="stMetricValue"] {
    color: #123c69 !important;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button {
    background: #1769aa;
    color: #ffffff !important;
    border: none;
    border-radius: 9px;
    padding: 0.55rem 1rem;
    font-weight: 650;
    transition: 0.2s;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: #104e85;
    color: #ffffff !important;
    border: none;
}

/* Inputs */
.stTextArea textarea,
.stTextInput input,
.stSelectbox div[data-baseweb="select"],
.stDateInput input {
    background: #ffffff !important;
    color: #172b4d !important;
    border: 1px solid #a9c8eb !important;
    border-radius: 9px !important;
}

/* File uploader */
div[data-testid="stFileUploader"] {
    background: #ffffff;
    border: 1px dashed #8bb5e8;
    border-radius: 12px;
    padding: 12px;
}

/* Tables */
div[data-testid="stDataFrame"] {
    background: #ffffff;
    border: 1px solid #c8ddf5;
    border-radius: 10px;
}

/* App banner */
.hero {
    background: linear-gradient(120deg, #d8ebff, #ffffff);
    padding: 26px;
    border: 1px solid #bfd8f5;
    border-radius: 18px;
    margin-bottom: 24px;
    box-shadow: 0 5px 18px rgba(29, 78, 137, 0.08);
}

.hero h1 {
    color: #123c69;
    margin-bottom: 8px;
}

.hero p {
    color: #405d7a;
    font-size: 16px;
}

/* Information cards */
.info-card {
    background: #ffffff;
    border: 1px solid #d0e1f5;
    border-radius: 13px;
    padding: 18px;
    margin-bottom: 12px;
    box-shadow: 0 3px 10px rgba(29, 78, 137, 0.05);
}

/* Footer */
.footer {
    color: #526d8a;
    text-align: center;
    font-size: 13px;
    padding: 18px 0;
}

/* Progress bar */
div[data-testid="stProgressBar"] > div > div {
    background-color: #1769aa;
}
</style>
""", unsafe_allow_html=True)


# ---------------- SESSION STATE ----------------
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# ---------------- HELPER FUNCTIONS ----------------
def save_scan(message, result, scan_type="Message"):
    """Save a scan in the current browser session."""
    st.session_state.scan_history.append({
        "Date and Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Scan Type": scan_type,
        "Message": message,
        "Risk Score": result.get("score", 0),
        "Risk Level": result.get("level", "Unknown"),
        "Categories": ", ".join(result.get("categories", []))
    })


def show_analysis(message, result):
    """Display the scam analysis results."""
    score = max(0, min(100, int(result.get("score", 0))))
    level = str(result.get("level", "Unknown"))

    st.markdown("---")
    st.subheader("🔎 Analysis Results")

    col1, col2 = st.columns(2)
    col1.metric("Risk Score", f"{score}/100")
    col2.metric("Risk Level", level)

    st.progress(score / 100)

    if level.lower() in ("critical", "high"):
        st.error(
            "⚠️ High risk: suspicious warning signs were detected. "
            "Do not send money or share OTPs/passwords."
        )
    elif level.lower() == "medium":
        st.warning(
            "⚠️ Medium risk: check the sender and verify the message "
            "through an independent, trusted source."
        )
    else:
        st.info(
            "ℹ️ Few configured warning signs were detected. "
            "This does not guarantee that the message is safe."
        )

    st.subheader("📌 Detected Categories")
    categories = result.get("categories", [])

    if categories:
        for category in categories:
            st.write(f"• {category}")
    else:
        st.write("No configured scam category matched.")

    st.subheader("🚩 Warning Phrases")
    findings = result.get("findings", [])

    if findings:
        if isinstance(findings, list) and isinstance(findings[0], dict):
            st.dataframe(
                pd.DataFrame(findings),
                use_container_width=True,
                hide_index=True
            )
        else:
            for finding in findings:
                st.write(f"• {finding}")
    else:
        st.write("No configured warning phrases matched.")

    suspicious_urls = result.get("suspicious_urls", [])

    if suspicious_urls:
        st.subheader("🔗 Suspicious Links to Review")
        for url in suspicious_urls:
            st.write(f"• {url}")

    st.subheader("🛡️ Safety Recommendations")
    advice = result.get("advice", [])

    if advice:
        for item in advice:
            st.write(f"• {item}")
    else:
        st.write("Verify the sender before taking action.")

    report = pd.DataFrame([{
        "Message": message,
        "Risk Score": score,
        "Risk Level": level,
        "Categories": ", ".join(categories),
        "Date and Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }])

    st.download_button(
        "⬇️ Download Scan Report",
        data=report.to_csv(index=False).encode("utf-8"),
        file_name="scamshield_report.csv",
        mime="text/csv"
    )


# ---------------- SIDEBAR NAVIGATION ----------------
with st.sidebar:
    st.markdown("## 🛡️ ScamShield")
    st.caption("Smart Scam Detection System")
    st.markdown("---")

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Message Scanner",
            "Screenshot Scanner",
            "Scan History",
            "Analytics",
            "Safety Guide"
        ],
        label_visibility="visible"
    )

    st.markdown("---")
    st.markdown("### 🔐 Stay Safe Online")
    st.caption("Stop • Check • Verify")
    st.caption("Never share your OTP or UPI PIN.")


# ---------------- DASHBOARD ----------------
if page == "Dashboard":

    st.markdown("""
    <div class="hero">
        <h1>🛡️ Welcome to ScamShield</h1>
        <p>
            Detect suspicious messages, identify common scam warning signs,
            and learn how to protect yourself online.
        </p>
    </div>
    """, unsafe_allow_html=True)

    total = len(st.session_state.scan_history)

    high_risk = sum(
        1 for item in st.session_state.scan_history
        if str(item["Risk Level"]).lower() in ("high", "critical")
    )

    avg_score = (
        sum(item["Risk Score"] for item in st.session_state.scan_history) / total
        if total else 0
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("📊 Total Scans", total)
    c2.metric("🚨 High/Critical Risk", high_risk)
    c3.metric("📈 Average Risk Score", f"{avg_score:.1f}/100")

    st.markdown("## ✨ What can ScamShield do?")

    a, b = st.columns(2)

    with a:
        st.markdown("""
        <div class="info-card">
            <h3>💬 Message Scanner</h3>
            <p>Check SMS, WhatsApp messages, job offers and other text.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="info-card">
            <h3>📸 Screenshot Scanner</h3>
            <p>Upload a message screenshot and extract readable text for analysis.</p>
        </div>
        """, unsafe_allow_html=True)

    with b:
        st.markdown("""
        <div class="info-card">
            <h3>📊 Analytics</h3>
            <p>Review your scan history and see the risk levels detected.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="info-card">
            <h3>🛡️ Safety Guide</h3>
            <p>Learn simple ways to identify and avoid common online scams.</p>
        </div>
        """, unsafe_allow_html=True)

    st.warning(
        "Important: ScamShield currently checks configured warning patterns. "
        "It is a supporting tool, not a guarantee that a message is safe."
    )


# ---------------- MESSAGE SCANNER ----------------
elif page == "Message Scanner":

    st.title("💬 Message Scam Scanner")
    st.write("Paste a suspicious message below to check for warning signs.")

    message = st.text_area(
        "Enter message",
        height=200,
        placeholder=(
            "Example: Congratulations! You won a prize. "
            "Click this link and pay a fee to claim it."
        )
    )

    if st.button("🔍 Analyze Message", type="primary"):
        if not message.strip():
            st.warning("Please enter a message first.")
        else:
            try:
                result = analyze_message(message)
                save_scan(message, result, "Message")
                show_analysis(message, result)
            except Exception as error:
                st.error("The message could not be analyzed.")
                st.caption(f"Technical details: {error}")


# ---------------- SCREENSHOT SCANNER ----------------
elif page == "Screenshot Scanner":

    st.title("📸 Screenshot Scam Scanner")
    st.write(
        "Upload a clear screenshot of an SMS, WhatsApp message, "
        "email, or job offer."
    )

    if not OCR_AVAILABLE:
        st.warning(
            "Screenshot scanning needs Pillow and pytesseract. "
            "Install them using the commands shown below."
        )
        st.code("python -m pip install pillow pytesseract")

    else:
        uploaded_file = st.file_uploader(
            "Upload screenshot",
            type=["png", "jpg", "jpeg"]
        )

        if uploaded_file is not None:
            try:
                image = Image.open(uploaded_file).convert("RGB")
                st.image(
                    image,
                    caption="Uploaded screenshot",
                    use_container_width=True
                )

                if st.button("🔍 Extract Text and Analyze", type="primary"):
                    with st.spinner("Reading screenshot..."):
                        try:
                            extracted_text = pytesseract.image_to_string(
                                image,
                                lang="eng+tel"
                            )
                        except Exception:
                            try:
                                extracted_text = pytesseract.image_to_string(
                                    image,
                                    lang="eng"
                                )
                                st.warning(
                                    "Telugu OCR may not be installed. "
                                    "English text extraction was attempted."
                                )
                            except Exception:
                                st.error(
                                    "OCR engine not found. Install Tesseract "
                                    "OCR on your computer and configure its PATH."
                                )
                                extracted_text = ""

                    if not extracted_text.strip():
                        st.warning(
                            "No readable text was found. Try a clearer screenshot."
                        )
                    else:
                        st.subheader("📝 Extracted Text")
                        st.text_area(
                            "Review the extracted text",
                            value=extracted_text,
                            height=160,
                            key="extracted_text"
                        )

                        st.caption(
                            "OCR may make mistakes. Review the extracted text "
                            "before relying on the result."
                        )

                        try:
                            result = analyze_message(extracted_text)
                            save_scan(extracted_text, result, "Screenshot")
                            show_analysis(extracted_text, result)
                        except Exception as error:
                            st.error("The extracted text could not be analyzed.")
                            st.caption(f"Technical details: {error}")

            except Exception:
                st.error("Could not open this image. Try another PNG or JPEG.")


# ---------------- SCAN HISTORY ----------------
elif page == "Scan History":

    st.title("🕘 Scan History")
    st.write("Scans are stored for this active app session.")

    history = st.session_state.scan_history

    if history:
        history_df = pd.DataFrame(history)

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download Full History",
            data=history_df.to_csv(index=False).encode("utf-8"),
            file_name="scamshield_scan_history.csv",
            mime="text/csv"
        )

        if st.button("🗑️ Clear Scan History"):
            st.session_state.scan_history = []
            st.rerun()

    else:
        st.info("No scans yet. Visit Message Scanner to begin.")


# ---------------- ANALYTICS ----------------
elif page == "Analytics":

    st.title("📊 Scam Detection Analytics")

    history = st.session_state.scan_history

    if not history:
        st.info("Complete a few scans to view analytics.")
    else:
        df = pd.DataFrame(history)

        c1, c2 = st.columns(2)
        c1.metric("Total Scans", len(df))
        c2.metric("Average Risk Score", f"{df['Risk Score'].mean():.1f}/100")

        st.subheader("Risk Level Distribution")
        risk_counts = (
            df["Risk Level"]
            .value_counts()
            .rename_axis("Risk Level")
            .reset_index(name="Number of Scans")
        )

        st.bar_chart(
            risk_counts.set_index("Risk Level")["Number of Scans"]
        )

        st.subheader("Risk Score by Scan")
        chart_df = df[["Date and Time", "Risk Score"]].copy()
        chart_df = chart_df.reset_index(drop=True)
        chart_df.index = chart_df.index + 1
        chart_df.index.name = "Scan Number"

        st.line_chart(chart_df["Risk Score"])

        st.subheader("Scan Types")
        st.bar_chart(df["Scan Type"].value_counts())


# ---------------- SAFETY GUIDE ----------------
elif page == "Safety Guide":

    st.title("🛡️ Online Safety Guide")
    st.write("Follow these tips to protect yourself from common scams.")

    tips = [
        (
            "💳 UPI and Payment Fraud",
            "Never share your UPI PIN or OTP. You do not need to enter "
            "your PIN to receive money."
        ),
        (
            "💼 Fake Job Offers",
            "Be careful if a recruiter demands registration fees, "
            "security deposits, or payment to guarantee a job."
        ),
        (
            "🔗 Phishing Links",
            "Do not open unexpected links or enter passwords on unfamiliar "
            "websites. Check the website address carefully."
        ),
        (
            "🎁 Fake Prizes and Lotteries",
            "Unexpected prize messages asking for payment or personal "
            "information are warning signs."
        ),
        (
            "🏦 Bank Impersonation",
            "If a message claims your account will be blocked, contact "
            "your bank using its official app or verified contact details."
        ),
        (
            "📱 OTP Safety",
            "Never share an OTP with someone who calls or messages you."
        ),
        (
            "🚨 Report Suspected Cybercrime",
            "In India, you can report cybercrime at cybercrime.gov.in. "
            "For urgent financial cyber fraud, call 1930."
        )
    ]

    for title, description in tips:
        st.markdown(f"""
        <div class="info-card">
            <h3>{title}</h3>
            <p>{description}</p>
        </div>
        """, unsafe_allow_html=True)

    st.info(
        "Remember: A low risk score does not prove a message is genuine. "
        "Always verify important requests independently."
    )


# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown("""
<div class="footer">
    🛡️ ScamShield 2.0 | Cybersecurity Awareness Project<br>
    Light Blue Edition • Rule-based screening • Stay alert, stay safe
</div>
""", unsafe_allow_html=True)
