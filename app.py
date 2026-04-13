import streamlit as st
from transformers import pipeline
import pandas as pd
from datetime import datetime
import re
import requests
import os
import base64
from dotenv import load_dotenv


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# -------------------------------
# Streamlit Page Config
# -------------------------------
st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("<h1 style='text-align:center; color: #FF6600;'>🛡️ ScamShield AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; color: gray;'>AI-powered phishing & scam detection system</p>", unsafe_allow_html=True)
st.markdown("---")

# -------------------------------
# Load Hugging Face Model
# -------------------------------
@st.cache_resource
def load_model():
    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=-1)

classifier = load_model()

# -------------------------------
# Scam Labels
# -------------------------------
labels = ["phishing scam", "financial scam", "stranded abroad scam", "safe message"]

# -------------------------------
# Local Logging
# -------------------------------
def log_analysis(platform, sender_email, message, risk, confidence):
    df = pd.DataFrame([[datetime.now(), platform, sender_email, message, risk, confidence]],
                      columns=["Timestamp", "Platform", "Sender Email", "Message", "Risk", "Confidence"])
    try:
        df_old = pd.read_csv("scam_log.csv")
        df = pd.concat([df_old, df], ignore_index=True)
    except FileNotFoundError:
        pass
    df.to_csv("scam_log.csv", index=False)

# -------------------------------
# VirusTotal URL Scan
# -------------------------------
def scan_url_virustotal(url):
    if not VT_API_KEY:
        return "VirusTotal API key not set."
    headers = {"x-apikey": VT_API_KEY}
    try:
        # Base64 encode URL as VirusTotal expects
        url_bytes = url.encode("utf-8")
        url_b64 = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        # Submit URL
        resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if resp.status_code != 200:
            return f"Error submitting URL: {resp.status_code} (VirusTotal)"
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_b64}", headers=headers)
        if report.status_code != 200:
            return f"Error retrieving report: {report.status_code} (VirusTotal)"
        stats = report.json()["data"]["attributes"]["last_analysis_stats"]
        return f"{stats} (Source: VirusTotal)"
    except Exception as e:
        return f"Error scanning URL: {e} (VirusTotal)"

# -------------------------------
# VirusTotal Domain Scan (for sender email)
# -------------------------------
def scan_domain_virustotal(domain):
    if not VT_API_KEY:
        return "VirusTotal API key not set."
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if resp.status_code != 200:
            return f"Error scanning domain: {resp.status_code} (VirusTotal)"
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return f"{stats} (Source: VirusTotal)"
    except Exception as e:
        return f"Error scanning domain: {e} (VirusTotal)"

# -------------------------------
# User Input Section
# -------------------------------
st.subheader("Step 1: Provide Message Details")
col1, col2 = st.columns([1,1])

with col1:
    platform = st.selectbox("Select message source:", ["Email", "WhatsApp", "SMS", "Other"])

with col2:
    link_input = st.text_input("Paste any link here (optional):")

# Show sender email input only if platform is Email
sender_email = ""
if platform == "Email":
    sender_email = st.text_input("Enter sender's email:")

st.subheader("Step 2: Paste Suspicious Message")
user_input = st.text_area("Message/Email Content:")

# -------------------------------
# Analyze Button
# -------------------------------
if st.button("Analyze"):
    if user_input.strip() != "":
        with st.spinner("🧠 AI is analyzing..."):
            # AI Classification
            result = classifier(user_input, labels)
            top_label = result["labels"][0]
            score = result["scores"][0]

            # Detect links and attachments
            links = re.findall(r"https?://\S+", user_input)
            if link_input:
                links.append(link_input)
            has_link = len(links) > 0
            has_attachment = any(ext in user_input.lower() for ext in [".pdf", ".zip", ".docx", "attached"])

            # Determine Risk
            reason = ""
            action = ""
            color = "green"

            if "scam" in top_label or "phishing" in top_label or "stranded abroad" in top_label:
                risk = "🚨 Dangerous"
                color = "red"
                reason = "Message matches known scam/phishing patterns."
                action = "Do NOT respond. Report immediately."
            else:
                risk = "⚠️ Suspicious"
                color = "orange"
                reason = "Message appears somewhat unusual or suspicious."
                action = "Verify sender and avoid clicking links."

            # Add context
            reason += f" Platform: {platform}."
            if sender_email:
                reason += f" Sender: {sender_email}."
            if has_link:
                reason += " Contains link(s) – check carefully!"
            if has_attachment:
                reason += " Mentions attachment(s) – scan before opening!"

            # -------------------------------
            # Display AI Results
            # -------------------------------
            st.markdown(f"<h2 style='color:{color}'>{risk}</h2>", unsafe_allow_html=True)
            st.markdown(f"**Confidence:** {round(score*100,2)}%")
            st.markdown(f"**Reason:** {reason}")
            st.markdown(f"**Recommended Action:** {action}")

            # -------------------------------
            # VirusTotal Link Scan
            # -------------------------------
            if has_link:
                st.subheader("🔗 VirusTotal Link Scan Results")
                st.info("Results below are from VirusTotal and independent from AI analysis.")
                for link in links:
                    vt_result = scan_url_virustotal(link)
                    st.markdown(f"- {link} → {vt_result}")

            # -------------------------------
            # VirusTotal Sender Domain Scan
            # -------------------------------
            if sender_email:
                domain_match = re.search(r"@(\S+)", sender_email)
                if domain_match:
                    domain = domain_match.group(1)
                    vt_domain_result = scan_domain_virustotal(domain)
                    st.subheader("📧 VirusTotal Sender Domain Scan")
                    st.info("Results below are from VirusTotal and independent from AI analysis.")
                    st.markdown(f"- Sender Domain: {domain} → {vt_domain_result}")

            # Log Analysis
            log_analysis(platform, sender_email, user_input, risk, round(score*100,2))
            st.success("Analysis Complete ✅")
    else:
        st.warning("Please enter a message to analyze.")

# -------------------------------
# Optional Log Display
# -------------------------------
if st.checkbox("Show Analysis History"):
    try:
        df_log = pd.read_csv("scam_log.csv")
        st.dataframe(df_log.sort_values(by="Timestamp", ascending=False))
    except FileNotFoundError:
        st.info("No analysis history found yet.")