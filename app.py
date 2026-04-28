# app.py – Global Security Shield Dashboard (built by Gesner Deslandes)
import streamlit as st
import pandas as pd
import datetime
import json
import secrets
import re
from typing import Dict, Optional, Tuple

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="🛡️ Global Security Shield – built by Gesner Deslandes",
    page_icon="🌐",
    layout="wide"
)

# ---------- AUTHENTICATION ----------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# ---------- DATA STORAGE ----------
if "apps" not in st.session_state:
    st.session_state.apps = {}
if "logs" not in st.session_state:
    st.session_state.logs = []
if "custom_rules" not in st.session_state:
    st.session_state.custom_rules = {}

# ---------- DEFAULT ATTACK PATTERNS ----------
DEFAULT_PATTERNS = {
    "sql_injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(union.*select)",
        r"(insert.*into)",
        r"(delete.*from)",
        r"(drop.*table)",
        r"(select.*from.*where)",
        r"(or\s+1\s*=\s*1)"
    ],
    "xss": [
        r"<script",
        r"javascript:",
        r"onload=",
        r"onerror=",
        r"onclick=",
        r"alert\(",
        r"prompt\("
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f"
    ],
    "command_injection": [
        r"(\|)|(\&)|(;)",
        r"(ping)|(nslookup)|(wget)"
    ],
    "malicious_user_agents": [
        r"sqlmap",
        r"nikto",
        r"nmap"
    ]
}

# ---------- HELPER FUNCTIONS ----------
def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def is_malicious(text: str, custom_rules: dict) -> tuple:
    if not isinstance(text, str):
        return False, None
    for attack_type, patterns in DEFAULT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return True, attack_type
    for attack_type, patterns in custom_rules.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return True, attack_type
    return False, None

def simulate_attack_detection():
    st.markdown("### 🧪 Live Attack Simulation")
    st.markdown("Type a malicious string below to see how the shield blocks it.")
    test_input = st.text_input("Test input (e.g., `<script>alert(1)</script>` or `' OR 1=1 --`)")
    if test_input:
        malicious, attack_type = is_malicious(test_input, st.session_state.custom_rules)
        if malicious:
            st.error(f"🚨 BLOCKED! Potential **{attack_type}** attack detected.")
            st.session_state.logs.append({
                "app_name": "DEMO (Live Test)",
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "data": {"type": "demo_input", "value": test_input, "attack_type": attack_type}
            })
        else:
            st.success("✅ Input appears safe (no known patterns).")

def process_incoming_log():
    params = st.query_params
    if "log" in params:
        try:
            log_data = json.loads(params["log"])
            log_data["received_at"] = datetime.datetime.utcnow().isoformat()
            st.session_state.logs.append(log_data)
            st.query_params.clear()
            st.rerun()
        except Exception:
            pass

# ---------- CUSTOM CSS FOR COLORFUL LOGIN ----------
st.markdown("""
<style>
    /* Login page gradient background */
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    /* Center the login card */
    .login-card {
        background-color: rgba(255,255,255,0.95);
        border-radius: 20px;
        padding: 2rem;
        box-shadow: 0 20px 35px rgba(0,0,0,0.2);
        text-align: center;
        max-width: 450
