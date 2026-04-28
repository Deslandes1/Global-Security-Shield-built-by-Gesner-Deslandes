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
    page_icon="🛡️",
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

# ---------- LOGIN PAGE ----------
def login_page():
    st.title("🛡️ Global Security Shield – built by Gesner Deslandes")
    st.markdown("### Enterprise‑grade protection for your Streamlit apps and Python web applications")
    st.markdown("---")
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown("#### 🔐 Login to Dashboard")
        with st.form("login_form"):
            pwd = st.text_input("Password", type="password")
            if st.form_submit_button("Access Dashboard"):
                if pwd == "20082010":
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Incorrect password.")
    st.markdown("---")
    st.markdown("""### What is the Global Security Shield?
- ✅ Real‑time attack blocking – SQL injection, XSS, path traversal, command injection.
- ✅ Central dashboard – Register your apps, view attack logs, add custom rules.
- ✅ Easy integration – Add just two lines of code to protect any Streamlit or Python web app.
- ✅ Autonomous protection – Once deployed, the shield protects your apps without manual intervention.

**How it works:**  
The shield runs inside your application. It checks every user input (URL parameters, forms, file uploads) against a set of attack patterns. If a match is found, the request is rejected and a log is sent to this dashboard.

**Get started:**  
1. Deploy this dashboard (you're looking at it).  
2. Register your apps below to obtain API keys.  
3. Copy the `shield.py` module into your app's repository.  
4. Initialise the shield with your API key and wrap user inputs with `sanitize_input()`.
""")
    with st.expander("📘 Example integration code"):
        st.code("""
from shield import WebAppShield, SecurityException

# Initialise the shield (use the API key from this dashboard)
shield = WebAppShield("My App", api_key="your-api-key-here")
shield.protect_streamlit()

# For every user input:
user_text = st.text_input("Enter something")
try:
    safe_text = shield.sanitize_input(user_text)
    # use safe_text safely
except SecurityException:
    st.error("Attack detected – request blocked.")
    st.stop()
        """, language="python")

# ---------- MAIN DASHBOARD ----------
def main_dashboard():
    st.title("🛡️ Global Security Shield Dashboard – built by Gesner Deslandes")
    st.markdown("Protect all your Python web applications from SQL injection, XSS, and other attacks.")

    st.sidebar.markdown("## 🔧 Shield Status")
    st.sidebar.success("🟢 Active – monitoring your apps")
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Registered apps:** {len(st.session_state.apps)}")
    st.sidebar.markdown(f"**Total threats blocked:** {len(st.session_state.logs)}")
    st.sidebar.markdown("---")
    st.sidebar.info(
        "📘 **Quick start**\n\n"
        "1. Register your app below → get an API key.\n"
        "2. Add the `shield.py` module to your app.\n"
        "3. Use the API key to initialise the shield.\n\n"
        "All attacks will be logged here automatically."
    )
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.rerun()

    tab1, tab2, tab3, tab4 = st.tabs(["📋 Registered Apps", "⚠️ Threat Logs", "⚙️ Custom Rules", "🧪 Live Demo"])

    with tab1:
        st.subheader("➕ Register a new application")
        with st.form("register_form"):
            app_name = st.text_input("Application name (e.g., 'Haiti Radar')")
            app_url = st.text_input("Deployed URL (optional, for reference)")
            submitted = st.form_submit_button("Register")
            if submitted and app_name:
                api_key = generate_api_key()
                st.session_state.apps[app_name] = {
                    "url": app_url,
                    "api_key": api_key,
                    "created_at": datetime.datetime.now().isoformat()
                }
                st.success(f"✅ App '{app_name}' registered!")
                st.code(f"API Key: {api_key}", language="text")
                st.info("Copy this key and use it in your app's shield initialisation.")
        st.subheader("📱 Registered Applications")
        if st.session_state.apps:
            for name, info in st.session_state.apps.items():
                with st.expander(f"🔐 {name}"):
                    st.write(f"**URL:** {info.get('url', 'Not provided')}")
                    st.write(f"**API Key:** `{info['api_key']}`")
                    st.write(f"**Created:** {info['created_at']}")
                    if st.button(f"🗑️ Revoke {name}", key=f"revoke_{name}"):
                        del st.session_state.apps[name]
                        st.rerun()
        else:
            st.info("No applications registered yet. Use the form above.")

    with tab2:
        st.subheader("⚠️ Security Alerts (real‑time)")
        if st.session_state.logs:
            df = pd.DataFrame(st.session_state.logs)
            df = df.sort_values("timestamp", ascending=False)
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False)
            st.download_button("📥 Download Logs (CSV)", csv, "security_logs.csv", "text/csv")
        else:
            st.info("No threats detected yet. When your protected apps block an attack, it will appear here.")
        st.markdown("---")
        st.markdown("### 🔌 Log Ingestion Endpoint")
        st.markdown("Protected apps send logs to this dashboard via a GET request. The URL is:")
        base_url = st.get_option("browser.serverAddress") or "your-dashboard.streamlit.app"
        st.code(f"https://{base_url}?log={{...}}", language="text")

    with tab3:
        st.subheader("➕ Add Custom Detection Rule")
        attack_type = st.selectbox("Attack type", list(DEFAULT_PATTERNS.keys()) + ["custom"])
        if attack_type == "custom":
            attack_type = st.text_input("New attack type name (e.g., 'custom_script')")
        new_pattern = st.text_input("Regex pattern (e.g., `(<.*>)`)", placeholder=r"<script.*>")
        if st.button("Add Pattern"):
            if attack_type and new_pattern:
                if attack_type not in st.session_state.custom_rules:
                    st.session_state.custom_rules[attack_type] = []
                st.session_state.custom_rules[attack_type].append(new_pattern)
                st.success(f"Pattern added to **{attack_type}**.")
                st.info("Custom rules will be applied to all subsequent checks.")
            else:
                st.error("Please fill both fields.")
        st.subheader("📋 Current Custom Rules")
        if st.session_state.custom_rules:
            for atype, patterns in st.session_state.custom_rules.items():
                st.markdown(f"**{atype}**")
                for p in patterns:
                    st.code(p, language="text")
        else:
            st.info("No custom rules added yet.")

    with tab4:
        st.markdown("## 🧪 Test the Shield Live")
        st.markdown("This section simulates how the shield would block malicious inputs in your own apps.")
        simulate_attack_detection()
        st.markdown("---")
        st.markdown("### 📊 How the shield integrates into your app")
        st.markdown("""
**Step 1 – Add `shield.py` to your project**  
The middleware is a single file. Place it in the same folder as your `app.py`.

**Step 2 – Initialise the shield**  
```python
from shield import WebAppShield, SecurityException
shield = WebAppShield("Your App Name", api_key="your-api-key")
shield.protect_streamlit()
