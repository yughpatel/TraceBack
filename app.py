import streamlit as st
from google import genai
from google.genai import types
import pandas as pd
import plotly.express as px
import json
from io import StringIO

# ==============================================================================
# 1. CONFIGURATION & SETUP
# ==============================================================================

st.set_page_config(
    page_title="Traceback v1",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Force Dark Mode and Clean UI
st.markdown("""
<style>
    /* Global Cleanliness */
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
        font-family: 'Inter', sans-serif;
    }
    
    /* Metrics Cards */
    div[data-testid="stMetric"] {
        background-color: #262730;
        border-radius: 8px;
        padding: 15px;
        border: 1px solid #363945;
    }
    
    /* Hide Deploy Button & Footer */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Headers */
    h1, h2, h3 {
        color: #E0E0E0 !important;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 2. HELPER FUNCTIONS
# ==============================================================================

def init_client():
    """Initialize the new GenAI Client."""
    try:
        api_key = st.secrets["google"]["api_key"]
        return genai.Client(api_key=api_key)
    except Exception as e:
        st.error(f"⚠️ API Key error: {e}")
        return None

def parse_log_file(uploaded_file):
    """Basic Parsing: Reads lines."""
    try:
        stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
        lines = stringio.readlines()
        return lines
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return []

# ==============================================================================
# 3. AI PROMPTS
# ==============================================================================

SYSTEM_PROMPT = """You are a Senior Security Analyst at Traceback specializing in
digital forensics and log analysis.

Responsibilities:
1. Analyze provided log data to identify suspicious security patterns (Brute Force, SQLi, XSS).
2. Assign a Risk Score from 0–10:
   - 0–3: Informational
   - 4–7: Warning
   - 8–10: Critical
3. Frame findings as "suspicious patterns" or "potential attack indicators". Do NOT claim certainty.
4. Explain findings in a way that teaches the user.

Output Format (JSON):
{
  "summary_metrics": {
    "total_threats": int,
    "most_active_ip": "string",
    "global_risk_score": int
  },
  "findings": [
    {
      "timestamp": "string",
      "attacker_ip": "string",
      "attack_type": "string",
      "risk_score": int,
      "status": "string (Observed/Allowed/Blocked)"
    }
  ],
  "educational_explanation": "markdown string explaining the top threats",
  "mitigation_suggestions": {
    "iptables": ["cmd1", "cmd2"],
    "ufw": ["cmd1"],
    "aws_sg": ["description of rule"]
  }
}
"""

def analyze_logs_with_ai(client, log_lines):
    """Sends logs to Gemini for structured analysis using the new SDK."""
    # Cap at 5000 lines
    log_content = "".join(log_lines[:5000])
    
    prompt = f"""
    Analyze the following log entries based on the system instructions.
    
    LOG DATA:
    {log_content}
    
    Respond strictly in valid JSON.
    """
    
    try:
        # New SDK Call Structure - Using Gemini 3 Preview as verified available
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=[SYSTEM_PROMPT, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        return json.loads(response.text)
    except Exception as e:
        st.error(f"AI Analysis failed: {e}")
        return None

def chat_investigation(client, log_lines, user_question):
    """Context-aware chat about specific logs."""
    log_content = "".join(log_lines[:2000])
    
    chat_prompt = f"""
    CONTEXT:
    {log_content}
    
    USER QUESTION:
    {user_question}
    
    INSTRUCTIONS:
    - Answer ONLY using the provided log data.
    - If the answer isn't in the logs, refuse to answer.
    - Be educational and professional.
    """
    
    try:
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=[SYSTEM_PROMPT, chat_prompt]
        )
        return response.text
    except Exception as e:
        return f"Error investigating: {e}"

# ==============================================================================
# 4. MAIN APP LOGIC
# ==============================================================================

def main():
    # Sidebar
    st.sidebar.title("🛡️ Traceback v1")
    st.sidebar.markdown("*Democratizing cybersecurity understanding for everyone.*")
    
    uploaded_file = st.sidebar.file_uploader("Upload Log File", type=['log', 'txt', 'csv'])
    
    # Initialize Client
    client = init_client()
    
    if uploaded_file and client:
        # Analyze once per file
        if 'last_uploaded' not in st.session_state or st.session_state.last_uploaded != uploaded_file.name:
            with st.spinner("🔍 Analyzing patterns..."):
                log_lines = parse_log_file(uploaded_file)
                analysis_result = analyze_logs_with_ai(client, log_lines)
                
                if analysis_result:
                    st.session_state.analysis = analysis_result
                    st.session_state.log_lines = log_lines
                    st.session_state.last_uploaded = uploaded_file.name
                else:
                    st.stop()
        
        # Load from State
        data = st.session_state.get('analysis', {})
        metrics = data.get('summary_metrics', {})
        findings = data.get('findings', [])
        education = data.get('educational_explanation', "")
        mitigation = data.get('mitigation_suggestions', {})
        
        # ---------------------------------------------------------
        # Header: Metrics
        # ---------------------------------------------------------
        col1, col2, col3 = st.columns(3)
        col1.metric("Threats Detected", metrics.get('total_threats', 0))
        col2.metric("Most Active IP", metrics.get('most_active_ip', 'N/A'))
        col3.metric("Global Risk Score", f"{metrics.get('global_risk_score', 0)}/10")
        
        st.divider()
        
        # ---------------------------------------------------------
        # Middle: Deep Dive (Threat Matrix)
        # ---------------------------------------------------------
        st.subheader("Deep Dive")
        if findings:
            df = pd.DataFrame(findings)
            cols = ['timestamp', 'attacker_ip', 'attack_type', 'risk_score', 'status']
            for c in cols:
                if c not in df.columns: df[c] = 'N/A'
            
            st.dataframe(
                df[cols],
                use_container_width=True,
                column_config={
                    "risk_score": st.column_config.NumberColumn("Risk", format="%d"),
                }
            )
            
            st.subheader("Attack Type Distribution")
            if 'attack_type' in df.columns:
                counts = df['attack_type'].value_counts()
                fig = px.bar(counts, orientation='h', color=counts.index, template="plotly_dark")
                fig.update_layout(showlegend=False, height=300)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No suspicious patterns detected.")

        st.divider()

        # ---------------------------------------------------------
        # Lower: Learn, Investigate, Mitigate
        # ---------------------------------------------------------
        
        with st.expander("🎓 Explain Like I'm a Junior", expanded=True):
            st.markdown(education)

        with st.expander("🕵️ Ask the log (context-aware)", expanded=True):
            user_q = st.text_input("Guided investigation:", key="log_q", placeholder="e.g., Why is IP 192.168.1.5 suspicious?")
            if user_q:
                with st.spinner("Investigating..."):
                    answer = chat_investigation(client, st.session_state.log_lines, user_q)
                    st.markdown(f"**Analyst:** {answer}")

        with st.expander("🛡️ Mitigation Suggestions", expanded=False):
            st.warning("These are suggestions for review. Do not apply blindly.")
            tabs = st.tabs(["iptables", "UFW", "AWS Security Groups"])
            with tabs[0]:
                for cmd in mitigation.get('iptables', []): st.code(cmd, language='bash')
            with tabs[1]:
                for cmd in mitigation.get('ufw', []): st.code(cmd, language='bash')
            with tabs[2]:
                for cmd in mitigation.get('aws_sg', []): st.code(cmd, language='text')

    else:
        st.info("👋 Welcome to Traceback. Upload a log file to begin analysis.")
        st.caption("Supported: .log, .txt, .csv")

if __name__ == "__main__":
    main()
