import streamlit as st
import google.generativeai as genai
import pandas as pd
import plotly.express as px
import io
import re
import json

# ==============================================================================
# 1. CONFIGURATION & SETUP
# ==============================================================================

st.set_page_config(
    page_title="Traceback v1",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Force Dark Mode and clean UI via CSS
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

def init_gemini():
    """Initialize Gemini API from secrets with fallback logic."""
    try:
        api_key = st.secrets["google"]["api_key"]
        if api_key == "YOUR_API_KEY_HERE":
            st.error("⚠️ API Key missing. Please update .streamlit/secrets.toml")
            return None
        
        genai.configure(api_key=api_key)
        
        # Use the standard Flash model alias
        return genai.GenerativeModel('gemini-1.5-flash')
        
    except Exception as e:
        st.error(f"⚠️ API Key configuration error: {e}")
        return None

def parse_log_file(uploaded_file):
    """
    Basic Parsing: Reads lines. 
    Notes: We let the AI do the heavy interpretation, but we extract simple lines here.
    """
    try:
        stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8"))
        lines = stringio.readlines()
        return lines
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return []

# ==============================================================================
# 3. AI PROMPTS
# ==============================================================================

SYSTEM_PROMPT = """You are a Senior Security Analyst at Traceback specializing in digital forensics
and log analysis.

Your responsibilities:
1. Analyze provided log data to identify suspicious security-related patterns.
2. Assign a Risk Score from 0–10:
   - 0–3: Informational
   - 4–7: Warning / Scanning
   - 8–10: Critical / Active Attack
3. Explain findings in a way that teaches junior users the underlying concept.
4. Generate accurate, copy-paste-ready defensive command suggestions.

Constraints:
- Do not exaggerate threats.
- Do not claim certainty without evidence.
- Do NOT hallucinate IP addresses or timestamps not present in the logs.
- Identify patterns like SQLi, XSS, Brute Force.
- Focus on education and root-cause understanding.

Output Format (JSON):
Return a JSON object with this structure:
{
  "summary_metrics": {
    "total_threats": <int>,
    "most_active_ip": "<ip_or_unknown>",
    "global_risk_score": <int 0-10>
  },
  "findings": [
    {
      "timestamp": "<extracted_timestamp>",
      "attacker_ip": "<extracted_ip>",
      "attack_type": "<short_type_e.g._SQL_Injection>",
      "risk_score": <int>,
      "status": "<Observed/Allowed/Blocked>",
      "raw_log_snippet": "<short_snippet>"
    }
  ],
  "educational_explanation": "<markdown_string_explaining_top_threats>",
  "mitigation_suggestions": {
    "iptables": ["<cmd1>", "<cmd2>"],
    "ufw": ["<cmd1>"],
    "aws_sg": ["<desc_of_rule>"]
  }
}
"""

def analyze_logs_with_ai(model, log_lines):
    """Sends logs to Gemini for structured analysis."""
    # Truncate if too huge, though Flash has large context. 
    # Let's verify size. 1M tokens is plenty for typical prototype logs.
    log_content = "".join(log_lines[:5000]) # Cap at 5000 lines for prototype safety
    
    # FIX: Ensure prompt string is clean logic
    prompt = f"""
    Analyze the following log entries based on the system instructions.
    
    LOG DATA:
    {log_content}
    
    Respond strictly in valid JSON.
    """
    
    try:
        response = model.generate_content([SYSTEM_PROMPT, prompt])
        # Simple cleanup to ensure JSON
        txt = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(txt)
        return data
    except Exception as e:
        st.error(f"AI Analysis failed. It might be due to an old library version or API error. Detail: {e}")
        return None

def chat_investigation(model, log_lines, user_question):
    """Context-aware chat about the specific logs."""
    log_content = "".join(log_lines[:2000]) # Smaller context for chat to stay fast
    
    chat_prompt = f"""
    CONTEXT:
    {log_content}
    
    USER QUESTION:
    {user_question}
    
    INSTRUCTIONS:
    - Answer ONLY using the provided log data.
    - If the answer isn't in the logs, say "I cannot find evidence of that in the current logs."
    - Be educational and professional.
    """
    
    try:
         try:
            response = model.generate_content([SYSTEM_PROMPT, chat_prompt])
            return response.text
         except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                fallback_model = genai.GenerativeModel('gemini-pro')
                response = fallback_model.generate_content([SYSTEM_PROMPT, chat_prompt])
                return response.text
            else:
                 raise e
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
    
    model = init_gemini()
    
    if uploaded_file and model:
        # State Management: Analyze once per file upload
        if 'last_uploaded' not in st.session_state or st.session_state.last_uploaded != uploaded_file.name:
            with st.spinner("🔍 Analyzing patterns & identifying threats..."):
                log_lines = parse_log_file(uploaded_file)
                analysis_result = analyze_logs_with_ai(model, log_lines)
                
                if analysis_result:
                    st.session_state.analysis = analysis_result
                    st.session_state.log_lines = log_lines
                    st.session_state.last_uploaded = uploaded_file.name
                else:
                    st.stop()
        
        # Load data from state
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
        # Middle: Threat Matrix
        # ---------------------------------------------------------
        st.subheader("Threat Matrix")
        if findings:
            df = pd.DataFrame(findings)
            # Reorder columns if they exist
            cols = ['timestamp', 'attacker_ip', 'attack_type', 'risk_score', 'status']
            existing_cols = [c for c in cols if c in df.columns]
            st.dataframe(
                df[existing_cols],
                use_container_width=True,
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "Risk",
                        help="Risk Score 0-10",
                        format="%d",
                        min_value=0,
                        max_value=10,
                    ),
                }
            )
            
            # Secondary: Distribution Chart
            st.subheader("Attack Distribution")
            if 'attack_type' in df.columns:
                counts = df['attack_type'].value_counts()
                fig = px.bar(
                    counts, 
                    orientation='h', 
                    color=counts.index, 
                    title="Threats by Type",
                    template="plotly_dark"
                )
                fig.update_layout(showlegend=False, height=300)
                st.plotly_chart(fig, use_container_width=True)
                
        else:
            st.info("No threats detected or unable to parse findings.")

        # ---------------------------------------------------------
        # Lower: Education & Chat
        # ---------------------------------------------------------
        with st.expander("🎓 Explain Like I'm a Junior", expanded=True):
            st.markdown(education)

        with st.expander("🕵️ Guided Log Investigation", expanded=True):
            st.markdown("ask questions about specific IP addresses, timestamps, or errors found in the logs.")
            user_q = st.text_input("Ask the log (context-aware):", key="log_q")
            if user_q:
                with st.spinner("Investigating..."):
                    answer = chat_investigation(model, st.session_state.log_lines, user_q)
                    st.markdown(f"**Analyst:** {answer}")

        with st.expander("🛡️ Mitigation Suggestions (Auto-Generated)", expanded=False):
            st.warning("These are AI-generated suggestions. Review carefully before applying.")
            
            tabs = st.tabs(["iptables", "UFW", "AWS Security Groups"])
            
            with tabs[0]:
                for cmd in mitigation.get('iptables', []):
                    st.code(cmd, language='bash')
            with tabs[1]:
                for cmd in mitigation.get('ufw', []):
                    st.code(cmd, language='bash')
            with tabs[2]:
                for cmd in mitigation.get('aws_sg', []):
                    st.code(cmd, language='text')

    else:
        # Empty State
        st.info("👋 Welcome to Traceback. Upload a log file to begin analysis.")
        st.markdown(
            """
            **Supported formats:**
            - Server Access Logs (Apache/Nginx)
            - Application Logs
            - Auth Logs
            """
        )

if __name__ == "__main__":
    main()
