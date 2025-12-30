import streamlit as st
import google.generativeai as genai
import pandas as pd
import plotly.express as px
import json
import os

# --------------------------------------------------------------------------------
# 1. Page Configuration & Professional Design System
# --------------------------------------------------------------------------------
st.set_page_config(
    page_title="Traceback",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Professional SaaS CSS Injection
st.markdown("""
<style>
    /* Global Typography & Background */
    .stApp {
        background-color: #1A1C20; /* Neutral Charcoal */
        color: #E0E0E0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Metric Cards (Calm) */
    .pro-card {
        background-color: #26292E;
        border: 1px solid #3E424B;
        border-radius: 8px;
        padding: 20px;
        text-align: left;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12);
        transition: all 0.2s ease;
    }
    
    .pro-card:hover {
        border-color: #4DB6AC; /* Teal Accent hover */
    }

    .pro-card .label {
        color: #9AA0A6;
        font-size: 0.85rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }
    
    .pro-card .value {
        color: #FFFFFF;
        font-size: 1.8rem;
        font-weight: 600;
    }

    .pro-card .sub-value {
        color: #4DB6AC; /* Teal Accent */
        font-size: 0.9rem;
        margin-left: 5px;
    }

    /* Headers */
    h1, h2, h3 {
        color: #FFFFFF;
        font-weight: 600;
        letter-spacing: -0.5px;
    }
    
    /* DataFrame */
    .stDataFrame {
        border: 1px solid #3E424B;
        border-radius: 8px;
    }

    /* Buttons */
    .stButton > button {
        background-color: #4DB6AC;
        color: #1A1C20;
        border: none;
        border-radius: 4px;
        font-weight: 600;
        padding: 0.5rem 1rem;
    }
    .stButton > button:hover {
        background-color: #80CBC4;
        color: #1A1C20;
    }

    /* Chat Messages */
    .stChatMessage {
        background-color: #26292E;
        border-radius: 8px;
        border: 1px solid #3E424B;
    }
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------------------------------------
# 2. Logic: Analysis & Helpers
# --------------------------------------------------------------------------------
def analyze_logs_with_gemini(log_content):
    """
    Sends log content to Gemini for security analysis.
    """
    try:
        # User secrets use [google]
        api_key = st.secrets["google"]["api_key"]
        genai.configure(api_key=api_key)
    except Exception:
        try:
             # Fallback if they changed it
             api_key = st.secrets["gemini"]["api_key"]
             genai.configure(api_key=api_key)
        except:
             st.error("Configuration Error: API Key missing in secrets.toml (checked [google] and [gemini])")
             return None

    # Robust Model Selection Strategy
    model = None
    # Prioritize 2.0/3.0 flash, fallback to Pro
    candidates = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-pro']
    
    for model_name in candidates:
        try:
            model = genai.GenerativeModel(model_name)
            # Test simple generation to verify access
            # This might be slow so we skip explicit test and just return the object
            # But the error usually happens at generate_content time.
            # We will use this model object.
            break 
        except:
            continue
            
    if not model:
        # Fallback to hardcoded string if loop fails strangely
        model = genai.GenerativeModel('gemini-pro')

    system_instruction = """
    You are a Senior Security Analyst. Your goal is to identify security events from logs and explain them clearly to a junior developer.
    
    Output MUST be valid JSON:
    {
        "threats": [
            {
                "timestamp": "string",
                "attacker_ip": "string",
                "attack_type": "string (SQL Injection, Brute Force, XSS)",
                "risk_level": "string (Low, Medium, High, Critical)",
                "status": "string (Allowed/Blocked)",
                "explanation": "string (Educational explanation)",
                "recommended_action": "string (Configuration/Rule)"
            }
        ],
        "summary": {
            "total_events": int,
            "high_risk_count": int,
            "most_active_ip": "string",
            "active_ip_count": int
        }
    }
    """

    prompt = f"""
    {system_instruction}
    
    ANALYZE THE FOLLOWING LOGS:
    {log_content[:40000]} 
    """

    try:
        with st.spinner(f"Analyzing log data..."):
            response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            return json.loads(response.text)
    except Exception as e:
        # Deep Fallback if 404 occurs during generation
        if "404" in str(e) or "not found" in str(e).lower():
            try:
                 fallback = genai.GenerativeModel('gemini-pro')
                 response = fallback.generate_content(prompt)
                 # Pro doesn't enforce JSON mode strictly, try to parse
                 text = response.text.replace("```json", "").replace("```", "").strip()
                 return json.loads(text)
            except Exception as e2:
                 st.error(f"Analysis Error (Fallback failed): {str(e2)}")
                 return None
        st.error(f"Analysis Error: {str(e)}")
        return None

def ask_log_assistant(question, log_context, chat_history):
    # Chat Model Logic
    try:
        api_key = st.secrets["google"]["api_key"]
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
    except:
        model = genai.GenerativeModel('gemini-pro')

    prompt = f"""
    You are the Traceback Assistant, a professional security educator.
    CONTEXT: {json.dumps(log_context)}
    CHAT HISTORY: {chat_history}
    USER QUESTION: {question}
    Answer professionally, concisely, and helpfully.
    """
    try:
        response = model.generate_content(prompt)
        return response.text
    except:
        return "I'm having trouble connecting to the AI right now. Please try again."

# --------------------------------------------------------------------------------
# 3. Main Interface
# --------------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Traceback")
    st.caption("v3.0 | Log Analysis Platform")
    st.markdown("---")
    uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt", "csv"])
    st.markdown("---")
    st.info("Upload server logs to identify security risks and learning opportunities.")

if uploaded_file is not None:
    try:
        log_content = uploaded_file.getvalue().decode("utf-8")
    except:
        log_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")

    if 'analysis_result' not in st.session_state:
        st.session_state.analysis_result = analyze_logs_with_gemini(log_content)

    results = st.session_state.analysis_result
    
    if results:
        threats = results.get("threats", [])
        summary = results.get("summary", {})

        # --- Top Metrics ---
        col1, col2, col3 = st.columns(3)
        
        def pro_metric(label, value, subtext, col):
            with col:
                st.markdown(f"""
                <div class="pro-card">
                    <div class="label">{label}</div>
                    <div class="value">{value}<span class="sub-value">{subtext}</span></div>
                </div>
                """, unsafe_allow_html=True)

        pro_metric("Events Detected", summary.get("total_events", 0), "Total", col1)
        pro_metric("Most Active Source", summary.get("most_active_ip", "N/A"), f"({summary.get('active_ip_count', 0)} events)", col2)
        pro_metric("Critical Risks", summary.get("high_risk_count", 0), "Direct Threats", col3)

        st.markdown("---")

        # --- Main Content (Table + Chart) ---
        col_table, col_chart = st.columns([0.65, 0.35])

        with col_table:
            st.subheader("Security Event Log")
            if threats:
                df = pd.DataFrame(threats)
                # Ensure columns exist
                needed_cols = ['timestamp', 'risk_level', 'attack_type', 'attacker_ip', 'status']
                for c in needed_cols:
                    if c not in df.columns:
                        df[c] = "N/A"
                
                display_df = df[needed_cols]
                
                st.dataframe(
                    display_df,
                    use_container_width=True,
                    height=450,
                    column_config={
                        "timestamp": "Timestamp",
                        "risk_level": "Risk",
                        "attack_type": "Event Type",
                        "attacker_ip": "Source IP",
                        "status": "Outcome"
                    },
                    hide_index=True
                )
            else:
                st.success("No security events identified.")

        with col_chart:
            st.subheader("Event Distribution")
            if threats and not df.empty:
                # Professional Donut Chart (Teal Palette)
                # Colors: Teal, Slate, Grey tones
                pro_colors = ['#4DB6AC', '#80CBC4', '#B2DFDB', '#546E7A', '#78909C']
                
                if 'attack_type' in df.columns:
                    fig = px.pie(df, names='attack_type', hole=0.7, color_discrete_sequence=pro_colors)
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', 
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color="#E0E0E0",
                        showlegend=True,
                        legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
                        margin=dict(t=0, b=50, l=0, r=0)
                    )
                    fig.update_traces(textinfo='percent')
                    st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # --- "Ask the Log" Assistant ---
        st.subheader("Ask the Log")
        st.caption("Ask questions about specific events to understand the root cause.")

        if "messages" not in st.session_state:
            st.session_state.messages = []

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

        if prompt := st.chat_input("E.g., 'Explain why the SQL Injection attempt was blocked?'"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.write(prompt)

            with st.chat_message("assistant"):
                with st.spinner("Reasoning..."):
                    response_text = ask_log_assistant(prompt, results, st.session_state.messages[-5:])
                    st.write(response_text)
            
            st.session_state.messages.append({"role": "assistant", "content": response_text})

else:
    # Empty State
    st.markdown("""
    <div style='text-align: center; padding: 100px; color: #9AA0A6;'>
        <h2>Ready to Analyze</h2>
        <p>Please upload a log file to begin the review.</p>
    </div>
    """, unsafe_allow_html=True)
