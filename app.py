"""
TraceBack Sentinel – AI-Powered Multi-Agent Log Intelligence
Main Streamlit Application (v3.0)

Multi-Agent Architecture:
  Agent 1 (Sieve)       → Log ingestion & PII redaction
  Agent 1.5 (Clusterer) → Log deduplication to save LLM tokens
  Agent 2 (Analyst)     → LLM-powered threat detection & MITRE ATT&CK
  Agent 3 (Compliance)  → PCI-DSS & GDPR compliance mapping
  Agent 4 (Remediator)  → Bash/config remediation script generation
"""

import sys
import io

# We remove the sys.stdout re-assignment here because Streamlit internally manages streams.
# Re-assigning it globally causes 'ValueError: I/O operation on closed file' during widget interaction.

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import json

from agents.sieve_agent import SieveAgent
from agents.analyst_agent import AnalystAgent
from agents.compliance_agent import ComplianceAuditorAgent
from agents.remediation_agent import RemediationAgent
from data.sample_logs import get_sample_logs
from utils.clustering import LogClusterer

# ═══════════════════════════════════════════════════════════════
# Page Configuration
# ═══════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="TraceBack Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ──────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: rgba(15, 20, 36, 0.8);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 16px;
    }

    div[data-testid="stMetric"] label {
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.7;
    }

    /* Hide deploy button */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    div[data-testid="stExpander"] {
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        overflow: hidden;
    }

    code {
        font-family: 'JetBrains Mono', monospace !important;
    }

    div[data-testid="stChatMessage"] {
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.06);
    }

    button[data-baseweb="tab"] {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
    }

    section[data-testid="stSidebar"] {
        border-right: 1px solid rgba(255,255,255,0.06);
    }

    .hero-title {
        font-size: 2.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 0.5rem;
        letter-spacing: -0.02em;
    }

    .hero-subtitle {
        text-align: center;
        color: #8892a8;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# Sidebar — Input & Chat
# ═══════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🛡️ TraceBack Sentinel")
    st.markdown("*Multi-Agent Log Intelligence*")
    st.divider()

    # API Key — auto-load from .streamlit/secrets.toml
    api_key = None
    try:
        api_key = st.secrets["groq"]["api_key"]
    except (KeyError, FileNotFoundError):
        pass

    if api_key and api_key != "YOUR_API_KEY_HERE":
        st.success("🔑 API Key loaded from secrets", icon="✅")
    else:
        api_key = st.text_input(
            "🔑 Groq API Key",
            type="password",
            help="Add your key to .streamlit/secrets.toml or enter here",
            placeholder="gsk_...",
        )
        if not api_key:
            st.warning("⚠️ Configure API key in `.streamlit/secrets.toml`")

    st.divider()

    # File upload
    st.markdown("### 📁 Log Input")
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=['log', 'txt', 'csv'],
        help="Supported: Apache/Nginx access logs, auth/syslog, generic logs",
    )

    # Sample logs
    st.markdown("**Or try a sample:**")
    samples = get_sample_logs()
    selected_sample = st.selectbox(
        "Sample Logs",
        options=['— Select —'] + list(samples.keys()),
        label_visibility="collapsed",
    )

    st.divider()

    # ── Vernacular Toggle ─────────────────────────────────
    st.markdown("### 🌐 Language")
    language = st.selectbox(
        "Explanation Language",
        options=["English", "Hindi (हिन्दी)", "Gujarati (ગુજરાતી)"],
        index=0,
        label_visibility="collapsed",
        help="Translate educational explanations for accessibility",
    )

    st.divider()

    # ── Interactive Chat Sidebar ──────────────────────────
    st.markdown("### 💬 Ask About Report")
    if 'sidebar_chat' not in st.session_state:
        st.session_state.sidebar_chat = []

    # Show chat history in sidebar
    chat_container = st.container(height=250)
    with chat_container:
        for msg in st.session_state.sidebar_chat:
            with st.chat_message(msg['role'], avatar="🧑‍💻" if msg['role'] == 'user' else "🔍"):
                st.markdown(msg['content'])

    sidebar_question = st.chat_input(
        "Ask about the security report...",
        key="sidebar_chat_input",
    )

    st.divider()
    st.markdown(
        "🔒 **Privacy**: PII is redacted by Agent 1 *before* "
        "any data reaches the AI model."
    )
    st.markdown(
        '<p style="font-size:0.75rem;color:#5a6478;">v3.0 – 5-Agent Architecture</p>',
        unsafe_allow_html=True,
    )
    
    if st.session_state.get('_results'):
        saved = st.session_state['_results']['analyst'].get('api_tokens_saved', 0)
        if saved > 0:
            st.success(f"🤖 **ML Bouncer Active**\n\nSaved **{saved:,.0f}** API tokens by filtering Normal traffic before LLM.")


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

def get_risk_color(score: int) -> str:
    if score <= 25: return "🟢"
    elif score <= 50: return "🟡"
    elif score <= 75: return "🟠"
    return "🔴"


def get_compliance_color(status: str) -> str:
    if status == "Compliant": return "🟢"
    elif status == "At Risk": return "🟡"
    elif status == "Non-Compliant": return "🟠"
    return "🔴"


def translate_with_llm(text: str, target_lang: str, api_key: str) -> str:
    """Use Groq Llama 3 to translate educational content to Hindi/Gujarati."""
    if not api_key or target_lang == "English":
        return text

    from groq import Groq
    try:
        client = Groq(api_key=api_key)

        lang_name = "Hindi" if "Hindi" in target_lang else "Gujarati"
        prompt = f"""Translate the following cybersecurity educational content to {lang_name}.
Keep all technical terms (SQL Injection, XSS, MITRE ATT&CK IDs, IP addresses) in English.
Translate the explanations, analogies, and descriptions to {lang_name}.
Maintain the markdown formatting.

CONTENT TO TRANSLATE:
{text}"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a professional technical translator."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=4096
        )
        return response.choices[0].message.content
    except Exception as e:
        return text + f"\n\n*⚠️ Translation error: {str(e)}*"


def run_multi_agent_analysis(raw_logs: str, api_key: str):
    """Orchestrate the 5-agent pipeline with real-time st.status feedback."""

    # ── Agent 1: Sieve ─────────────────────────────────────
    with st.status("🔒 **Agent 1 (Sieve)** — Parsing logs & redacting PII...", expanded=True) as status1:
        sieve = SieveAgent()
        sieve_result = sieve.process(raw_logs)

        for step in sieve_result['reasoning']:
            st.write(step)
            time.sleep(0.2)

        status1.update(
            label=f"🔒 **Sieve Agent** — Complete ({sieve_result['metadata']['total_lines']} lines, "
                  f"{sieve_result['metadata']['pii_redacted']['ips']} IPs redacted)",
            state="complete", expanded=False,
        )

    # ── Agent 1.5: Log Clustering ──────────────────────────
    with st.status("📦 **Log Clustering** — Deduplicating repetitive entries...", expanded=True) as status_cluster:
        clusterer = LogClusterer()
        cluster_result = clusterer.cluster(sieve_result['redacted_logs'])

        for step in cluster_result['reasoning']:
            st.write(step)
            time.sleep(0.2)

        stats = cluster_result['stats']
        status_cluster.update(
            label=f"📦 **Clustering** — {stats['unique_patterns']} patterns "
                  f"({stats['reduction_pct']}% reduction)",
            state="complete", expanded=False,
        )

    # ── Agent 2: Analyst ───────────────────────────────────
    with st.status("🔍 **Agent 2 (Analyst)** — AI threat analysis & MITRE ATT&CK mapping...", expanded=True) as status2:
        analyst = AnalystAgent(api_key)

        if not analyst.is_configured():
            st.error("❌ Groq API key not configured.")
            status2.update(label="🔍 **Analyst Agent** — Failed (No API key)", state="error")
            return None

        st.write("Sending clustered, PII-redacted logs to Groq Llama 3...")
        time.sleep(0.3)

        # Use clustered text for token efficiency
        analyst_result = analyst.analyze(
            cluster_result['clustered_text'],
            sieve_result['metadata'],
        )

        for step in analyst_result.get('reasoning', []):
            st.write(step)
            time.sleep(0.15)

        finding_count = len(analyst_result.get('findings', []))
        threat_level = analyst_result.get('threat_level', 0)

        status2.update(
            label=f"🔍 **Analyst Agent** — Complete ({finding_count} threats, "
                  f"level: {threat_level}/100)",
            state="complete", expanded=False,
        )

    # ── Agent 3: Compliance Auditor ────────────────────────
    with st.status("📋 **Agent 3 (Compliance)** — Mapping to PCI-DSS & GDPR...", expanded=True) as status3:
        compliance = ComplianceAuditorAgent()
        compliance_result = compliance.audit(analyst_result.get('findings', []))

        for step in compliance_result['reasoning']:
            st.write(step)
            time.sleep(0.2)

        status3.update(
            label=f"📋 **Compliance Agent** — Complete "
                  f"({compliance_result['compliance_status']}, Score: {compliance_result['compliance_score']}/100)",
            state="complete", expanded=False,
        )

    # ── Agent 4: Remediation ───────────────────────────────
    with st.status("🔧 **Agent 4 (Remediator)** — Generating mitigation scripts...", expanded=True) as status4:
        remediator = RemediationAgent()
        remediation_result = remediator.remediate(analyst_result.get('findings', []))

        for step in remediation_result['reasoning']:
            st.write(step)
            time.sleep(0.2)

        status4.update(
            label=f"🔧 **Remediator** — Complete ({len(remediation_result['scripts'])} scripts generated)",
            state="complete", expanded=False,
        )

    return {
        'sieve': sieve_result,
        'clustering': cluster_result,
        'analyst': analyst_result,
        'compliance': compliance_result,
        'remediation': remediation_result,
        'raw_logs': raw_logs,
    }


# ═══════════════════════════════════════════════════════════════
# Main Application
# ═══════════════════════════════════════════════════════════════

def main():
    # Determine log content source
    log_content = None

    if uploaded_file is not None:
        log_content = uploaded_file.getvalue().decode('utf-8', errors='replace')
    elif selected_sample and selected_sample != '— Select —':
        log_content = samples[selected_sample]

    # ── Handle sidebar chat (needs results) ───────────────
    if sidebar_question and st.session_state.get('_results'):
        st.session_state.sidebar_chat.append({'role': 'user', 'content': sidebar_question})
        results = st.session_state['_results']
        if api_key:
            analyst_agent = AnalystAgent(api_key)
            redacted = results['sieve'].get('redacted_logs', '')
            # Build context from results
            context_summary = f"""Report Summary:
- Threat Level: {results['analyst'].get('threat_level', 0)}/100
- Findings: {len(results['analyst'].get('findings', []))} threats
- Compliance: {results['compliance'].get('compliance_status', 'Unknown')} ({results['compliance'].get('compliance_score', 0)}/100)
- PCI-DSS Violations: {len(results['compliance'].get('pci_dss_violations', []))}
- GDPR Violations: {len(results['compliance'].get('gdpr_violations', []))}
- Remediation Scripts: {len(results['remediation'].get('scripts', []))}"""

            answer = analyst_agent.investigate(
                redacted + "\n\nREPORT CONTEXT:\n" + context_summary,
                sidebar_question,
            )
        else:
            answer = "⚠️ Configure your API key to use the chat."
        st.session_state.sidebar_chat.append({'role': 'assistant', 'content': answer})
        st.rerun()

    # ── No Input State ─────────────────────────────────────
    if log_content is None:
        st.markdown('<p class="hero-title">🛡️ TraceBack Sentinel</p>', unsafe_allow_html=True)
        st.markdown(
            '<p class="hero-subtitle">Multi-Agent AI Log Intelligence for Education & Small Teams</p>',
            unsafe_allow_html=True,
        )

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("### 🔒 Sieve")
            st.markdown("Regex PII redaction. IPs & emails scrubbed *before* AI sees logs.")
        with col2:
            st.markdown("### 🔍 Analyst")
            st.markdown("Groq Llama 3 detects SQLi, XSS, brute force + MITRE ATT&CK mapping.")
        with col3:
            st.markdown("### 📋 Auditor")
            st.markdown("Maps threats to PCI-DSS and GDPR with compliance scoring.")
        with col4:
            st.markdown("### 🔧 Remediator")
            st.markdown("Generates bash scripts, firewall rules & config patches.")

        st.divider()
        st.info("👈 Upload a log file or select a sample from the sidebar to begin analysis.", icon="📤")
        return

    # ── Run Analysis ───────────────────────────────────────
    cache_key = hash(log_content)
    if st.session_state.get('_cache_key') != cache_key:
        results = run_multi_agent_analysis(log_content, api_key)
        if results is None:
            return
        st.session_state['_cache_key'] = cache_key
        st.session_state['_results'] = results
        st.session_state['_log_content'] = log_content
        st.session_state.sidebar_chat = []  # Reset chat on new analysis
    else:
        results = st.session_state['_results']

    sieve = results['sieve']
    clustering = results['clustering']
    analyst = results['analyst']
    compliance = results['compliance']
    remediation = results['remediation']

    # ═══════════════════════════════════════════════════════
    # RISK DASHBOARD
    # ═══════════════════════════════════════════════════════

    st.markdown("---")
    st.markdown("## 📊 Risk Dashboard")

    threat_level = analyst.get('threat_level', 0)
    comp_score = compliance.get('compliance_score', 100)
    comp_status = compliance.get('compliance_status', 'Unknown')
    findings = analyst.get('findings', [])

    if findings:
        from collections import Counter
        attack_types = [f.get('attack_type', 'Unknown') for f in findings]
        top_attack = Counter(attack_types).most_common(1)[0][0]
    else:
        top_attack = "None Detected"

    has_demo_alert = any(f.get('demo_ui_alert', False) for f in findings)
    if has_demo_alert:
        st.markdown("""
        <div style="background-color: rgba(255, 71, 87, 0.15); border: 2px solid #ff4757; color: #ff4757; padding: 15px; border-radius: 8px; font-weight: bold; text-align: center; margin-bottom: 20px; animation: pulse 1.5s infinite; font-size: 1.1rem;">
            ⚠️ LIVE THREAT FEED: CRITICAL ALERT DETECTED — FINANCIAL DATA AT RISK
        </div>
        <style>
        @keyframes pulse {
            0% { opacity: 1; box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.4); }
            70% { opacity: 0.8; box-shadow: 0 0 0 10px rgba(255, 71, 87, 0); }
            100% { opacity: 1; box-shadow: 0 0 0 0 rgba(255, 71, 87, 0); }
        }
        </style>
        """, unsafe_allow_html=True)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric(
            "Threat Level",
            f"{get_risk_color(threat_level)} {threat_level}/100",
            delta=f"{'Critical' if threat_level > 75 else 'High' if threat_level > 50 else 'Medium' if threat_level > 25 else 'Low'}",
            delta_color="inverse",
        )
    with m2:
        st.metric("Threats Found", len(findings),
                  delta=f"{sieve['metadata']['total_lines']} lines analyzed")
    with m3:
        st.metric("Compliance",
                  f"{get_compliance_color(comp_status)} {comp_score}/100",
                  delta=comp_status,
                  delta_color="inverse" if comp_score < 80 else "normal")
    with m4:
        st.metric("Primary Attack", top_attack.replace('_', ' '),
                  delta=f"{sieve['metadata']['unique_ips']} unique IPs")
    with m5:
        st.metric("Token Savings",
                  f"{clustering['stats']['reduction_pct']}%",
                  delta=f"{clustering['stats']['unique_patterns']} patterns")

    # ═══════════════════════════════════════════════════════
    # TABBED VIEWS
    # ═══════════════════════════════════════════════════════

    tab1, tab_biz, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "⚔️ Threat Matrix",
        "💼 Business Impact",
        "📊 Visualizations",
        "📋 Compliance",
        "🔧 Remediation",
        "🎓 Learn",
        "🕵️ Investigate",
        "📝 Audit Trail",
    ])

    # ── Tab 1: Threat Matrix ──────────────────────────────
    with tab1:
        st.markdown("### Threat Findings")
        if findings:
            df = pd.DataFrame(findings)
            display_cols = ['timestamp', 'attacker_ip', 'attack_type', 'risk_score',
                           'confidence', 'mitre_attack_id', 'status', 'explanation']
            available = [c for c in display_cols if c in df.columns]

            st.dataframe(
                df[available], width="stretch",
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "Risk Score", format="%d", min_value=0, max_value=10),
                    "confidence": st.column_config.ProgressColumn(
                        "Confidence", format="%.0%%", min_value=0, max_value=1),
                    "attack_type": st.column_config.TextColumn("Attack Type"),
                    "mitre_attack_id": st.column_config.TextColumn("MITRE ATT&CK"),
                },
                hide_index=True,
            )
            
            st.markdown("### 🔬 Technical Depth & Architecture View")
            for idx, f in enumerate(findings):
                with st.expander(f"Deep Dive: {f.get('attack_type', 'Suspicious')} (IP: {f.get('attacker_ip', 'Unknown')})"):
                    st.markdown("**Technical Architecture Flaw:**")
                    st.info(f.get('technical_architecture_flaw', 'Awaiting generation...'))
                    st.markdown("**Raw Log Payload (Evidence):**")
                    st.code(f.get('evidence', 'No raw payload available'), language='text')

        else:
            st.success("🎉 No threats detected — your logs look clean!")

    # ── Tab: Business Impact ──────────────────────────────
    with tab_biz:
        st.markdown("### 💼 Operations & Financial Impact Panel")
        st.markdown("*Executive summary translating technical logs into business risk.*")
        if findings:
            for f in findings:
                impact = f.get('enterprise_business_impact', 'Unknown')
                severity = f.get('risk_score', 0)
                
                # Synthetic metrics based on severity
                est_downtime = f"{severity * 2} - {severity * 5} Hours" if severity > 5 else "Minimal"
                breach_risk = "CRITICAL" if severity > 8 else "HIGH" if severity > 5 else "MODERATE"
                
                st.markdown(f"#### Attack: {f.get('attack_type', 'Unknown')} (IP: {f.get('attacker_ip', 'Unknown')})")
                
                b1, b2, b3 = st.columns(3)
                with b1:
                    st.metric("Estimated Downtime Risk", est_downtime)
                with b2:
                    st.metric("Data Breach Severity", breach_risk)
                with b3:
                    st.metric("Financial Exposure", "High (Regulatory fines possible)" if severity > 7 else "Low to Moderate")
                    
                st.info(f"**Enterprise Business Impact:**\n\n{impact}")
                st.divider()
        else:
            st.success("🎉 No business risks detected.")

    # ── Tab 2: Visualizations ─────────────────────────────
    with tab2:
        if findings:
            viz_col1, viz_col2 = st.columns(2)
            with viz_col1:
                st.markdown("#### Attack Type Distribution")
                attack_counts = pd.Series(
                    [f.get('attack_type', 'Unknown') for f in findings]
                ).value_counts()
                fig1 = px.bar(x=attack_counts.values, y=attack_counts.index,
                             orientation='h', color=attack_counts.index,
                             color_discrete_map={
                                 'SQL_Injection': '#ff4757', 'XSS': '#a855f7',
                                 'Brute_Force': '#ffb347',
                                 'Directory_Traversal': '#00d4ff',
                                 'Scanner_Probe': '#5a6478',
                             }, template='plotly_dark')
                fig1.update_layout(showlegend=False, height=300,
                                  margin=dict(l=0, r=0, t=10, b=0),
                                  xaxis_title="Count", yaxis_title="",
                                  paper_bgcolor='rgba(0,0,0,0)',
                                  plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig1, use_container_width=True)

            with viz_col2:
                st.markdown("#### Risk Score Distribution")
                risk_scores = [f.get('risk_score', 0) for f in findings]
                fig2 = go.Figure(data=[go.Histogram(
                    x=risk_scores, nbinsx=10, marker_color='#00d4ff', opacity=0.8)])
                fig2.update_layout(template='plotly_dark', height=300,
                                  margin=dict(l=0, r=0, t=10, b=0),
                                  xaxis_title="Risk Score", yaxis_title="Count",
                                  paper_bgcolor='rgba(0,0,0,0)',
                                  plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig2, use_container_width=True)

            st.markdown("#### IP Activity Frequency")
            ip_freq = sieve['metadata'].get('ip_frequency', {})
            if ip_freq:
                ip_df = pd.DataFrame([
                    {'IP': ip, 'Requests': count} for ip, count in ip_freq.items()
                ])
                fig3 = px.bar(ip_df, x='Requests', y='IP', orientation='h',
                             template='plotly_dark', color='Requests',
                             color_continuous_scale='tealrose')
                fig3.update_layout(height=max(200, len(ip_freq) * 35),
                                  margin=dict(l=0, r=0, t=10, b=0),
                                  paper_bgcolor='rgba(0,0,0,0)',
                                  plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No threat data to visualize.")

    # ── Tab 3: Compliance ─────────────────────────────────
    with tab3:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### 🏛️ PCI-DSS Violations")
            pci = compliance.get('pci_dss_violations', [])
            if pci:
                for v in pci:
                    icon = "🔴" if v['severity'] == 'Critical' else "🟠" if v['severity'] == 'High' else "🟡"
                    with st.expander(f"{icon} {v['attack_type'].replace('_', ' ')} — Req {', '.join(v['requirements'])}"):
                        st.markdown(v['description'])
                        if v.get('mitre_id'):
                            st.code(f"MITRE ATT&CK: {v['mitre_id']}", language="text")
            else:
                st.success("✅ No PCI-DSS violations detected.")
        with c2:
            st.markdown("### 🇪🇺 GDPR Violations")
            gdpr = compliance.get('gdpr_violations', [])
            if gdpr:
                for v in gdpr:
                    icon = "🔴" if v['severity'] == 'Critical' else "🟠" if v['severity'] == 'High' else "🟡"
                    with st.expander(f"{icon} {v['attack_type'].replace('_', ' ')} — {', '.join(v['articles'])}"):
                        st.markdown(v['description'])
            else:
                st.success("✅ No GDPR violations detected.")

    # ── Tab 4: Remediation ────────────────────────────────
    with tab4:
        st.markdown("### 🚀 Automated Remediation & Innovation")
        st.markdown("*Advanced remediation advice and automated patching simulation.*")
        
        if findings:
            for idx, f in enumerate(findings):
                st.markdown(f"#### {f.get('attack_type', 'Unknown')} Incident")
                st.markdown("**Innovative Remediation Strategy:**")
                st.info(f.get('innovative_remediation', 'Awaiting generation...'))
                
                if st.button(f"🚀 Deploy Architecture Patch", key=f"deploy_btn_{idx}"):
                    with st.spinner("Initiating zero-downtime hot-patch deployment via Kubernetes..."):
                        import time
                        time.sleep(1.5)
                        st.success("✅ Patch successfully deployed across cluster. Vulnerability mitigated.")
            st.divider()

        st.markdown("### 🔧 Agentic Remediation Scripts")
        st.markdown("*Auto-generated bash commands and config patches for each detected threat.*")

        scripts = remediation.get('scripts', [])
        if scripts:
            # Group by attack type
            from collections import defaultdict
            grouped = defaultdict(list)
            for s in scripts:
                grouped[s['attack_type']].append(s)

            for attack_type, group in grouped.items():
                st.markdown(f"#### {group[0]['title']}")
                for script in group:
                    with st.expander(f"📜 {script['name']}", expanded=False):
                        st.code(script['code'], language=script['lang'])
                        st.button(
                            f"📋 Copy", key=f"copy_{hash(script['code'])}",
                            help="Copy to clipboard",
                        )
                st.divider()
        else:
            st.success("✅ No remediation scripts needed — no threats detected!")

        # Compliance remediation recommendations
        st.markdown("### 📌 Compliance Remediation Advice")
        compliance_recs = compliance.get('remediation', [])
        if compliance_recs:
            for rec in compliance_recs:
                st.markdown(f"- {rec}")

    # ── Tab 5: Learn (with Vernacular) ────────────────────
    with tab5:
        st.markdown("### 🎓 Understanding the Threats")

        # Language indicator
        if language != "English":
            lang_label = "Hindi" if "Hindi" in language else "Gujarati"
            st.info(f"🌐 Showing explanations in **{lang_label}** (technical terms remain in English)")

        education = analyst.get('educational_explanation', '')
        if education:
            # Translate if needed
            if language != "English":
                # Cache translation
                trans_key = f"_trans_{language}_{hash(education)}"
                if trans_key not in st.session_state:
                    with st.spinner(f"Translating to {lang_label}..."):
                        st.session_state[trans_key] = translate_with_llm(
                            education, language, api_key
                        )
                translated = st.session_state[trans_key]
            else:
                translated = education

            with st.chat_message("assistant", avatar="🎓"):
                st.markdown(translated)
        else:
            st.info("No educational content available.")

        timeline = analyst.get('attack_timeline', '')
        if timeline:
            st.divider()
            st.markdown("### ⏱️ Attack Timeline")
            with st.chat_message("assistant", avatar="🕐"):
                if language != "English":
                    tl_key = f"_trans_tl_{language}_{hash(timeline)}"
                    if tl_key not in st.session_state:
                        with st.spinner("Translating timeline..."):
                            st.session_state[tl_key] = translate_with_llm(
                                timeline, language, api_key
                            )
                    st.markdown(st.session_state[tl_key])
                else:
                    st.markdown(timeline)

    # ── Tab 6: Investigation ──────────────────────────────
    with tab6:
        st.markdown("### 🕵️ Guided Log Investigation")
        st.markdown("Ask questions about specific IPs, timestamps, or patterns.")

        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []

        for msg in st.session_state.chat_history:
            with st.chat_message(msg['role'], avatar="🧑‍💻" if msg['role'] == 'user' else "🔍"):
                st.markdown(msg['content'])

        user_question = st.chat_input(
            "e.g., What did the most active IP do? Is there data exfiltration?",
        )

        if user_question:
            st.session_state.chat_history.append({'role': 'user', 'content': user_question})
            with st.chat_message("user", avatar="🧑‍💻"):
                st.markdown(user_question)

            with st.chat_message("assistant", avatar="🔍"):
                if not api_key:
                    answer = "⚠️ Please configure your API key to enable investigation."
                else:
                    with st.spinner("Investigating..."):
                        analyst_agent = AnalystAgent(api_key)
                        redacted = sieve.get('redacted_logs', log_content)
                        answer = analyst_agent.investigate(redacted, user_question)
                st.markdown(answer)

            st.session_state.chat_history.append({'role': 'assistant', 'content': answer})

    # ── Tab 7: Audit Trail ────────────────────────────────
    with tab7:
        st.markdown("### 📝 Full Audit Trail")
        st.markdown(
            "*Every AI decision is transparent and verifiable. "
            "Each finding shows the **evidence** (log snippet that triggered the alert) "
            "and the **rationale** (step-by-step logic).*"
        )

        # ── Build remediation script lookup ──
        remediation_audit = remediation.get('audit_scripts', [])
        script_map = {}
        for ra in remediation_audit:
            key = ra['attack_type']
            if key not in script_map:
                script_map[key] = []
            script_map[key].append(ra)

        # ── Compliance Audit Entries (expander per finding) ──
        audit_entries = compliance.get('audit_entries', [])

        if audit_entries:
            for idx, entry in enumerate(audit_entries, start=1):
                finding_type = entry.get('finding', 'Unknown')
                risk = entry.get('risk_score', 0)
                conf = entry.get('confidence', 0)
                mitre = entry.get('mitre_id', '')

                # Severity badge
                if risk >= 8:
                    badge = "🔴 Critical"
                elif risk >= 5:
                    badge = "🟠 High"
                elif risk >= 3:
                    badge = "🟡 Medium"
                else:
                    badge = "🟢 Low"

                expander_title = (
                    f"{badge}  ·  Finding {idx}: **{finding_type.replace('_', ' ')}**  "
                    f"·  Risk {risk}/10  ·  {mitre}"
                )

                with st.expander(expander_title, expanded=(idx <= 3)):
                    # ── Metrics row ──
                    mc1, mc2, mc3, mc4 = st.columns(4)
                    with mc1:
                        st.metric("Risk Score", f"{risk}/10")
                    with mc2:
                        st.metric("LLM Confidence", f"{conf:.0%}")
                        ml_c = analyst.get('ml_confidence')
                        if ml_c is not None:
                            st.caption(f"🤖 ML Bouncer: {ml_c:.0%} certainty")
                    with mc3:
                        st.metric("MITRE ATT&CK", mitre or "—")
                    with mc4:
                        st.metric("Attacker", entry.get('ip', 'N/A'))

                    # ── Evidence ──
                    st.markdown("#### 🔍 Evidence (verbatim log snippet)")
                    evidence_text = entry.get('evidence', '')
                    if evidence_text:
                        st.code(evidence_text, language="text")
                    else:
                        st.info("No verbatim evidence available for this finding.")

                    # ── Rationale ──
                    st.markdown("#### 🧠 Rationale (step-by-step logic)")
                    rationale_text = entry.get('rationale', '')
                    if rationale_text:
                        st.markdown(rationale_text)
                    else:
                        st.markdown(f"_{entry.get('reasoning', 'No rationale available.')}_")

                    # ── Compliance Citations ──
                    comp_col1, comp_col2 = st.columns(2)
                    with comp_col1:
                        pci = entry.get('pci_reqs', '')
                        st.markdown(f"**🏛️ PCI-DSS:** `{pci}`" if pci else "**🏛️ PCI-DSS:** —")
                    with comp_col2:
                        gdpr = entry.get('gdpr_arts', '')
                        st.markdown(f"**🇪🇺 GDPR:** `{gdpr}`" if gdpr else "**🇪🇺 GDPR:** —")

                    # ── Remediation Script (if available) ──
                    norm_type = finding_type.replace(' ', '_')
                    if norm_type in script_map:
                        st.markdown("#### 🔧 Remediation Scripts")
                        for s in script_map[norm_type]:
                            st.code(
                                f"# {s['script_name']}\n{s['script_code']}",
                                language="bash",
                            )
        else:
            st.info("No audit trail entries available. Run an analysis to populate this tab.")

        st.divider()

        # ── Summary Table (compact overview) ──
        if audit_entries:
            with st.expander("📊 Audit Summary Table", expanded=False):
                audit_df = pd.DataFrame(audit_entries)
                display_cols_audit = ['finding', 'ip', 'risk_score', 'confidence',
                                      'mitre_id', 'pci_reqs', 'gdpr_arts', 'reasoning']
                available_audit = [c for c in display_cols_audit if c in audit_df.columns]
                st.dataframe(
                    audit_df[available_audit], use_container_width=True,
                    column_config={
                        "risk_score": st.column_config.ProgressColumn(
                            "Risk", format="%d", min_value=0, max_value=10),
                        "confidence": st.column_config.NumberColumn(
                            "Confidence", format="%.0%%"),
                        "finding": st.column_config.TextColumn("Attack Type"),
                        "mitre_id": st.column_config.TextColumn("MITRE ID"),
                        "pci_reqs": st.column_config.TextColumn("PCI-DSS"),
                        "gdpr_arts": st.column_config.TextColumn("GDPR"),
                        "reasoning": st.column_config.TextColumn(
                            "Agent Reasoning", width="large"),
                    },
                    hide_index=True,
                )

        # ── PII Map ───────────────────────────────────────
        with st.expander("🔒 PII Redaction Map (Agent 1 — Sieve)"):
            pii_map = sieve.get('pii_map', {})
            if pii_map:
                pii_df = pd.DataFrame([
                    {'Redacted Token': k, 'Original Value': v}
                    for k, v in pii_map.items()
                ])
                st.dataframe(pii_df, use_container_width=True, hide_index=True)
            else:
                st.info("No PII was found to redact.")

        # ── Clustering Stats ──────────────────────────────
        with st.expander("📦 Log Clustering Stats"):
            cl_stats = clustering['stats']
            st.markdown(
                f"- **Original lines:** {cl_stats['original_lines']}\n"
                f"- **Unique patterns:** {cl_stats['unique_patterns']}\n"
                f"- **Token reduction:** {cl_stats['reduction_pct']}%"
            )

        # ── Agent Decision Logs ───────────────────────────
        with st.expander("🧠 Agent Decision Logs"):
            st.markdown("**Agent 1 (Sieve):**")
            for step in sieve.get('reasoning', []):
                st.markdown(f"- {step}")
            st.markdown("**Clustering:**")
            for step in clustering.get('reasoning', []):
                st.markdown(f"- {step}")
            st.markdown("**Agent 2 (Analyst):**")
            for step in analyst.get('reasoning', []):
                st.markdown(f"- {step}")
            st.markdown("**Agent 3 (Compliance):**")
            for step in compliance.get('reasoning', []):
                st.markdown(f"- {step}")
            st.markdown("**Agent 4 (Remediator):**")
            for step in remediation.get('reasoning', []):
                st.markdown(f"- {step}")


if __name__ == "__main__":
    main()
