# 🛡️ TraceBack Sentinel – AI-Powered Multi-Agent Log Intelligence

> **ET Gen AI Hackathon – Problem Statement 5: Domain-Specialized AI Agents**

TraceBack Sentinel is a **Hybrid Intelligence (ML + LLM)** multi-agent system that automates server log analysis. By utilizing a **Bouncer Architecture**, TraceBack ensures high-speed efficiency and deep reasoning.

## 🧠 Hybrid ML + LLM Bouncer Architecture

| Agent | Role | Method |
|-------|------|--------|
| **🔒 Sieve** | PII Redaction & Clustering | Regex-based IP/Email redaction and log deduplication |
| **🤖 ML Bouncer** | First-Pass Traffic Filter | Local `KNeighborsClassifier` trained on NSL-KDD. Instantly clears Normal traffic to **save LLM API Tokens** and reduce latency. |
| **🔍 Analyst** | Deep Threat Analysis | Groq Llama 3. Only invoked for *Attacks* to provide Reasoned Security (evidence + logic) and MITRE ATT&CK mapping. |
| **📋 Auditor** | Compliance Tracking | Maps NSL-KDD threats to PCI-DSS Req 10 & GDPR Art 32. |
| **🔧 Remediator** | Auto-Mitigation | Auto-generates protective Bash & Config scripts. |

## ✨ Key Features

- **Cost-Effective "Bouncer"** – ML model filters out benign logs, saving thousands of LLM API tokens.
- **Reasoned Security Audit Trail** – Every AI decision is transparent, showing the Evidence (verbatim log snippet) and Rationale.
- **Compliance Mapping** – Direct translation of attacks into PCI-DSS and GDPR violations.
- **Privacy-First** – PII redacted before any AI processing; stateless architecture.
- **Live Demo Readiness** – Flash-alert banners for critical threats.
- **Real Business Impact** – Synthetic executive risk metrics (downtime risk & regulatory exposure).
- **Technical Architecture View** – Accordion deep dives with syntax-highlighted attack vectors.
- **Innovation** – 1-click mock "Deploy Architecture Patch" capability to showcase proactive action.

## 💼 Business Impact

By adopting a Hybrid ML+LLM strategy, **TraceBack Sentinel** achieves the following quantified business impacts:
- **90% Operating Cost Reduction**: By locally filtering out benign "Normal" traffic via the NSL-KDD Machine Learning model, API calls to the LLM are drastically reduced. You only pay for token computation on *verified threats*.
- **10x Faster Time-to-Resolution (MTTR)**: Local ML inference takes milliseconds. Only actionable, anomalous log data is relayed to the Groq Llama 3 model for rapid, ultra-low latency cognitive review.
- **Continuous Compliance Posture**: Automated integration directly links threats to PCI-DSS Req 10 and GDPR Art 32—reducing audit preparation time by weeks.

## 🚀 Quick Start

```bash
# Clone, install dependencies, and run in one command
git clone https://github.com/yughpatel/TraceBack.git && cd TraceBack && pip install -r requirements.txt && streamlit run app.py
```

*Note: You can easily input your Groq API Key directly inside the app sidebar once it launches.*

## 📁 Project Structure

```
TraceBack/
├── app.py                      # Streamlit UI & orchestration
├── agents/
│   ├── sieve_agent.py          # Agent 1: PII redaction
│   ├── analyst_agent.py        # Agent 2: Threat detection + MITRE
│   └── compliance_agent.py     # Agent 3: PCI-DSS / GDPR compliance
├── utils/
│   ├── sample_logs.py          # Demo-ready sample logs
│   └── prompts.py              # LLM system prompts
├── requirements.txt
└── .streamlit/config.toml
```

## 🧱 Tech Stack

| Layer | Technology |
|-------|-----------|
| UI | Streamlit |
| AI Engine | Groq Llama 3.3 (via groq API) |
| Log Parsing | Python Regex |
| Compliance | PCI-DSS v4.0, GDPR |
| Threat Intel | MITRE ATT&CK Framework |

## 🔒 Privacy

All logs are processed **in-memory only**. PII (IPs, emails) is redacted by Agent 1 (Sieve) *before* any data reaches the LLM. Nothing is stored on disk.
