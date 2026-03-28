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

## 💼 Business Impact & Impact Model

By adopting a Hybrid ML+LLM strategy, **TraceBack Sentinel** achieves the following quantified results:
- **95% Operating Cost Reduction**: $346,750 / year saved by filtering out benign traffic via the local ML Bouncer.
- **99.9% Faster MTTR**: From 1,666 manual analyst hours to <15 minutes of automated reasoning.
- **Continuous Compliance**: Automated 1:1 mapping of threats to PCI-DSS Req 10 & GDPR Art 32.

> [!TIP]
> **View the full Impact Model & Math:** [IMPACT_MODEL.md](file:///e:/projects/TraceBack/FINAL/IMPACT_MODEL.md)

## 🚀 Quick Start & Setup

### 1. Prerequisites
- **Python**: 3.9+ 
- **Groq API Key**: [Get one here](https://console.groq.com/keys)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/yughpatel/TraceBack.git
cd TraceBack

# Install dependencies
pip install -r requirements.txt
```

### 3. API Key Configuration
You can configure your **Groq API Key** in two ways:
- **Option A (Persistent)**: Create a file at `.streamlit/secrets.toml` with the following content:
  ```toml
  [groq]
  api_key = "gsk_your_key_here"
  ```
- **Option B (Rapid Setup)**: Enter the key directly into the **Sidebar UI** after launching the app.

### 4. Launch Application
```bash
streamlit run app.py
```

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
