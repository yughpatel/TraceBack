# TraceBack Sentinel

TraceBack Sentinel is a hybrid log intelligence platform. It uses a mix of local ML and LLMs to scan server logs, flag threats, and explain what's actually happening without burning through thousands of dollars in API tokens.

## The Approach: "The Bouncer"

Running every log line through an LLM is overkill and too expensive ($1k+/day for a million logs). We built a **Classify-First, Explain-Second** pipeline:

1.  **Local ML Filter**: A KNN model acts as a "bouncer." It tosses out 95%+ of benign traffic locally (zero cost, zero latency).
2.  **Groq Analyst**: Only the weird/anomalous logs get sent to Llama 3 for deep reasoning (Forensics, MITRE mapping, and logic).
3.  **Result**: 95% cheaper than pure LLM setups and way faster than manual SOC reviews.

## What's in the box?

Check these out in the **`app.py`** dashboard:

- **Live Threat Feed**: Real-time pulses for detected attacks (SQLi, XSS, etc.).
- **Impact Panel**: Technical logs converted into business risk (Downtime & Financial exposure).
- **Multilingual Support**: Explanations available in **Hindi** and **Gujarati** for regional teams.
- **1-Click Remediation**: A simulation to deploy architecture patches instantly.
- **Audit Logs**: Deep dives into the **Evidence** and **Rationale** for every alert.

## Setup

### 1. Prerequisites
- Python 3.9+ 
- [Groq API Key](https://console.groq.com/keys)

### 2. Install
```bash
git clone https://github.com/yughpatel/TraceBack.git
cd TraceBack
pip install -r requirements.txt
```

### 3. Config
Add your key in `.streamlit/secrets.toml`:
```toml
[groq]
api_key = "gsk_your_key_here"
```
*Or just paste it into the sidebar once the app is running.*

### 4. Run
```bash
streamlit run app.py
```

## Project Structure

```text
TraceBack/
├── app.py                  # Main UI & Orchestration
├── agents/
│   ├── sieve_agent.py      # PII Redactor
│   ├── analyst_agent.py    # Threat Detection (Groq)
│   └── compliance_agent.py # PCI-DSS / GDPR Auditor
├── utils/
│   ├── sample_logs.py      # Test data
│   └── prompts.py          # System prompts
└── requirements.txt
```

## Tech Stack

- **Frontend**: Streamlit
- **LLM**: Groq Llama 3.3
- **ML**: Scikit-learn (KNN)
- **Compliance**: PCI-DSS v4.0, GDPR
- **Framework**: MITRE ATT&CK

## Privacy

Logs stay in memory. Agent 1 (Sieve) redacts sensitive stuff (IPs, emails) locally *before* anything hits an external API. We don't store your data on disk.

