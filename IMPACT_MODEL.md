# TraceBack Sentinel: Impact Model & Business Value

This document provides a quantified estimate of the business impact achieved by deploying **TraceBack Sentinel** and its Hybrid ML+LLM "Bouncer" architecture.

---

## 📊 1. Core Assumptions
For this "Back-of-Envelope" math, we assume a mid-sized enterprise environment:
- **Log Volume**: 1,000,000 log lines per day.
- **Traffic Profile**: 95% "Normal" (benign) traffic, 5% "Anomalous" (requires review).
- **LLM Token Density**: 1 log line avg = 100 tokens (including system prompts/context).
- **LLM Unit Cost**: $10.00 per 1,000,000 tokens (Average pricing for high-tier models like Groq Llama 3 70B/8B).
- **Human Analyst Rate**: $50.00 / hour.
- **Manual Review Time**: 2 minutes per anomalous event for a human to identify the root cause.

---

## 💰 2. Financial Impact: Cost Reduction
### Scenario A: Pure LLM Analysis (Without Bouncer)
All 1M log lines are sent to the LLM for analysis.
- **Total Tokens**: 1,000,000 logs * 100 tokens = 100M tokens.
- **Daily Cost**: (100M / 1M) * $10.00 = **$1,000.00 / day**.
- **Annual Cost**: **$365,000 / year**.

### Scenario B: TraceBack Hybrid Bouncer (ML + LLM)
Only the 5% anomalous logs (50,000 lines) reach the expensive LLM. The 95% Normal logs are filtered locally by the ML Bouncer at zero variable cost.
- **Total Tokens**: 50,000 logs * 100 tokens = 5M tokens.
- **Daily Cost**: (5M / 1M) * $10.00 = **$50.00 / day**.
- **Annual Cost**: **$18,250 / year**.

> [!IMPORTANT]
> **Total Savings**: $346,750 / year (**95% cost reduction**).

---

## ⏱️ 3. Operational Impact: Time to Resolution (MTTR)
### Manual SOC Operation
An analyst must manually verify the 50,000 anomalous events flagged by basic threshold alerts.
- **Total Time**: 50,000 events * 2 minutes = 100,000 minutes = **1,666 hours**.
- **Labor Cost**: 1,666 hours * $50/hr = **$83,300 / day** (Requires a massive fleet of analysts).

### TraceBack Sentinel Operation
- **ML Bouncer Inference**: <5ms per log (local CPU).
- **LLM Deep Analysis**: ~2 seconds per clustered threat pattern (via Groq API).
- **Total Time**: TraceBack identifies, maps to MITRE, and suggests remediation for all 50,000 events in roughly **15 minutes** of concurrent API processing time.

> [!IMPORTANT]
> **MTTR Improvement**: From **1,666 Hours** (Manual) to **<15 Minutes** (Automated). 
> **Resolution Speed Increase**: **99.9% reduction in technical verification lag.**

---

## 🏆 4. Conclusion
TraceBack Sentinel transforms a $365k/year cloud cost into a $18k/year operating expense while providing near-instantaneous security reasoning that would otherwise be humanly impossible to achieve at scale.
