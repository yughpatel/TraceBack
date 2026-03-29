# Impact & ROI Model

A quick breakdown of how TraceBack Sentinel impacts the bottom line for a mid-sized enterprise.

## 1. The Numbers (Assumptions)
- **Daily Volume**: 1,000,000 log lines.
- **Traffic Split**: 95% Normal, 5% Anomalous (requires LLM/Human review).
- **LLM Cost**: ~$10 per 1M tokens (Llama 3 70B on Groq).
- **Analysis Depth**: 100 tokens per log line.
- **Human Labor**: $50/hr (for manual SOC review).

---

## 2. Cost Analysis: LLM Tokens

### Case A: Pure LLM (Brute Force)
Every log line goes to the LLM.
- **Total Tokens**: 1M logs * 100 tokens = 100M tokens.
- **Daily Cost**: **$1,000 / day** ($365k / year).

### Case B: TraceBack Hybrid (ML Bouncer)
The local ML model filters the 95% junk. Only the 5% anomalous logs reach the API.
- **Total Tokens**: 50,000 logs * 100 tokens = 5M tokens.
- **Daily Cost**: **$50 / day** ($18k / year).

> [!TIP]
> **Total Savings**: ~$346,000 / year (**95% cost reduction**).

---

## 3. Operational Speed (MTTR)

### Manual Review
A human analyst takes ~2 minutes to verify one anomalous log.
- **Workload**: 50,000 anomalous events * 2 minutes = 1,666 hours.
- **Result**: Physically impossible for a standard SOC team to process daily logs in real-time.

### TraceBack Sentinel
- **ML Filtering**: <5ms per log.
- **LLM Reasoning**: ~2 seconds per clustered pattern.
- **Batch Processing**: ~15 minutes to clear a daily surge.

> [!IMPORTANT]
> **Efficiency Gain**: 99.9% reduction in technical verification lag.

---

## Summary
By using the local ML bouncer to pre-filter traffic, we convert what would be a massive cloud bill and a humanly impossible workload into a $50/day automated operation.
