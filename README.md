# TraceBack

TraceBack is a log analysis tool that helps identify suspicious activity in server logs. It uses a K-Nearest Neighbors (KNN) model to classify log entries as benign or anomalous, cutting down the volume of traffic that needs manual review.

## Background

Originally built for Google for Startups' **"Prompt to Prototype"** program (in partnership with Scaler). Later extended for the **ET GenAI Hackathon**, and used as a final project submission for **CS50x: Introduction to Computer Science (Harvard)**.

## How it works

- Log entries (Apache / authentication logs) are parsed and passed through a KNN classifier trained to flag patterns associated with brute-force attempts, SQL injection, and XSS.
- Flagged entries are highlighted with extracted details — IP addresses, timestamps, and a basic risk score — so the more interesting logs surface first instead of requiring a full manual scan.
- All processing happens in memory; logs are not stored to disk.

## Tech Stack

- **Language**: Python
- **ML**: Scikit-learn (KNN)
- **Interface**: Streamlit

## Status

Actively being extended — future work includes deeper LLM-based reasoning on flagged entries and broader log format support.

## Setup

```
git clone https://github.com/yughpatel/TraceBack.git
cd TraceBack
pip install -r requirements.txt
streamlit run app.py
```
