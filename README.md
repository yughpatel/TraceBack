# Traceback: AI-Powered Log Analysis

**An AI-native security tool that democratizes log analysis for students using Gemini 1.5 Flash.**

Traceback helps junior developers and sysadmins understand their server logs by identifying threats, explaining them in plain English, and suggesting defense rules.

## Setup Instructions

⚠️ **Important:** This application requires a Google Gemini API key to function.

1.  **Clone the repository** (if you haven't already).
2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure Access**:
    You must create a secrets file manually. It is excluded from Git for security.
    
    Create a file at `.streamlit/secrets.toml` and add your key:
    
    ```toml
    [gemini]
    api_key = "YOUR_GOOGLE_AI_API_KEY_HERE"
    ```

## Running the App

To start the dashboard, run:

```bash
streamlit run app.py
```
