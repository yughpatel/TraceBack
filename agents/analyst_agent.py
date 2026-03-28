"""
Agent 2 – Analyst Agent
LLM-powered threat detection with MITRE ATT&CK mapping.
Receives PII-redacted logs from the Sieve Agent.
"""

import json
import re
import os
import joblib
from groq import Groq
from utils.prompts import ANALYST_SYSTEM_PROMPT
from utils.feature_extractor import extract_features


class AnalystAgent:
    """
    Agent 2: The Analyst — AI-powered threat detection.

    Responsibilities:
    - Analyze PII-redacted logs using Google Gemini
    - Identify attack patterns (SQLi, Brute Force, XSS, etc.)
    - Map each finding to MITRE ATT&CK technique IDs
    - Assign risk scores with confidence levels
    - Generate educational explanations
    """

    # Model names to try in order (newest first)
    MODEL_FALLBACKS = [
        'gemini-2.0-flash',
        'gemini-2.0-flash-lite',
        'gemini-1.5-flash',
        'gemini-pro',
    ]

    # Keep mappings close to the Analyst so the UI and downstream agents stay consistent.
    SEVERITY_TO_RISK_SCORE = {
        'Critical': 10,
        'High': 8,
        'Medium': 5,
        'Low': 2,
        'Informational': 1,
    }
    SEVERITY_TO_CONFIDENCE = {
        'Critical': 0.95,
        'High': 0.9,
        'Medium': 0.75,
        'Low': 0.6,
        'Informational': 0.4,
    }
    MITRE_MAP = {
        'SQL_Injection': {'id': 'T1190', 'name': 'Exploit Public-Facing Application'},
        'XSS': {'id': 'T1189', 'name': 'Drive-by Compromise'},
        'Brute_Force': {'id': 'T1110', 'name': 'Brute Force'},
        'Directory_Traversal': {'id': 'T1083', 'name': 'File and Directory Discovery'},
        'Scanner_Probe': {'id': 'T1595', 'name': 'Active Scanning'},
        'Suspicious': {'id': 'T1071', 'name': 'Application Layer Protocol'},
    }

    def __init__(self, api_key: str, model_name: str = 'llama-3.3-70b-versatile'):
        self.api_key = api_key
        self.model_name = model_name
        self.client = None

    def is_configured(self) -> bool:
        """Check if the API key is set and not the placeholder."""
        return bool(self.api_key) and self.api_key != 'YOUR_API_KEY_HERE'

    def _get_client(self):
        """Lazy-initialize the Groq client."""
        if self.client is None:
            self.client = Groq(api_key=self.api_key)
        return self.client

    def analyze(self, redacted_logs: str, metadata: dict) -> dict:
        """
        Run AI-powered analysis on redacted logs.

        Args:
            redacted_logs: PII-redacted log content from Sieve Agent
            metadata: Metadata dict from Sieve Agent

        Returns:
            dict with keys:
                - threat_level: int (0-100)
                - findings: list of finding dicts
                - educational_explanation: str (markdown)
                - attack_timeline: str (markdown)
                - reasoning: list of str (agent's reasoning steps)
                - raw_response: str (raw LLM output for audit)
        """
        reasoning = []
        reasoning.append("Received redacted logs from Sieve Agent.")
        reasoning.append(
            f"Context: {metadata['total_lines']} lines, "
            f"{metadata['unique_ips']} unique IPs, "
            f"{metadata['suspicious_count']} pre-flagged entries."
        )
        reasoning.append("Preparing structured prompt for Gemini AI...")

        # ── Phase 1: Local ML Bouncer (KNN) ──
        reasoning.append("Initiating Phase 1: Local ML Bouncer Inference (KNN)...")
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            knn = joblib.load(os.path.join(base_dir, 'models', 'nsl_kdd_model.pkl'))
            scaler = joblib.load(os.path.join(base_dir, 'models', 'scaler.pkl'))
            le = joblib.load(os.path.join(base_dir, 'models', 'label_encoder.pkl'))

            features = extract_features(redacted_logs, le, scaler)
            prediction = knn.predict(features)[0]
            confidence = max(knn.predict_proba(features)[0])
            
            reasoning.append(f"ML Classifier predicts: **{prediction}** with {confidence:.0%} confidence.")

            if prediction == 'Normal':
                reasoning.append("✅ Traffic classified as Normal. Skipping LLM Agent (Saving API tokens!)")
                return {
                    'threat_level': 0,
                    'findings': [],
                    'educational_explanation': 'Traffic is benign. No threats detected.',
                    'attack_timeline': 'Standard user behavior.',
                    'reasoning': reasoning,
                    'raw_response': 'Bouncer prevented LLM invocation.',
                    'ml_confidence': confidence,
                    'api_tokens_saved': len(redacted_logs.split()) * 1.5 # Token estimate
                }
            else:
                reasoning.append(f"⚠️ Suspicious pattern detected ({prediction}). Escalating to LLM for reasoned analysis...")
        except Exception as e:
            reasoning.append(f"⚠️ ML Bouncer failed ({e}). Defaulting to full LLM analysis.")

        # ── Phase 2: LLM Deep Analysis ──
        client = self._get_client()

        # Build context string
        context = (
            f"Log Summary: {metadata['total_lines']} total lines | "
            f"Formats: {', '.join(metadata['log_formats'])} | "
            f"Unique IPs: {metadata['unique_ips']} | "
            f"Pre-flagged suspicious: {metadata['suspicious_count']}"
        )

        # Truncate logs for token safety
        log_lines = redacted_logs.split('\n')
        if len(log_lines) > 3000:
            truncated = '\n'.join(log_lines[:3000])
            reasoning.append(f"Truncated logs from {len(log_lines)} to 3000 lines for API limits.")
        else:
            truncated = redacted_logs

        prompt = f"""Analyze the following PII-redacted server log entries.

{context}

REDACTED LOG DATA:
{truncated}

Respond strictly in valid JSON format."""

        reasoning.append("Sending to Groq Llama 3 for ultra-fast analysis...")

        try:
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=4096,
                response_format={"type": "json_object"}
            )

            raw_text = response.choices[0].message.content
            reasoning.append("Received response from Groq. Parsing JSON...")
                
        except Exception as e:
            error_str = str(e)
            reasoning.append(f"❌ AI analysis error: {error_str}")
            return self._fallback_result(reasoning, error_str)

        if not raw_text:
            return self._fallback_result(reasoning, "Failed to capture text from API.")

        try:
            # Clean and parse
            cleaned = raw_text.replace('```json', '').replace('```', '').strip()

            # Find the JSON object
            start = cleaned.find('{')
            end = cleaned.rfind('}') + 1
            if start >= 0 and end > start:
                data = json.loads(cleaned[start:end])
            else:
                reasoning.append("❌ Failed to extract valid JSON from LLM response.")
                return self._fallback_result(reasoning, raw_text)

            # Validate required fields
            if 'findings' not in data:
                data['findings'] = []

            # `findings` returned by Gemini are auditable objects:
            # { threat_type, severity, evidence, rationale }
            # Convert them into the legacy schema expected by the rest of the SOC pipeline.
            audit_findings = data.get('findings', [])
            data['audit_findings'] = audit_findings
            data['findings'] = self._convert_audit_findings(audit_findings)

            if 'threat_level' not in data:
                data['threat_level'] = self._calc_threat_level(data.get('findings', []))

            reasoning.append(
                f"✅ Analysis complete: {len(data.get('findings', []))} threats detected, "
                f"threat level: {data.get('threat_level', 0)}/100."
            )

            data['reasoning'] = reasoning
            data['raw_response'] = raw_text
            data['ml_confidence'] = locals().get('confidence', 0.0)
            return data

        except Exception as e:
            reasoning.append(f"❌ AI analysis error: {str(e)}")
            return self._fallback_result(reasoning, str(e))

    def investigate(self, redacted_logs: str, question: str) -> str:
        """
        Context-aware investigation chat.

        Args:
            redacted_logs: PII-redacted log content
            question: User's question

        Returns:
            Markdown-formatted answer string
        """
        client = self._get_client()

        # Cap context
        lines = redacted_logs.split('\n')[:2000]
        truncated = '\n'.join(lines)

        prompt = f"""You are a Security Analyst helping investigate server logs.

LOG CONTEXT (PII-redacted):
{truncated}

USER QUESTION:
{question}

INSTRUCTIONS:
- Answer ONLY using evidence from the provided logs.
- If the answer isn't in the logs, say "I cannot find evidence of that in the current logs."
- Be educational: explain WHY something is suspicious.
- Reference specific log entries when making claims.
- Use the redacted IP labels (e.g., [REDACTED_IP_0]) as-is.
- Format your response in clean markdown."""

        try:
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2048
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"⚠️ Investigation error: {str(e)}"

    def _calc_threat_level(self, findings: list) -> int:
        """Calculate an overall threat level (0-100) from findings."""
        if not findings:
            return 0
        scores = [f.get('risk_score', 0) for f in findings]
        if not scores:
            return 0
        # Weighted: max score has most influence
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        # Scale to 0-100
        level = int((max_score * 0.6 + avg_score * 0.4) * 10)
        return min(level, 100)

    def _fallback_result(self, reasoning: list, raw: str) -> dict:
        """Fallback response if the LLM fails or API key is invalid."""
        return {
            'threat_level': 0,
            'summary': 'AI Analysis failed or no API key provided.',
            'findings': [],
            'reasoning': reasoning + ['Using fallback (safe) response.'],
            'raw_response': raw
        }

    def _convert_audit_findings(self, audit_findings: list) -> list:
        """
        Convert auditable findings into the legacy `findings` schema expected by
        `compliance_agent` and `remediation_agent`.
        """
        legacy = []
        for f in audit_findings:
            threat_type = self._normalize_threat_type(f.get('threat_type', 'Suspicious'))
            severity = f.get('severity', 'Low')
            evidence = f.get('evidence', '')
            rationale = f.get('rationale', '')

            risk_score = self.SEVERITY_TO_RISK_SCORE.get(severity, 2)
            confidence = self.SEVERITY_TO_CONFIDENCE.get(severity, 0.6)

            mitre = self.MITRE_MAP.get(threat_type, {'id': '', 'name': ''})
            attacker_ip = self._extract_first_redacted_ip(evidence)

            legacy.append({
                # Legacy schema keys (used across the app)
                'timestamp': '',
                'attacker_ip': attacker_ip,
                'attack_type': threat_type,
                'risk_score': risk_score,
                'confidence': confidence,
                'mitre_attack_id': mitre.get('id', ''),
                'mitre_attack_name': mitre.get('name', ''),
                'status': 'Observed',
                'raw_log_snippet': evidence,
                # First-class evidence + rationale for the Audit Trail
                'evidence': evidence,
                'rationale': rationale,
                # One-line summary for the threat table; full rationale is in `audit_findings`.
                'explanation': self._one_line_rationale(rationale),
                
                # New hackathon fields
                'technical_architecture_flaw': f.get('technical_architecture_flaw', 'N/A'),
                'enterprise_business_impact': f.get('enterprise_business_impact', 'Unknown Impact'),
                'innovative_remediation': f.get('innovative_remediation', 'N/A'),
                'demo_ui_alert': f.get('demo_ui_alert', False),
            })
        return legacy

    def _normalize_threat_type(self, threat_type: str) -> str:
        """
        Normalize Gemini output into the enum keys used by the rest of the project.
        """
        if not threat_type:
            return 'Suspicious'
        t = str(threat_type).strip()

        # If the model already returned one of the enum keys, keep it.
        known = {'SQL_Injection', 'XSS', 'Brute_Force', 'Directory_Traversal', 'Scanner_Probe', 'Suspicious'}
        if t in known:
            return t

        # Keyword fallback (keeps the pipeline resilient).
        low = t.lower()
        if 'sql' in low or 'sqli' in low or 'injection' in low:
            return 'SQL_Injection'
        if 'xss' in low or ('cross' in low and 'script' in low):
            return 'XSS'
        if 'brute' in low or 'force' in low:
            return 'Brute_Force'
        if 'traversal' in low or 'directory' in low or 'path' in low:
            return 'Directory_Traversal'
        if 'scan' in low or 'probe' in low or 'recon' in low:
            return 'Scanner_Probe'
        return 'Suspicious'

    def _extract_first_redacted_ip(self, text: str) -> str:
        match = re.findall(r'\[REDACTED_IP_\d+\]', text or '')
        return match[0] if match else 'N/A'

    def _one_line_rationale(self, rationale: str) -> str:
        """
        Convert the numbered rationale into a compact description for table display.
        """
        r = (rationale or '').strip().replace('\n', ' ')
        return (r[:140] + '...') if len(r) > 140 else r
