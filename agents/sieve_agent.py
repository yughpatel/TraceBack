"""
Agent 1 – Sieve Agent
Handles log ingestion, PII redaction, and preliminary parsing.
Ensures privacy by redacting IPs and emails before LLM processing.
"""

import re
from collections import Counter, OrderedDict


class SieveAgent:
    """
    Agent 1: The Sieve — Log ingestion and PII redaction.

    Responsibilities:
    - Parse raw log lines (Apache, auth/syslog, generic)
    - Detect and redact PII (IP addresses, email addresses)
    - Maintain a private PII mapping for the audit trail
    - Return redacted logs + metadata
    """

    # ── Regex Patterns ──────────────────────────────────────────
    IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    EMAIL_PATTERN = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')

    APACHE_PATTERN = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s"]*)\s*(?:HTTP/[\d.]+)?"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    )

    AUTH_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[\d+\])?:\s+'
        r'(?P<message>.*)'
    )

    # ── Suspicious Pattern Indicators (for pre-flagging) ────────
    SQLI_INDICATORS = re.compile(
        r"(union\s+select|'\s*or\s+'|1\s*=\s*1|drop\s+table|"
        r"insert\s+into|select\s+.*from|--\s*$|;\s*drop)",
        re.IGNORECASE
    )

    XSS_INDICATORS = re.compile(
        r"(<\s*script|javascript\s*:|onerror\s*=|alert\s*\(|"
        r"document\.cookie|<\s*iframe|<\s*img[^>]+on)",
        re.IGNORECASE
    )

    TRAVERSAL_INDICATORS = re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)",
        re.IGNORECASE
    )

    BRUTE_FORCE_KEYWORDS = [
        'failed password', 'authentication failure', 'invalid user',
        'failed login', 'access denied'
    ]

    def process(self, raw_content: str) -> dict:
        """
        Main processing pipeline for the Sieve Agent.

        Args:
            raw_content: Raw log file content as string.

        Returns:
            dict with keys:
                - redacted_logs: str (PII-redacted log content)
                - pii_map: dict mapping redacted tokens → original values
                - metadata: dict with line_count, log_formats, unique_ips, etc.
                - entries: list of parsed entry dicts
                - reasoning: list of str (agent's reasoning steps)
                - suspicious_flags: list of pre-flagged suspicious entries
        """
        reasoning = []
        reasoning.append("Starting log ingestion and PII analysis...")

        lines = raw_content.strip().split('\n')
        reasoning.append(f"Received {len(lines)} log lines for processing.")

        # ── Step 1: Detect log formats ──
        formats = self._detect_formats(lines)
        reasoning.append(f"Detected log formats: {', '.join(formats) if formats else 'unknown'}")

        # ── Step 2: Extract and redact PII ──
        pii_map, redacted_content, ip_count, email_count = self._redact_pii(raw_content)
        reasoning.append(
            f"PII Redaction complete: {ip_count} unique IPs redacted, "
            f"{email_count} unique emails redacted."
        )

        # ── Step 3: Parse entries ──
        entries, suspicious_flags = self._parse_entries(lines)
        reasoning.append(f"Parsed {len(entries)} log entries.")
        if suspicious_flags:
            reasoning.append(
                f"⚠️ Pre-flagged {len(suspicious_flags)} suspicious entries "
                f"based on pattern matching."
            )
        else:
            reasoning.append("No obviously suspicious patterns detected in pre-scan.")

        # ── Step 4: Build metadata ──
        all_ips = [e.get('ip') for e in entries if e.get('ip')]
        ip_freq = Counter(all_ips)

        metadata = {
            'total_lines': len(lines),
            'parsed_entries': len(entries),
            'log_formats': formats,
            'unique_ips': len(set(all_ips)),
            'ip_frequency': dict(ip_freq.most_common(20)),
            'suspicious_count': len(suspicious_flags),
            'pii_redacted': {'ips': ip_count, 'emails': email_count},
        }

        reasoning.append("✅ Sieve Agent processing complete. Logs are PII-safe for AI analysis.")

        return {
            'redacted_logs': redacted_content,
            'pii_map': pii_map,
            'metadata': metadata,
            'entries': entries,
            'reasoning': reasoning,
            'suspicious_flags': suspicious_flags,
        }

    def _detect_formats(self, lines: list) -> list:
        """Detect which log formats are present."""
        formats = set()
        sample = lines[:50]  # Check first 50 lines

        for line in sample:
            if self.APACHE_PATTERN.match(line.strip()):
                formats.add('Apache/Nginx Access Log')
            elif self.AUTH_PATTERN.match(line.strip()):
                formats.add('Auth/Syslog')

        if not formats:
            formats.add('Generic')

        return list(formats)

    def _redact_pii(self, content: str) -> tuple:
        """
        Redact IPs and emails from log content.

        Returns:
            (pii_map, redacted_content, ip_count, email_count)
        """
        pii_map = OrderedDict()
        ip_counter = 0
        email_counter = 0

        # Find all unique IPs
        unique_ips = list(OrderedDict.fromkeys(self.IP_PATTERN.findall(content)))
        for ip in unique_ips:
            token = f"[REDACTED_IP_{ip_counter}]"
            pii_map[token] = ip
            content = content.replace(ip, token)
            ip_counter += 1

        # Find all unique emails
        unique_emails = list(OrderedDict.fromkeys(self.EMAIL_PATTERN.findall(content)))
        for email in unique_emails:
            token = f"[REDACTED_EMAIL_{email_counter}]"
            pii_map[token] = email
            content = content.replace(email, token)
            email_counter += 1

        return pii_map, content, ip_counter, email_counter

    def _parse_entries(self, lines: list) -> tuple:
        """
        Parse each line and flag suspicious entries.

        Returns:
            (entries_list, suspicious_flags_list)
        """
        entries = []
        suspicious = []

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            entry = self._parse_single_line(line, i + 1)
            entries.append(entry)

            if entry.get('flags'):
                suspicious.append(entry)

        return entries, suspicious

    def _parse_single_line(self, line: str, line_num: int) -> dict:
        """Parse a single log line with format detection and flag suspicious patterns."""

        # Try Apache format
        match = self.APACHE_PATTERN.match(line)
        if match:
            entry = {
                'line_num': line_num,
                'raw': line,
                'format': 'apache',
                'ip': match.group('ip'),
                'timestamp': match.group('timestamp'),
                'method': match.group('method'),
                'path': match.group('path'),
                'status': int(match.group('status')),
                'flags': [],
            }
            self._flag_web_patterns(entry)
            return entry

        # Try auth/syslog format
        match = self.AUTH_PATTERN.match(line)
        if match:
            message = match.group('message')
            ips = self.IP_PATTERN.findall(message)
            entry = {
                'line_num': line_num,
                'raw': line,
                'format': 'auth',
                'ip': ips[0] if ips else None,
                'timestamp': match.group('timestamp'),
                'service': match.group('service'),
                'message': message,
                'flags': [],
            }
            self._flag_auth_patterns(entry)
            return entry

        # Fallback
        ips = self.IP_PATTERN.findall(line)
        return {
            'line_num': line_num,
            'raw': line,
            'format': 'generic',
            'ip': ips[0] if ips else None,
            'flags': [],
        }

    def _flag_web_patterns(self, entry: dict):
        """Flag suspicious patterns in web log entries."""
        path = entry.get('path', '')
        if self.SQLI_INDICATORS.search(path):
            entry['flags'].append('Possible_SQLi')
        if self.XSS_INDICATORS.search(path):
            entry['flags'].append('Possible_XSS')
        if self.TRAVERSAL_INDICATORS.search(path):
            entry['flags'].append('Possible_Traversal')

    def _flag_auth_patterns(self, entry: dict):
        """Flag suspicious patterns in auth log entries."""
        message = entry.get('message', '').lower()
        for keyword in self.BRUTE_FORCE_KEYWORDS:
            if keyword in message:
                entry['flags'].append('Possible_BruteForce')
                break
        if 'invalid user' in message:
            entry['flags'].append('Invalid_User')
