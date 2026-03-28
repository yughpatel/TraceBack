"""
Agent 3 – Compliance Auditor Agent
Maps detected threats to PCI-DSS and GDPR regulatory frameworks.
Operates on the findings from the Analyst Agent.
"""


class ComplianceAuditorAgent:
    """
    Agent 3: The Compliance Auditor — Regulatory violation mapping.

    Responsibilities:
    - Map detected attack types to PCI-DSS requirements
    - Map detected attack types to GDPR articles
    - Assess overall compliance status
    - Provide remediation recommendations
    """

    # ── PCI-DSS Mapping ─────────────────────────────────────────
    PCI_DSS_MAP = {
        'SQL_Injection': {
            'requirements': ['6.5.1', '6.6'],
            'description': 'PCI-DSS Req 6.5.1: Prevent injection flaws (SQLi). '
                           'Req 6.6: Web application firewall or code review required.',
            'severity': 'Critical',
        },
        'XSS': {
            'requirements': ['6.5.7'],
            'description': 'PCI-DSS Req 6.5.7: Prevent cross-site scripting (XSS) vulnerabilities.',
            'severity': 'High',
        },
        'Brute_Force': {
            'requirements': ['8.1.6', '8.1.7', '10.2.4'],
            'description': 'PCI-DSS Req 8.1.6: Limit repeated access attempts (lockout after 6 tries). '
                           'Req 8.1.7: Set lockout duration to minimum 30 minutes. '
                           'Req 10.2.4: Log invalid logical access attempts.',
            'severity': 'High',
        },
        'Directory_Traversal': {
            'requirements': ['6.5.8'],
            'description': 'PCI-DSS Req 6.5.8: Prevent improper access control—directory traversal '
                           'indicates missing input validation.',
            'severity': 'Critical',
        },
        'Scanner_Probe': {
            'requirements': ['11.4'],
            'description': 'PCI-DSS Req 11.4: Use intrusion detection/prevention systems '
                           'to detect and alert on network intrusions.',
            'severity': 'Medium',
        },
        'Suspicious': {
            'requirements': ['10.6'],
            'description': 'PCI-DSS Req 10.6: Review logs and security events for anomalies.',
            'severity': 'Low',
        },
    }

    # ── GDPR Mapping ────────────────────────────────────────────
    GDPR_MAP = {
        'SQL_Injection': {
            'articles': ['Art. 32', 'Art. 33', 'Art. 5(1)(f)'],
            'description': 'GDPR Art. 32: Implement appropriate technical measures (input validation, WAF). '
                           'Art. 33: Data breach notification within 72 hours if personal data is exposed. '
                           'Art. 5(1)(f): Integrity and confidentiality principle.',
            'severity': 'Critical',
        },
        'XSS': {
            'articles': ['Art. 32', 'Art. 5(1)(f)'],
            'description': 'GDPR Art. 32: Appropriate security measures required to prevent '
                           'unauthorized data access through XSS.',
            'severity': 'High',
        },
        'Brute_Force': {
            'articles': ['Art. 32', 'Art. 33', 'Art. 34'],
            'description': 'GDPR Art. 32: Implement access controls and account lockout. '
                           'Art. 33/34: If brute force succeeds, breach notification may be required.',
            'severity': 'High',
        },
        'Directory_Traversal': {
            'articles': ['Art. 32', 'Art. 5(1)(f)'],
            'description': 'GDPR Art. 32: Ensure proper access controls prevent unauthorized '
                           'file system access.',
            'severity': 'Critical',
        },
        'Scanner_Probe': {
            'articles': ['Art. 32'],
            'description': 'GDPR Art. 32: Implement monitoring and detection measures.',
            'severity': 'Medium',
        },
        'Suspicious': {
            'articles': ['Art. 32'],
            'description': 'GDPR Art. 32: Maintain ability to ensure ongoing confidentiality.',
            'severity': 'Low',
        },
    }

    # ── MITRE ATT&CK fallback mapping (if not provided by Analyst) ──
    MITRE_MAP = {
        'SQL_Injection': {'id': 'T1190', 'name': 'Exploit Public-Facing Application'},
        'XSS': {'id': 'T1189', 'name': 'Drive-by Compromise'},
        'Brute_Force': {'id': 'T1110', 'name': 'Brute Force'},
        'Directory_Traversal': {'id': 'T1083', 'name': 'File and Directory Discovery'},
        'Scanner_Probe': {'id': 'T1595', 'name': 'Active Scanning'},
        'Suspicious': {'id': 'T1071', 'name': 'Application Layer Protocol'},
        'DoS': {'id': 'T1498', 'name': 'Network Denial of Service'},
        'Probe': {'id': 'T1595', 'name': 'Active Scanning'},
        'R2L': {'id': 'T1110', 'name': 'Brute Force'},
        'U2R': {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation'},
    }

    # ── NSL-KDD → PCI-DSS Requirement 10 (Logging & Monitoring) ────
    NSL_KDD_PCI_REQ10_MAP = {
        'DoS': {
            'requirements': ['10.6.1'],
            'description': 'PCI-DSS Req 10.6.1: Review security events daily — '
                           'DoS traffic indicates inadequate real-time monitoring.',
            'severity': 'High',
        },
        'Probe': {
            'requirements': ['10.2.7', '11.4'],
            'description': 'PCI-DSS Req 10.2.7: Log creation/deletion of system-level objects. '
                           'Req 11.4: Deploy IDS/IPS to detect network scanning.',
            'severity': 'Medium',
        },
        'R2L': {
            'requirements': ['10.2.4', '10.2.5'],
            'description': 'PCI-DSS Req 10.2.4: Log invalid logical access attempts. '
                           'Req 10.2.5: Log use of identification and authentication mechanisms.',
            'severity': 'High',
        },
        'U2R': {
            'requirements': ['10.2.2', '10.2.5'],
            'description': 'PCI-DSS Req 10.2.2: Log all actions taken by any individual with '
                           'root or administrative privileges. '
                           'Req 10.2.5: Log changes to identification and authentication mechanisms.',
            'severity': 'Critical',
        },
    }

    # ── NSL-KDD → GDPR Article 32 (Security of Processing) ────────
    NSL_KDD_GDPR_ART32_MAP = {
        'DoS': {
            'articles': ['Art. 32(1)(b)'],
            'description': 'GDPR Art. 32(1)(b): Ensure ongoing availability and '
                           'resilience of processing systems and services.',
            'severity': 'High',
        },
        'Probe': {
            'articles': ['Art. 32(1)(d)'],
            'description': 'GDPR Art. 32(1)(d): Regularly test, assess, and evaluate the '
                           'effectiveness of technical and organisational security measures.',
            'severity': 'Medium',
        },
        'R2L': {
            'articles': ['Art. 32(1)(b)'],
            'description': 'GDPR Art. 32(1)(b): Ensure ongoing confidentiality of '
                           'processing systems and services.',
            'severity': 'High',
        },
        'U2R': {
            'articles': ['Art. 32(1)(a)'],
            'description': 'GDPR Art. 32(1)(a): Implement pseudonymisation and encryption '
                           'of personal data to prevent privilege-escalation attacks.',
            'severity': 'Critical',
        },
    }

    def audit(self, findings: list) -> dict:
        """
        Run compliance audit on analyst findings.

        Args:
            findings: List of finding dicts from Analyst Agent.

        Returns:
            dict with keys:
                - pci_dss_violations: list of violation dicts
                - gdpr_violations: list of violation dicts
                - compliance_status: str ('Compliant', 'At Risk', 'Non-Compliant')
                - compliance_score: int (0-100, 100 = fully compliant)
                - remediation: list of recommendation strings
                - reasoning: list of str (agent's reasoning steps)
                - audit_entries: list of detailed audit trail entries
        """
        reasoning = []
        reasoning.append("Starting compliance audit on analyst findings...")
        reasoning.append(f"Evaluating {len(findings)} threat findings against PCI-DSS and GDPR.")

        pci_violations = []
        gdpr_violations = []
        audit_entries = []
        seen_pci = set()
        seen_gdpr = set()

        for finding in findings:
            attack_type = self._normalize_attack_type(finding.get('attack_type', ''))
            risk_score = finding.get('risk_score', 0)
            confidence = finding.get('confidence', 0.8)
            mitre_id = finding.get('mitre_attack_id', '')

            # Fallback MITRE mapping
            if not mitre_id and attack_type in self.MITRE_MAP:
                mitre_info = self.MITRE_MAP[attack_type]
                mitre_id = mitre_info['id']

            # ── PCI-DSS Check (standard web-attack mapping) ──
            if attack_type in self.PCI_DSS_MAP:
                pci = self.PCI_DSS_MAP[attack_type]
                req_key = tuple(pci['requirements'])
                if req_key not in seen_pci:
                    seen_pci.add(req_key)
                    pci_violations.append({
                        'attack_type': attack_type,
                        'requirements': pci['requirements'],
                        'description': pci['description'],
                        'severity': pci['severity'],
                        'mitre_id': mitre_id,
                    })

            # ── PCI-DSS Req 10 Check (NSL-KDD categories) ──
            if attack_type in self.NSL_KDD_PCI_REQ10_MAP:
                nsl_pci = self.NSL_KDD_PCI_REQ10_MAP[attack_type]
                req_key = ('NSL_KDD',) + tuple(nsl_pci['requirements'])
                if req_key not in seen_pci:
                    seen_pci.add(req_key)
                    pci_violations.append({
                        'attack_type': attack_type,
                        'requirements': nsl_pci['requirements'],
                        'description': nsl_pci['description'],
                        'severity': nsl_pci['severity'],
                        'mitre_id': mitre_id,
                    })

            # ── GDPR Check (standard web-attack mapping) ──
            if attack_type in self.GDPR_MAP:
                gdpr = self.GDPR_MAP[attack_type]
                art_key = tuple(gdpr['articles'])
                if art_key not in seen_gdpr:
                    seen_gdpr.add(art_key)
                    gdpr_violations.append({
                        'attack_type': attack_type,
                        'articles': gdpr['articles'],
                        'description': gdpr['description'],
                        'severity': gdpr['severity'],
                    })

            # ── GDPR Art. 32 Check (NSL-KDD categories) ──
            if attack_type in self.NSL_KDD_GDPR_ART32_MAP:
                nsl_gdpr = self.NSL_KDD_GDPR_ART32_MAP[attack_type]
                art_key = ('NSL_KDD',) + tuple(nsl_gdpr['articles'])
                if art_key not in seen_gdpr:
                    seen_gdpr.add(art_key)
                    gdpr_violations.append({
                        'attack_type': attack_type,
                        'articles': nsl_gdpr['articles'],
                        'description': nsl_gdpr['description'],
                        'severity': nsl_gdpr['severity'],
                    })

            # ── Collect all PCI + GDPR reqs for this finding ──
            pci_reqs_list = []
            if attack_type in self.PCI_DSS_MAP:
                pci_reqs_list.extend(self.PCI_DSS_MAP[attack_type]['requirements'])
            if attack_type in self.NSL_KDD_PCI_REQ10_MAP:
                pci_reqs_list.extend(self.NSL_KDD_PCI_REQ10_MAP[attack_type]['requirements'])

            gdpr_arts_list = []
            if attack_type in self.GDPR_MAP:
                gdpr_arts_list.extend(self.GDPR_MAP[attack_type]['articles'])
            if attack_type in self.NSL_KDD_GDPR_ART32_MAP:
                gdpr_arts_list.extend(self.NSL_KDD_GDPR_ART32_MAP[attack_type]['articles'])

            # ── Audit Trail Entry ──
            audit_entries.append({
                'finding': finding.get('attack_type', 'Unknown'),
                'ip': finding.get('attacker_ip', 'N/A'),
                'risk_score': risk_score,
                'confidence': confidence,
                'mitre_id': mitre_id,
                'pci_reqs': ', '.join(pci_reqs_list) if pci_reqs_list else '',
                'gdpr_arts': ', '.join(gdpr_arts_list) if gdpr_arts_list else '',
                'evidence': finding.get('evidence', finding.get('raw_log_snippet', '')),
                'rationale': finding.get('rationale', ''),
                'reasoning': f"Detected {attack_type} → mapped to MITRE {mitre_id}, "
                            f"risk={risk_score}/10, confidence={confidence:.0%}",
            })

        # ── Compliance Assessment ──
        reasoning.append(
            f"Found {len(pci_violations)} PCI-DSS violations, "
            f"{len(gdpr_violations)} GDPR violations."
        )

        # Calculate compliance score
        if not findings:
            compliance_score = 100
            compliance_status = 'Compliant'
        else:
            severity_weights = {'Critical': 30, 'High': 20, 'Medium': 10, 'Low': 5}
            total_penalty = 0
            for v in pci_violations + gdpr_violations:
                total_penalty += severity_weights.get(v.get('severity', 'Low'), 5)
            compliance_score = max(0, 100 - total_penalty)
            if compliance_score >= 80:
                compliance_status = 'At Risk'
            elif compliance_score >= 50:
                compliance_status = 'Non-Compliant'
            else:
                compliance_status = 'Critical Non-Compliance'

        reasoning.append(f"Compliance score: {compliance_score}/100 → Status: {compliance_status}")

        # ── Remediation ──
        remediation = self._generate_remediation(pci_violations, gdpr_violations)
        reasoning.append(f"Generated {len(remediation)} remediation recommendations.")
        reasoning.append("✅ Compliance Auditor complete.")

        return {
            'pci_dss_violations': pci_violations,
            'gdpr_violations': gdpr_violations,
            'compliance_status': compliance_status,
            'compliance_score': compliance_score,
            'remediation': remediation,
            'reasoning': reasoning,
            'audit_entries': audit_entries,
        }

    def _normalize_attack_type(self, attack_type: str) -> str:
        """Normalize attack type strings to match our mapping keys.
        Recognises both standard web-attack names and NSL-KDD categories."""
        t = attack_type.lower().replace(' ', '_')
        # NSL-KDD categories (exact match first)
        nsl_kdd = {'dos': 'DoS', 'probe': 'Probe', 'r2l': 'R2L', 'u2r': 'U2R'}
        if t in nsl_kdd:
            return nsl_kdd[t]
        if 'sql' in t or 'sqli' in t or 'injection' in t:
            return 'SQL_Injection'
        if 'xss' in t or 'cross' in t and 'script' in t:
            return 'XSS'
        if 'brute' in t or 'force' in t or 'credential' in t:
            return 'Brute_Force'
        if 'traversal' in t or 'directory' in t or 'path' in t:
            return 'Directory_Traversal'
        if 'scan' in t or 'probe' in t or 'recon' in t:
            return 'Scanner_Probe'
        return 'Suspicious'

    def _generate_remediation(self, pci_violations: list, gdpr_violations: list) -> list:
        """Generate actionable remediation recommendations."""
        recommendations = []
        seen = set()

        attack_remediations = {
            'SQL_Injection': [
                '🔒 Implement parameterized queries / prepared statements for all database operations',
                '🛡️ Deploy a Web Application Firewall (WAF) with SQL injection rule sets',
                '🔍 Conduct code review focusing on input validation and output encoding',
            ],
            'XSS': [
                '🔒 Implement Content Security Policy (CSP) headers',
                '🧹 Sanitize and encode all user inputs before rendering in HTML',
                '🛡️ Enable HTTPOnly and Secure flags on all cookies',
            ],
            'Brute_Force': [
                '🔐 Implement account lockout after 5-6 failed attempts (PCI-DSS 8.1.6)',
                '⏱️ Set minimum 30-minute lockout duration (PCI-DSS 8.1.7)',
                '🔑 Enforce multi-factor authentication (MFA) for all admin access',
                '📊 Implement rate limiting on authentication endpoints',
            ],
            'Directory_Traversal': [
                '🔒 Implement strict input validation — reject paths containing ".."',
                '📁 Use chroot jails or containerization to limit file system access',
                '🛡️ Configure web server to deny access to sensitive directories',
            ],
            'Scanner_Probe': [
                '🛡️ Deploy an Intrusion Detection System (IDS) like Snort or Suricata',
                '🚫 Implement IP-based rate limiting and geo-blocking for non-business regions',
                '📝 Remove default pages, admin panels, and unused endpoints',
            ],
        }

        for v in pci_violations + gdpr_violations:
            attack_type = v.get('attack_type', '')
            if attack_type in attack_remediations and attack_type not in seen:
                seen.add(attack_type)
                recommendations.extend(attack_remediations[attack_type])

        if not recommendations:
            recommendations.append('✅ No critical compliance violations detected. Continue monitoring.')

        return recommendations
