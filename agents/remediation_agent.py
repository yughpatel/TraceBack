"""
Agent 4 – Remediation Agent
Generates actionable bash commands, config patches, and firewall rules
based on detected threats from the Analyst Agent.
"""


class RemediationAgent:
    """
    Agent 4: The Remediator — Agentic remediation script generation.

    Responsibilities:
    - Generate executable bash commands for each detected threat
    - Produce config patches (iptables, fail2ban, ModSecurity, etc.)
    - Provide copy-pasteable scripts for immediate incident response
    - Log all generated scripts in the audit trail
    """

    # ── Remediation Templates (bash / config) ─────────────────
    REMEDIATION_SCRIPTS = {
        'SQL_Injection': {
            'title': 'SQL Injection Remediation',
            'scripts': [
                {
                    'name': 'Block attacker IP (iptables)',
                    'lang': 'bash',
                    'code': '# Block the attacker IP immediately\nsudo iptables -A INPUT -s {attacker_ip} -j DROP\nsudo iptables-save > /etc/iptables/rules.v4\necho "[✓] Blocked {attacker_ip} via iptables"',
                },
                {
                    'name': 'Enable ModSecurity WAF rules',
                    'lang': 'bash',
                    'code': '# Enable OWASP ModSecurity Core Rule Set for SQLi protection\nsudo apt-get install -y libapache2-mod-security2\nsudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf\nsudo sed -i \'s/SecRuleEngine DetectionOnly/SecRuleEngine On/\' /etc/modsecurity/modsecurity.conf\nsudo systemctl restart apache2\necho "[✓] ModSecurity WAF enabled with SQLi protection"',
                },
                {
                    'name': 'Nginx WAF config patch',
                    'lang': 'nginx',
                    'code': '# Add to nginx server block to block common SQLi patterns\nlocation / {\n    # Block SQL injection attempts\n    if ($query_string ~* "(union|select|insert|update|delete|drop|alter|create|exec)" ) {\n        return 403;\n    }\n    if ($query_string ~* "(\\\'|\\"|;|\\-\\-)" ) {\n        return 403;\n    }\n}',
                },
            ],
        },
        'XSS': {
            'title': 'XSS Attack Remediation',
            'scripts': [
                {
                    'name': 'Add Content Security Policy headers',
                    'lang': 'bash',
                    'code': '# Add CSP headers to Apache config\nsudo bash -c \'echo "Header set Content-Security-Policy \\"default-src \\x27self\\x27; script-src \\x27self\\x27\\"" >> /etc/apache2/conf-enabled/security.conf\'\nsudo bash -c \'echo "Header set X-XSS-Protection \\"1; mode=block\\"" >> /etc/apache2/conf-enabled/security.conf\'\nsudo bash -c \'echo "Header set X-Content-Type-Options \\"nosniff\\"" >> /etc/apache2/conf-enabled/security.conf\'\nsudo a2enmod headers\nsudo systemctl restart apache2\necho "[✓] CSP and XSS protection headers enabled"',
                },
                {
                    'name': 'Block attacker IP',
                    'lang': 'bash',
                    'code': '# Block the XSS attacker IP\nsudo iptables -A INPUT -s {attacker_ip} -j DROP\nsudo iptables-save > /etc/iptables/rules.v4\necho "[✓] Blocked XSS attacker {attacker_ip}"',
                },
            ],
        },
        'Brute_Force': {
            'title': 'Brute Force Remediation',
            'scripts': [
                {
                    'name': 'Install & configure Fail2Ban',
                    'lang': 'bash',
                    'code': '# Install and configure Fail2Ban for SSH brute force protection\nsudo apt-get install -y fail2ban\nsudo bash -c \'cat > /etc/fail2ban/jail.local << EOF\n[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 5\nbantime = 1800\nfindtime = 600\nEOF\'\nsudo systemctl enable fail2ban\nsudo systemctl restart fail2ban\necho "[✓] Fail2Ban installed: 5 max retries, 30-min ban"',
                },
                {
                    'name': 'Block brute force IP immediately',
                    'lang': 'bash',
                    'code': '# Immediately block the brute force attacker\nsudo iptables -A INPUT -s {attacker_ip} -j DROP\nsudo fail2ban-client set sshd banip {attacker_ip}\necho "[✓] Banned {attacker_ip} via iptables + fail2ban"',
                },
                {
                    'name': 'Harden SSH configuration',
                    'lang': 'bash',
                    'code': '# Harden SSH to prevent brute force\nsudo sed -i \'s/#MaxAuthTries 6/MaxAuthTries 3/\' /etc/ssh/sshd_config\nsudo sed -i \'s/#PermitRootLogin yes/PermitRootLogin no/\' /etc/ssh/sshd_config\nsudo sed -i \'s/#PasswordAuthentication yes/PasswordAuthentication no/\' /etc/ssh/sshd_config\nsudo systemctl restart sshd\necho "[✓] SSH hardened: root login disabled, key-only auth"',
                },
            ],
        },
        'Directory_Traversal': {
            'title': 'Directory Traversal Remediation',
            'scripts': [
                {
                    'name': 'Block traversal in Apache',
                    'lang': 'apache',
                    'code': '# Add to Apache config to block directory traversal\n<Directory />\n    Options -Indexes -FollowSymLinks\n    AllowOverride None\n    Require all denied\n</Directory>\n\n# Block ".." in URLs via rewrite rules\nRewriteEngine On\nRewriteCond %{QUERY_STRING} (\\.\\./) [NC,OR]\nRewriteCond %{QUERY_STRING} (\\.\\.\\\\) [NC]\nRewriteRule .* - [F,L]',
                },
                {
                    'name': 'Block attacker IP',
                    'lang': 'bash',
                    'code': '# Block directory traversal attacker\nsudo iptables -A INPUT -s {attacker_ip} -j DROP\necho "[✓] Blocked traversal attacker {attacker_ip}"',
                },
            ],
        },
        'Scanner_Probe': {
            'title': 'Scanner/Probe Remediation',
            'scripts': [
                {
                    'name': 'Rate limit with iptables',
                    'lang': 'bash',
                    'code': '# Rate-limit incoming connections to prevent scanning\nsudo iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP\nsudo iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 20 -j DROP\nsudo iptables -A INPUT -p tcp -m state --state NEW -m recent --set\nsudo iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP\necho "[✓] Rate limiting enabled: max 20 concurrent, 10 new/min"',
                },
                {
                    'name': 'Block scanner IP',
                    'lang': 'bash',
                    'code': '# Block the scanning IP\nsudo iptables -A INPUT -s {attacker_ip} -j DROP\necho "[✓] Blocked scanner {attacker_ip}"',
                },
            ],
        },
    }

    def remediate(self, findings: list) -> dict:
        """
        Generate remediation scripts for each detected threat.

        Args:
            findings: List of finding dicts from Analyst Agent.

        Returns:
            dict with keys:
                - scripts: list of remediation script dicts
                - summary: str (brief summary of actions)
                - reasoning: list of str (agent's reasoning steps)
                - audit_scripts: list of dicts for audit trail
        """
        reasoning = []
        reasoning.append("Starting remediation script generation...")
        reasoning.append(f"Processing {len(findings)} threat findings for actionable responses.")

        all_scripts = []
        audit_scripts = []
        seen_types = set()

        for finding in findings:
            attack_type = self._normalize_attack_type(finding.get('attack_type', ''))
            attacker_ip = finding.get('attacker_ip', 'UNKNOWN_IP')

            if attack_type not in self.REMEDIATION_SCRIPTS:
                continue

            if attack_type in seen_types:
                continue
            seen_types.add(attack_type)

            template = self.REMEDIATION_SCRIPTS[attack_type]

            for script_tmpl in template['scripts']:
                # Replace {attacker_ip} placeholder
                code = script_tmpl['code'].replace('{attacker_ip}', attacker_ip)
                script_entry = {
                    'attack_type': attack_type,
                    'title': template['title'],
                    'name': script_tmpl['name'],
                    'lang': script_tmpl['lang'],
                    'code': code,
                }
                all_scripts.append(script_entry)

                # Audit trail entry
                audit_scripts.append({
                    'attack_type': attack_type,
                    'script_name': script_tmpl['name'],
                    'script_code': code,
                    'target_ip': attacker_ip,
                })

            reasoning.append(
                f"Generated {len(template['scripts'])} scripts for {attack_type} "
                f"targeting {attacker_ip}"
            )

        summary = f"Generated {len(all_scripts)} remediation scripts for {len(seen_types)} threat types."
        reasoning.append(f"✅ Remediation complete: {summary}")

        return {
            'scripts': all_scripts,
            'summary': summary,
            'reasoning': reasoning,
            'audit_scripts': audit_scripts,
        }

    def _normalize_attack_type(self, attack_type: str) -> str:
        """Normalize attack type strings to match mapping keys."""
        t = attack_type.lower().replace(' ', '_')
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
