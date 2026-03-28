"""
TraceBack Sentinel – Test Script v3.0
Tests all agents and modules including new features.
Run: python test_agents.py
"""
import io
import sys
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
print("=" * 60)
print("TraceBack Sentinel - Agent Test Suite v3.0")
print("=" * 60)

# ── Test 1: Imports ──────────────────────────────────────────
print("\n[TEST 1] Importing all modules...")
try:
    from agents.sieve_agent import SieveAgent
    from agents.analyst_agent import AnalystAgent
    from agents.compliance_agent import ComplianceAuditorAgent
    from agents.remediation_agent import RemediationAgent
    from data.sample_logs import get_sample_logs
    from utils.prompts import ANALYST_SYSTEM_PROMPT
    from utils.clustering import LogClusterer
    print("  [OK] All imports successful")
except Exception as e:
    print(f"  [FAIL] Import error: {e}")
    sys.exit(1)

# ── Test 2: Sample Logs ─────────────────────────────────────
print("\n[TEST 2] Loading sample logs...")
samples = get_sample_logs()
print(f"  [OK] {len(samples)} sample log sets loaded")

# ── Test 3: Sieve Agent on each sample ──────────────────────
print("\n[TEST 3] Testing Sieve Agent (PII Redaction)...")
sieve = SieveAgent()

for name, log_content in samples.items():
    result = sieve.process(log_content)
    meta = result['metadata']

    # Verify redaction worked
    for token, original in result['pii_map'].items():
        assert token in result['redacted_logs'], f"Redaction failed: {token}"
        assert original not in result['redacted_logs'], f"PII leak: {original}"

    assert len(result['reasoning']) > 0
    # Windows console may not support emoji glyphs (cp1252). Keep test output ASCII-only.
    safe_name = name.encode('ascii', 'ignore').decode('ascii') or 'sample'
    print(f"  [OK] Sieve: {safe_name} ({meta['total_lines']} lines, {meta['pii_redacted']['ips']} IPs)")

# ── Test 4: Log Clustering ──────────────────────────────────
print("\n[TEST 4] Testing Log Clustering...")
clusterer = LogClusterer()

for name, log_content in samples.items():
    cluster_result = clusterer.cluster(log_content)
    stats = cluster_result['stats']

    assert stats['original_lines'] > 0
    assert stats['unique_patterns'] > 0
    assert stats['unique_patterns'] <= stats['original_lines']
    assert len(cluster_result['clustered_text']) > 0
    assert stats['reduction_pct'] >= 0

    safe_name = name.encode('ascii', 'ignore').decode('ascii') or 'sample'
    print(f"  [OK] Clustering: {safe_name} ({stats['original_lines']} -> {stats['unique_patterns']} patterns, "
          f"{stats['reduction_pct']}% reduction)")

# ── Test 5: Compliance Agent ────────────────────────────────
print("\n[TEST 5] Testing Compliance Agent...")
compliance = ComplianceAuditorAgent()

mock_findings = [
    {'attack_type': 'SQL_Injection', 'risk_score': 9, 'confidence': 0.95,
     'mitre_attack_id': 'T1190', 'attacker_ip': '[REDACTED_IP_0]',
     'evidence': 'GET /index.php?id=1 UNION SELECT 1,2--', 'rationale': 'Matched SQLi pattern.'},
    {'attack_type': 'DoS', 'risk_score': 8, 'confidence': 0.98,
     'mitre_attack_id': 'T1498', 'attacker_ip': '[REDACTED_IP_1]',
     'evidence': '20,000 requests in 1 second', 'rationale': 'ML identified as DoS attack.'},
    {'attack_type': 'Directory_Traversal', 'risk_score': 6, 'confidence': 0.85,
     'mitre_attack_id': 'T1083', 'attacker_ip': '[REDACTED_IP_2]',
     'evidence': 'GET /../../etc/passwd', 'rationale': 'Path traversal attempt.'},
]

comp_result = compliance.audit(mock_findings)
assert comp_result['compliance_score'] >= 0 and comp_result['compliance_score'] <= 100
assert len(comp_result['pci_dss_violations']) > 0
assert len(comp_result['gdpr_violations']) > 0
assert len(comp_result['audit_entries']) == len(mock_findings)

# Verify evidence/rationale passthrough
for entry in comp_result['audit_entries']:
    assert 'evidence' in entry
    assert 'rationale' in entry
    assert entry['evidence'] != ''
    assert entry['rationale'] != ''

# Verify NSL-KDD mapping (DoS)
dos_entries = [e for e in comp_result['audit_entries'] if e['finding'] == 'DoS']
assert len(dos_entries) == 1
assert '10.6.1' in dos_entries[0]['pci_reqs']
assert 'Art. 32' in dos_entries[0]['gdpr_arts']

print(f"  [OK] Compliance: {len(comp_result['pci_dss_violations'])} PCI-DSS, "
      f"{len(comp_result['gdpr_violations'])} GDPR, score={comp_result['compliance_score']}")

# ── Test 6: Remediation Agent ───────────────────────────────
print("\n[TEST 6] Testing Remediation Agent...")
remediator = RemediationAgent()
rem_result = remediator.remediate(mock_findings)

assert len(rem_result['scripts']) > 0, "Should generate scripts"
assert len(rem_result['audit_scripts']) > 0, "Should generate audit script entries"
assert len(rem_result['reasoning']) > 0

# Verify scripts have IP placeholders replaced
for script in rem_result['scripts']:
    assert '{attacker_ip}' not in script['code'], "Placeholder not replaced"
    assert script['lang'] in ['bash', 'nginx', 'apache', 'text']
    assert len(script['code']) > 10

print(f"  [OK] Remediation: {len(rem_result['scripts'])} scripts, "
      f"{len(rem_result['audit_scripts'])} audit entries")

# Verify audit trail has remediation scripts
for entry in rem_result['audit_scripts']:
    assert 'script_code' in entry
    assert 'attack_type' in entry
    assert 'target_ip' in entry
print("  [OK] Audit trail includes remediation scripts")

# ── Test 7: Analyst Agent init ──────────────────────────────
print("\n[TEST 7] Testing Analyst Agent (no API call)...")
analyst = AnalystAgent("test_key")
assert analyst.is_configured() == True
analyst_empty = AnalystAgent("")
assert analyst_empty.is_configured() == False
print("  [OK] Analyst init checks passed")

# ── Test 8: System prompts ──────────────────────────────────
print("\n[TEST 8] Validating system prompts...")
assert "MITRE" in ANALYST_SYSTEM_PROMPT
assert "JSON" in ANALYST_SYSTEM_PROMPT
assert "threat_type" in ANALYST_SYSTEM_PROMPT
assert "severity" in ANALYST_SYSTEM_PROMPT
assert "evidence" in ANALYST_SYSTEM_PROMPT
assert "rationale" in ANALYST_SYSTEM_PROMPT
print("  [OK] System prompts validated")

# ── Test 9: Full pipeline (Sieve -> Cluster -> Compliance -> Remediation) ──
print("\n[TEST 9] End-to-end pipeline test...")
for name, log_content in samples.items():
    s = sieve.process(log_content)
    cl = clusterer.cluster(s['redacted_logs'])
    cp = compliance.audit(mock_findings)
    rm = remediator.remediate(mock_findings)

    assert 'redacted_logs' in s
    assert 'clustered_text' in cl
    assert 'pci_dss_violations' in cp
    assert 'scripts' in rm
    assert 'audit_scripts' in rm

print("  [OK] Full pipeline verified for all samples")

# ── Summary ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("ALL 9 TESTS PASSED")
print("=" * 60)
