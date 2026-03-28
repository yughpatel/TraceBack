"""
Log Clustering Module
Groups repetitive log entries using Python sets/hashing before sending to LLM.
Saves tokens by deduplicating structurally similar lines.
"""

import re
from collections import Counter, defaultdict


class LogClusterer:
    """
    Clusters structurally similar log entries to reduce LLM token usage.

    Strategy:
    - Normalize each log line by replacing dynamic parts (IPs, timestamps,
      ports, numbers) with placeholders
    - Group lines by their normalized pattern
    - Send unique patterns + occurrence counts instead of raw duplicates
    """

    # Patterns to normalize
    IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    REDACTED_IP_RE = re.compile(r'\[REDACTED_IP_\d+\]')
    REDACTED_EMAIL_RE = re.compile(r'\[REDACTED_EMAIL_\d+\]')
    TIMESTAMP_APACHE = re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[^\]]*\]')
    TIMESTAMP_SYSLOG = re.compile(r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}')
    PORT_RE = re.compile(r'port\s+\d+')
    PID_RE = re.compile(r'\[\d+\]')
    NUMBER_RE = re.compile(r'\b\d{4,}\b')  # Long numbers (PIDs, sizes, etc.)

    def cluster(self, raw_logs: str) -> dict:
        """
        Cluster log lines by structural similarity.

        Args:
            raw_logs: Raw or redacted log content.

        Returns:
            dict with keys:
                - clustered_text: str (deduplicated text for LLM, with counts)
                - clusters: list of cluster dicts
                - stats: dict with original_lines, unique_patterns, reduction_pct
                - reasoning: list of str
        """
        reasoning = []
        lines = [l.strip() for l in raw_logs.strip().split('\n') if l.strip()]
        reasoning.append(f"Received {len(lines)} log lines for clustering.")

        # Normalize each line
        pattern_map = defaultdict(list)  # normalized → [original_lines]
        for line in lines:
            pattern = self._normalize(line)
            pattern_map[pattern].append(line)

        clusters = []
        for pattern, members in pattern_map.items():
            clusters.append({
                'pattern': pattern,
                'count': len(members),
                'sample': members[0],  # Representative sample
                'all_lines': members,
            })

        # Sort by frequency (most common patterns first)
        clusters.sort(key=lambda c: c['count'], reverse=True)

        unique_patterns = len(clusters)
        original = len(lines)
        reduction = ((original - unique_patterns) / max(original, 1)) * 100

        reasoning.append(
            f"Clustered into {unique_patterns} unique patterns "
            f"(from {original} lines = {reduction:.0f}% reduction)."
        )

        # Build the LLM-optimized text
        clustered_text = self._build_clustered_text(clusters)
        reasoning.append(f"Clustered text is {len(clustered_text)} chars (vs ~{sum(len(l) for l in lines)} original).")

        return {
            'clustered_text': clustered_text,
            'clusters': clusters,
            'stats': {
                'original_lines': original,
                'unique_patterns': unique_patterns,
                'reduction_pct': round(reduction, 1),
            },
            'reasoning': reasoning,
        }

    def _normalize(self, line: str) -> str:
        """Replace dynamic parts with placeholders to find structural matches."""
        normalized = line
        normalized = self.IP_RE.sub('<IP>', normalized)
        normalized = self.REDACTED_IP_RE.sub('<REDACTED_IP>', normalized)
        normalized = self.REDACTED_EMAIL_RE.sub('<REDACTED_EMAIL>', normalized)
        normalized = self.TIMESTAMP_APACHE.sub('<TIMESTAMP>', normalized)
        normalized = self.TIMESTAMP_SYSLOG.sub('<TIMESTAMP>', normalized)
        normalized = self.PORT_RE.sub('port <PORT>', normalized)
        normalized = self.PID_RE.sub('[<PID>]', normalized)
        normalized = self.NUMBER_RE.sub('<NUM>', normalized)
        return normalized

    def _build_clustered_text(self, clusters: list) -> str:
        """Build optimized text for the LLM with deduplication info."""
        parts = []
        for cluster in clusters:
            if cluster['count'] > 1:
                parts.append(
                    f"[{cluster['count']}x REPEATED] {cluster['sample']}"
                )
            else:
                parts.append(cluster['sample'])
        return '\n'.join(parts)
