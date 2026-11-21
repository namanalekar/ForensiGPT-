import re
from datetime import datetime, timezone
from typing import Any

# Combined Log Format: 192.168.1.1 - user [21/Nov/2026:12:00:00 +0000] "GET /path HTTP/1.1" 200 4523 "referrer" "user-agent"
COMBINED_PATTERN = re.compile(
    r'^([0-9a-fA-F\.:]+)\s+[^\s]+\s+([^\s]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

SUSPICIOUS_WEB_PATTERNS = [
    (r'(\.\./|\.\.\\)', "Path Traversal Attempt"),
    (r'(union\s+select|select.+from|order\s+by\s+\d+)', "SQL Injection Pattern"),
    (r'(cmd\.php|c99\.php|r57\.php|shell\.php|webshell)', "Webshell Access Attempt"),
    (r'(eval\(|base64_decode|system\(|passthru\()', "PHP Code Execution Payload"),
    (r'(/etc/passwd|/etc/shadow|/proc/version)', "Sensitive File Disclosure Probe"),
]

class WebLogParser:
    """Parser for Nginx and Apache Web Server Access Logs (Common & Combined Formats)."""

    @classmethod
    def parse_lines(cls, lines: list[str]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            m = COMBINED_PATTERN.match(line_str)
            if not m:
                continue

            ip, ident_user, ts_str, method, uri, protocol, status_code, bytes_sent, ref, ua = m.groups()

            # Parse timestamp: "21/Nov/2026:12:00:00 +0000"
            dt_iso = None
            epoch = 0.0
            try:
                dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                epoch = dt.timestamp()
                dt_iso = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                pass

            norm_type = "web_request"
            relevance = 25
            status_int = int(status_code)

            # Check suspicious URI patterns
            suspicious_hits = []
            for pat, desc in SUSPICIOUS_WEB_PATTERNS:
                if re.search(pat, uri, re.IGNORECASE):
                    suspicious_hits.append(desc)

            if suspicious_hits:
                norm_type = "web_attack_attempt"
                relevance = 80
            elif status_int >= 500:
                norm_type = "web_server_error"
                relevance = 50
            elif status_int in {401, 403}:
                norm_type = "web_auth_denied"
                relevance = 45
            elif method in {"POST", "PUT", "DELETE"} and status_int == 200:
                relevance = 60

            msg = f"{method} {uri} -> {status_code} ({bytes_sent} bytes)"
            if suspicious_hits:
                msg += f" [ALERT: {', '.join(suspicious_hits)}]"

            events.append({
                "line_number": line_idx,
                "timestamp": dt_iso,
                "timestamp_epoch": epoch,
                "host": ip,
                "process": "web_server",
                "message": msg,
                "raw_line": line_str,
                "normalized_type": norm_type,
                "relevance_score": relevance
            })

        return events
