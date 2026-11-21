import re
from datetime import datetime, timezone
from typing import Any

# RFC 3164 Syslog: Oct 14 09:21:00 host process[123]: message
RFC3164_PATTERN = re.compile(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:]+):\s+(.*)$')
# RFC 5424 Syslog: 2026-11-21T12:00:00Z host process 123 - message
RFC5424_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+([^\s]+)\s+([^\s]+)\s+(?:[^\s]+)\s+(?:[^\s]+)\s+(.*)$')

class SyslogParser:
    """Parser for Linux /var/log/syslog and /var/log/messages (RFC 3164 & RFC 5424)."""

    @classmethod
    def parse_lines(cls, lines: list[str], target_year: int = 2026, timezone_offset_hours: float = 0.0) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            dt_iso = None
            epoch = 0.0
            host = ""
            proc = ""
            msg = line_str
            norm_type = "system_event"
            relevance = 20

            m5424 = RFC5424_PATTERN.match(line_str)
            m3164 = RFC3164_PATTERN.match(line_str)

            if m5424:
                ts_str, host, proc, msg = m5424.groups()
                try:
                    # ISO 8601 parsing
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    epoch = dt.timestamp()
                    dt_iso = dt.astimezone(timezone.utc).isoformat()
                except Exception:
                    pass
            elif m3164:
                ts_str, host, proc, msg = m3164.groups()
                try:
                    dt_naive = datetime.strptime(f"{target_year} {ts_str}", "%Y %b %d %H:%M:%S")
                    epoch = dt_naive.replace(tzinfo=timezone.utc).timestamp() - (timezone_offset_hours * 3600)
                    dt_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                except Exception:
                    pass

            msg_lower = msg.lower()
            if "cron" in proc.lower() or "cron" in msg_lower:
                norm_type = "scheduled_task"
                relevance = 45
            elif any(pkg in msg_lower for pkg in ["installed", "removed", "apt-get", "dpkg"]):
                norm_type = "package_management"
                relevance = 50
            elif "systemd" in proc.lower():
                if any(k in msg_lower for k in ["started", "stopped", "failed"]):
                    norm_type = "service_state"
                    relevance = 40
            elif any(sus in msg_lower for sus in ["segfault", "core dump", "panic", "killed process"]):
                norm_type = "system_anomaly"
                relevance = 75

            events.append({
                "line_number": line_idx,
                "timestamp": dt_iso,
                "timestamp_epoch": epoch,
                "host": host,
                "process": proc,
                "message": msg,
                "raw_line": line_str,
                "normalized_type": norm_type,
                "relevance_score": relevance
            })

        return events
