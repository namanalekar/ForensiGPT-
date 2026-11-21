import re
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict

SSH_FAILED_PATTERN = re.compile(r'Failed password for (?:invalid user |user )?([^\s]+) from ([0-9a-fA-F\.:]+) port (\d+)')
SSH_ACCEPTED_PATTERN = re.compile(r'Accepted (?:password|publickey) for ([^\s]+) from ([0-9a-fA-F\.:]+) port (\d+)')
SUDO_CMD_PATTERN = re.compile(r'sudo:\s+([^\s:]+)\s*:\s+TTY=[^\s]+\s+;\s+PWD=[^\s]+\s+;\s+USER=([^\s]+)\s+;\s+COMMAND=(.+)')
USERADD_PATTERN = re.compile(r'new user: name=([^\s,]+)')

class AuthLogParser:
    """Parser for Linux /var/log/auth.log and /var/log/secure."""

    @classmethod
    def parse_lines(cls, lines: list[str], target_year: int = 2026, timezone_offset_hours: float = 0.0) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        # Track failed attempts per IP for brute-force bursts: ip -> list of (epoch, line_num)
        failed_attempts_by_ip: dict[str, list[tuple[float, int]]] = defaultdict(list)

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # Standard syslog timestamp: "Oct 14 09:21:00 hostname sshd[1234]: ..."
            parts = line_str.split(maxsplit=4)
            if len(parts) < 5:
                continue

            month_str, day_str, time_str, host, rest = parts
            raw_ts = f"{month_str} {day_str} {time_str}"

            dt = None
            epoch = 0.0
            try:
                # Construct datetime with explicit target year and UTC offset
                dt_naive = datetime.strptime(f"{target_year} {raw_ts}", "%Y %b %d %H:%M:%S")
                epoch = dt_naive.replace(tzinfo=timezone.utc).timestamp() - (timezone_offset_hours * 3600)
                dt_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            except Exception:
                dt_iso = None

            # Split process and message
            proc = ""
            msg = rest
            if ":" in rest:
                proc_part, msg_part = rest.split(":", 1)
                proc = proc_part.strip()
                msg = msg_part.strip()

            norm_type = "auth_other"
            relevance = 20

            # 1. Failed SSH password
            m_fail = SSH_FAILED_PATTERN.search(msg)
            if m_fail:
                user, ip, port = m_fail.groups()
                norm_type = "auth_failed"
                relevance = 50
                if epoch > 0:
                    failed_attempts_by_ip[ip].append((epoch, line_idx))

            # 2. Accepted SSH password
            m_succ = SSH_ACCEPTED_PATTERN.search(msg)
            if m_succ:
                user, ip, port = m_succ.groups()
                norm_type = "auth_success"
                relevance = 70

            # 3. Sudo command execution
            m_sudo = SUDO_CMD_PATTERN.search(line_str)
            if m_sudo:
                invoker, target_user, command = m_sudo.groups()
                norm_type = "privilege_escalation"
                relevance = 80
                # Higher score if executing suspicious tools or root shells
                if any(k in command for k in ["/bin/bash", "/bin/sh", "curl", "wget", "nc ", "chmod +x"]):
                    relevance = 95

            # 4. New user created
            m_uadd = USERADD_PATTERN.search(msg)
            if m_uadd:
                norm_type = "account_created"
                relevance = 85

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

        # Evaluate brute force bursts (>5 failed attempts from same IP within 60s)
        brute_force_ips = set()
        for ip, attempts in failed_attempts_by_ip.items():
            if len(attempts) >= 5:
                # Check sliding window of 60s
                for i in range(len(attempts) - 4):
                    t_start = attempts[i][0]
                    t_end = attempts[i + 4][0]
                    if (t_end - t_start) <= 60.0:
                        brute_force_ips.add(ip)
                        break

        # Elevate events associated with brute force IPs
        for ev in events:
            for bf_ip in brute_force_ips:
                if bf_ip in ev["message"] and ev["normalized_type"] == "auth_failed":
                    ev["normalized_type"] = "auth_brute_force"
                    ev["relevance_score"] = 90
                    ev["message"] += f" [BURST: >5 failed attempts in 60s from {bf_ip}]"

        return events
