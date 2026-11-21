from typing import Any

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110.001": {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1548.003": {
        "id": "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/"
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004/"
    },
    "T1053.003": {
        "id": "T1053.003",
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Execution / Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/"
    },
    "T1136.001": {
        "id": "T1136.001",
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/001/"
    },
    "T1098.004": {
        "id": "T1098.004",
        "name": "Account Manipulation: SSH Authorized Keys",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1098/004/"
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1027/"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/"
    }
}

class MitreMapper:
    """Maps forensic activity patterns to standard MITRE ATT&CK techniques."""

    @classmethod
    def get_technique(cls, technique_id: str) -> dict[str, str]:
        return MITRE_TECHNIQUES.get(technique_id, {
            "id": technique_id,
            "name": "Unknown Technique",
            "tactic": "General",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        })

    @classmethod
    def map_event(cls, normalized_type: str, message: str) -> list[dict[str, str]]:
        tags = []
        msg_lower = message.lower()

        if normalized_type in {"auth_failed", "auth_brute_force"} or "brute force" in msg_lower or "failed password" in msg_lower:
            tags.append(cls.get_technique("T1110.001"))
        elif normalized_type == "auth_success" or "accepted password" in msg_lower:
            tags.append(cls.get_technique("T1078"))

        if "sudo:" in msg_lower or normalized_type == "privilege_escalation":
            tags.append(cls.get_technique("T1548.003"))

        if "cron" in msg_lower or normalized_type == "scheduled_task":
            tags.append(cls.get_technique("T1053.003"))

        if any(cmd in msg_lower for cmd in ["useradd", "adduser", "new user:"]):
            tags.append(cls.get_technique("T1136.001"))

        if "authorized_keys" in msg_lower:
            tags.append(cls.get_technique("T1098.004"))

        if any(tool in msg_lower for tool in ["curl ", "wget ", "fetch "]):
            tags.append(cls.get_technique("T1105"))

        if any(obf in msg_lower for obf in ["base64 -d", "base64 --decode", "xxd", "openssl enc"]):
            tags.append(cls.get_technique("T1027"))

        if any(sh in msg_lower for sh in ["/bin/sh", "/bin/bash", "bash -i", "/dev/tcp/"]):
            tags.append(cls.get_technique("T1059.004"))

        if any(web in msg_lower for web in ["../", "union select", "cmd.php", "eval("]):
            tags.append(cls.get_technique("T1190"))

        return tags
