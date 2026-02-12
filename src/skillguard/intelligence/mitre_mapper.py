"""MITRE ATT&CK technique mapper for SkillGuard findings.

Maps engine findings to MITRE ATT&CK techniques and provides
lookup capabilities for technique metadata.
"""

from __future__ import annotations

from skillguard.core.models import EngineResult

# MITRE ATT&CK techniques relevant to AI agent attacks
TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shell commands to execute malicious payloads.",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1059.006": {
        "name": "Python",
        "tactic": "Execution",
        "description": "Adversaries may abuse Python for execution of malicious code.",
        "url": "https://attack.mitre.org/techniques/T1059/006/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using HTTP/S for C2.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data via a non-C2 protocol.",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data over an unencrypted non-C2 protocol.",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search for unsecured credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Adversaries may search local file systems for credential material.",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from OS.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate content to make detection harder.",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "T1027.010": {
        "name": "Command Obfuscation",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate commands to make detection harder.",
        "url": "https://attack.mitre.org/techniques/T1027/010/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from an external system.",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling to facilitate initial or recurring execution.",
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to run a program during boot.",
        "url": "https://attack.mitre.org/techniques/T1547/",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversaries may position themselves between components to intercept data.",
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may manipulate products or delivery mechanisms.",
        "url": "https://attack.mitre.org/techniques/T1195/",
    },
    "T1195.002": {
        "name": "Compromise Software Supply Chain",
        "tactic": "Initial Access",
        "description": "Adversaries may manipulate software dependencies.",
        "url": "https://attack.mitre.org/techniques/T1195/002/",
    },
}


class MitreMapper:
    """Maps findings to MITRE ATT&CK techniques and provides lookups."""

    def get_techniques_from_results(
        self, engine_results: list[EngineResult]
    ) -> list[dict[str, str]]:
        """Extract all unique MITRE ATT&CK techniques from engine results.

        Returns a deduplicated list of technique details.
        """
        technique_ids: set[str] = set()
        for result in engine_results:
            for finding in result.findings:
                technique_ids.update(finding.mitre_attack)

        techniques = []
        for tid in sorted(technique_ids):
            if tid in TECHNIQUE_DB:
                entry = TECHNIQUE_DB[tid].copy()
                entry["id"] = tid
                techniques.append(entry)
            else:
                techniques.append({
                    "id": tid,
                    "name": f"Unknown Technique {tid}",
                    "tactic": "Unknown",
                    "description": "",
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                })

        return techniques

    def get_technique(self, technique_id: str) -> dict[str, str] | None:
        """Look up a single MITRE ATT&CK technique by ID."""
        if technique_id in TECHNIQUE_DB:
            entry = TECHNIQUE_DB[technique_id].copy()
            entry["id"] = technique_id
            return entry
        return None

    def get_tactics_summary(self, engine_results: list[EngineResult]) -> dict[str, int]:
        """Summarize findings by MITRE ATT&CK tactic."""
        tactic_counts: dict[str, int] = {}
        techniques = self.get_techniques_from_results(engine_results)
        for tech in techniques:
            tactic = tech.get("tactic", "Unknown")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return tactic_counts
