"""
MITRE ATT&CK Framework Mapping Engine.
Maps static file attributes, dynamic behaviors, and email anomalies
to standardized MITRE ATT&CK Tactics and Techniques with concrete evidence.
"""
from typing import Dict, Any, List

MITRE_DATABASE = {
    "T1059.001": {
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter: PowerShell",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1059.003": {
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/"
    },
    "T1055": {
        "tactic": "Privilege Escalation / Defense Evasion",
        "name": "Process Injection",
        "url": "https://attack.mitre.org/techniques/T1055/"
    },
    "T1547.001": {
        "tactic": "Persistence",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1490": {
        "tactic": "Impact",
        "name": "Inhibit System Recovery",
        "url": "https://attack.mitre.org/techniques/T1490/"
    },
    "T1486": {
        "tactic": "Impact",
        "name": "Data Encrypted for Impact (Ransomware)",
        "url": "https://attack.mitre.org/techniques/T1486/"
    },
    "T1555.003": {
        "tactic": "Credential Access",
        "name": "Credentials from Web Browsers",
        "url": "https://attack.mitre.org/techniques/T1555/003/"
    },
    "T1071.001": {
        "tactic": "Command and Control",
        "name": "Application Layer Protocol: Web Protocols",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1027.002": {
        "tactic": "Defense Evasion",
        "name": "Software Packing",
        "url": "https://attack.mitre.org/techniques/T1027/002/"
    },
    "T1566.001": {
        "tactic": "Initial Access",
        "name": "Phishing: Spearphishing Attachment",
        "url": "https://attack.mitre.org/techniques/T1566/001/"
    },
    "T1566.002": {
        "tactic": "Initial Access",
        "name": "Phishing: Spearphishing Link",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "T1082": {
        "tactic": "Discovery",
        "name": "System Information Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/"
    },
    "T1041": {
        "tactic": "Exfiltration",
        "name": "Exfiltration Over C2 Channel",
        "url": "https://attack.mitre.org/techniques/T1041/"
    },
    "T1204.002": {
        "tactic": "Execution",
        "name": "User Execution: Malicious File",
        "url": "https://attack.mitre.org/techniques/T1204/002/"
    }
}

class MitreMapper:
    def __init__(self):
        pass

    def map_analysis(self, static_report: Dict[str, Any], dynamic_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        mapped_techniques = {}

        # 1. YARA rules
        for y_match in static_report.get("yara_matches", []):
            tid = y_match.get("mitre_technique")
            if tid and tid in MITRE_DATABASE:
                rule_name = y_match.get("rule")
                self._add_finding(mapped_techniques, tid, f"Matched YARA rule '{rule_name}'")

        # 2. Suspicious APIs in PE
        pe_info = static_report.get("pe_analysis") or {}
        susp_apis = pe_info.get("suspicious_apis", {})
        if "Process Injection" in susp_apis:
            self._add_finding(mapped_techniques, "T1055", f"Imported process injection APIs: {', '.join(susp_apis['Process Injection'])}")
        if "Persistence" in susp_apis:
            self._add_finding(mapped_techniques, "T1547.001", f"Imported persistence APIs: {', '.join(susp_apis['Persistence'])}")
        if "Defense Evasion" in susp_apis:
            self._add_finding(mapped_techniques, "T1027.002", f"Imported anti-analysis/evasion APIs: {', '.join(susp_apis['Defense Evasion'])}")
        if "Cryptography / Ransomware" in susp_apis:
            self._add_finding(mapped_techniques, "T1486", f"Imported cryptographic APIs: {', '.join(susp_apis['Cryptography / Ransomware'])}")

        # 3. Dynamic Timeline & Process Activity
        for p in dynamic_report.get("process_tree", []):
            cmd = p.get("cmdline", "").lower()
            if "powershell" in cmd:
                self._add_finding(mapped_techniques, "T1059.001", f"Spawned PowerShell: {p.get('cmdline')}")
            if "cmd.exe" in cmd:
                self._add_finding(mapped_techniques, "T1059.003", f"Spawned Windows Command Shell: {p.get('cmdline')}")
            if "vssadmin" in cmd or "delete shadows" in cmd:
                self._add_finding(mapped_techniques, "T1490", f"Inhibited recovery via command: {p.get('cmdline')}")

        # 4. Registry operations
        for reg in dynamic_report.get("registry_operations", []):
            path = reg.get("path", "").lower()
            if "currentversion\\run" in path:
                self._add_finding(mapped_techniques, "T1547.001", f"Modified Autostart Run Key: {reg.get('path')} = {reg.get('value')}")
            if "cryptography\\machineguid" in path or "bios" in path:
                self._add_finding(mapped_techniques, "T1082", f"Queried Machine Identity / Hardware GUID: {reg.get('path')}")

        # 5. File Operations
        for f in dynamic_report.get("file_operations", []):
            fpath = f.get("path", "").lower()
            if "login data" in fpath or "logins.json" in fpath:
                self._add_finding(mapped_techniques, "T1555.003", f"Targeted browser credentials database: {f.get('path')}")
            if ".wncry" in fpath:
                self._add_finding(mapped_techniques, "T1486", f"Encrypted file with ransomware extension: {f.get('path')}")

        # 6. Network / C2
        if dynamic_report.get("http_requests") or dynamic_report.get("network_connections"):
            c2_count = len(dynamic_report.get("http_requests", []))
            self._add_finding(mapped_techniques, "T1071.001", f"Established {c2_count} application-layer HTTP/HTTPS C2 sessions")

        return list(mapped_techniques.values())

    def _add_finding(self, mapped: Dict[str, Any], tid: str, evidence: str):
        meta = MITRE_DATABASE.get(tid, {"tactic": "General", "name": tid, "url": "https://attack.mitre.org/"})
        if tid not in mapped:
            mapped[tid] = {
                "technique_id": tid,
                "tactic": meta["tactic"],
                "technique_name": meta["name"],
                "url": meta["url"],
                "evidence": []
            }
        if evidence not in mapped[tid]["evidence"]:
            mapped[tid]["evidence"].append(evidence)
