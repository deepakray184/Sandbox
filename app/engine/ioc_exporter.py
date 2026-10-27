"""
IOC Exporter Engine.
Exports Indicators of Compromise into STIX 2.1, MISP JSON, Suricata/Snort rules,
auto-generated YARA signatures, and CSV.
"""
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List

def defang(val: str) -> str:
    return val.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

class IocExporter:
    def __init__(self):
        pass

    def export_stix21(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates an OASIS STIX 2.1 compliant JSON bundle."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        now = datetime.utcnow().isoformat() + "Z"
        objects = []

        filename = report.get("filename", "unknown_sample")
        sha256 = report.get("hashes", {}).get("sha256", "")
        verdict = report.get("verdict", "Malicious")

        # 1. Malware SDO
        malware_id = f"malware--{uuid.uuid4()}"
        objects.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": now,
            "modified": now,
            "name": filename,
            "is_family": False,
            "malware_types": [verdict.lower()],
            "description": f"Analyzed sample {filename} with verdict {verdict}"
        })

        # 2. File Hash Indicator
        if sha256:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"File hash for {filename}",
                "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                "pattern_type": "stix",
                "valid_from": now
            })

        # 3. Network Indicators
        for dns in report.get("sandbox", {}).get("dns_queries", []):
            domain = dns.get("query")
            if domain:
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": f"C2 Domain: {domain}",
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "valid_from": now
                })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

    def export_misp(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a MISP standard event JSON."""
        event_id = str(uuid.uuid4())
        filename = report.get("filename", "sample")
        hashes = report.get("hashes", {})
        attributes = []

        if hashes.get("sha256"):
            attributes.append({"type": "sha256", "category": "Payload delivery", "value": hashes["sha256"], "to_ids": True})
        if hashes.get("md5"):
            attributes.append({"type": "md5", "category": "Payload delivery", "value": hashes["md5"], "to_ids": True})

        for dns in report.get("sandbox", {}).get("dns_queries", []):
            attributes.append({"type": "domain", "category": "Network activity", "value": dns.get("query", ""), "to_ids": True})

        for conn in report.get("sandbox", {}).get("network_connections", []):
            ip = conn.get("dst", "").split(":")[0]
            if ip:
                attributes.append({"type": "ip-dst", "category": "Network activity", "value": ip, "to_ids": True})

        return {
            "Event": {
                "uuid": event_id,
                "info": f"Vanguard Analysis: {filename} ({report.get('verdict', 'Unknown')})",
                "threat_level_id": "1" if report.get("verdict") == "Malicious" else "3",
                "analysis": "2",
                "Attribute": attributes
            }
        }

    def export_suricata(self, report: Dict[str, Any]) -> str:
        """Generates Suricata / Snort network IDS detection rules."""
        rules = []
        sid = 1000001
        filename = report.get("filename", "sample")

        for req in report.get("sandbox", {}).get("http_requests", []):
            host = req.get("host")
            if host:
                rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"VANGUARD-SOC Malicious HTTP C2 Connection to {host} ({filename})"; flow:established,to_server; http.host; content:"{host}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1

        for dns in report.get("sandbox", {}).get("dns_queries", []):
            domain = dns.get("query")
            if domain:
                rule = f'alert dns $HOME_NET any -> any 53 (msg:"VANGUARD-SOC Malicious C2 DNS Query for {domain} ({filename})"; dns.query; content:"{domain}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1

        if not rules:
            rules.append(f'# No network indicators detected during dynamic execution of {filename}')

        return "\n".join(rules)

    def export_yara(self, report: Dict[str, Any]) -> str:
        """Generates a tailored YARA rule for this specific sample."""
        filename = report.get("filename", "sample")
        safe_name = "".join([c if c.isalnum() else "_" for c in filename])
        sha256 = report.get("hashes", {}).get("sha256", "")
        imphash = report.get("hashes", {}).get("imphash", "")
        sample_strings = report.get("strings", {}).get("sample", [])[:5]

        str_lines = []
        for i, s in enumerate(sample_strings):
            clean_s = s.replace('\\', '\\\\').replace('"', '\\"')
            if len(clean_s) >= 4 and len(clean_s) < 100:
                str_lines.append(f'        $s{i+1} = "{clean_s}"')

        yara_code = f"""rule Vanguard_AutoGenerated_{safe_name}
{{
    meta:
        description = "Auto-generated threat rule for {filename}"
        author = "Vanguard SOC Analysis Platform"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        sha256 = "{sha256}"
        imphash = "{imphash}"
        threat_score = "{report.get('threat_score', 0)}/100"
    
    strings:
{chr(10).join(str_lines) if str_lines else '        $magic = { 4D 5A }'}

    condition:
        {f'2 of them' if len(str_lines) >= 2 else 'any of them'}
}}"""
        return yara_code

    def export_csv(self, report: Dict[str, Any]) -> str:
        """Generates a CSV string of all extracted IOCs."""
        rows = ["Indicator Type,Indicator Value,Defanged Value,Description,Context"]
        hashes = report.get("hashes", {})
        if hashes.get("sha256"):
            rows.append(f"SHA-256,{hashes['sha256']},{hashes['sha256']},File SHA256 Hash,Sample Identification")
        if hashes.get("md5"):
            rows.append(f"MD5,{hashes['md5']},{hashes['md5']},File MD5 Hash,Sample Identification")

        for dns in report.get("sandbox", {}).get("dns_queries", []):
            q = dns.get("query", "")
            rows.append(f"Domain,{q},{defang(q)},C2 DNS Resolution,Dynamic Sandbox")

        for conn in report.get("sandbox", {}).get("network_connections", []):
            ip = conn.get("dst", "")
            rows.append(f"IP-Port,{ip},{defang(ip)},Outbound Connection,Dynamic Sandbox")

        for f in report.get("sandbox", {}).get("dropped_files", []):
            p = f.get("path", "")
            rows.append(f"Dropped File,{p},{p},Artifact Dropped to Disk,Filesystem Activity")

        return "\n".join(rows)
