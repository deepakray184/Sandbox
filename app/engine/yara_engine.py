"""
High-performance Pure-Python YARA rule compiler and scanner.
Provides enterprise signature scanning without requiring unstable C-extensions.
"""
import re
from typing import List, Dict, Any, Optional

class YaraRule:
    def __init__(self, name: str, meta: Dict[str, Any], strings: Dict[str, Any], condition: str):
        self.name = name
        self.meta = meta
        self.strings = strings  # identifier -> {'type': 'text'|'hex'|'regex', 'pattern': ...}
        self.condition = condition

    def match(self, data: bytes) -> Optional[Dict[str, Any]]:
        matched_strings = []
        identifiers_matched = set()

        for identifier, rule_str in self.strings.items():
            pattern_type = rule_str.get('type', 'text')
            pattern = rule_str.get('pattern')
            nocase = rule_str.get('nocase', False)

            if pattern_type == 'text':
                target_bytes = pattern.encode('utf-8', errors='ignore') if isinstance(pattern, str) else pattern
                if nocase:
                    idx = data.lower().find(target_bytes.lower())
                else:
                    idx = data.find(target_bytes)
                if idx != -1:
                    matched_strings.append({
                        "identifier": identifier,
                        "offset": hex(idx),
                        "snippet": str(target_bytes[:60])
                    })
                    identifiers_matched.add(identifier)

            elif pattern_type == 'hex':
                # Convert hex string "4D 5A ?? 00" to regex or bytes
                hex_clean = pattern.replace(' ', '')
                try:
                    target_bytes = bytes.fromhex(hex_clean)
                    idx = data.find(target_bytes)
                    if idx != -1:
                        matched_strings.append({
                            "identifier": identifier,
                            "offset": hex(idx),
                            "snippet": f"Hex: {target_bytes.hex()[:30]}"
                        })
                        identifiers_matched.add(identifier)
                except Exception:
                    pass

            elif pattern_type == 'regex':
                flags = re.IGNORECASE if nocase else 0
                regex_bytes = pattern.encode('utf-8') if isinstance(pattern, str) else pattern
                m = re.search(regex_bytes, data, flags)
                if m:
                    matched_strings.append({
                        "identifier": identifier,
                        "offset": hex(m.start()),
                        "snippet": str(m.group(0)[:60])
                    })
                    identifiers_matched.add(identifier)

        # Evaluate condition
        is_hit = False
        cond = self.condition.strip().lower()
        if cond == "any of them":
            is_hit = len(identifiers_matched) > 0
        elif cond == "all of them":
            is_hit = len(identifiers_matched) == len(self.strings) and len(self.strings) > 0
        elif "of them" in cond:
            # e.g. "2 of them"
            try:
                num = int(cond.split("of them")[0].strip())
                is_hit = len(identifiers_matched) >= num
            except Exception:
                is_hit = len(identifiers_matched) > 0
        else:
            # Simple identifier presence e.g. "$a and ($b or $c)"
            eval_expr = cond
            for ident in self.strings.keys():
                eval_expr = re.sub(rf"\{ident}\b", str(ident in identifiers_matched), eval_expr)
            eval_expr = eval_expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
            try:
                # safe evaluation of boolean expression
                is_hit = bool(eval(eval_expr, {"__builtins__": {}}, {}))
            except Exception:
                is_hit = len(identifiers_matched) > 0

        if is_hit:
            return {
                "rule": self.name,
                "meta": self.meta,
                "matched_strings": matched_strings,
                "severity": self.meta.get("severity", "MEDIUM"),
                "threat_family": self.meta.get("threat_family", "Generic"),
                "mitre_technique": self.meta.get("mitre_technique", "")
            }
        return None


class YaraEngine:
    def __init__(self):
        self.rules: List[YaraRule] = []
        self._load_builtin_rules()

    def add_rule(self, rule: YaraRule):
        self.rules.append(rule)

    def scan(self, data: bytes) -> List[Dict[str, Any]]:
        results = []
        for rule in self.rules:
            res = rule.match(data)
            if res:
                results.append(res)
        return results

    def _load_builtin_rules(self):
        # 1. EICAR Test File
        self.add_rule(YaraRule(
            name="EICAR_Standard_AV_Test_File",
            meta={
                "description": "Standard EICAR Anti-Virus Test File Signature",
                "author": "Vanguard SOC",
                "severity": "LOW",
                "threat_family": "EICAR-Test",
                "mitre_technique": "T1204"
            },
            strings={
                "$eicar": {"type": "text", "pattern": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}
            },
            condition="any of them"
        ))

        # 2. Ransomware Generic Shadow Copy & Recovery Disabling
        self.add_rule(YaraRule(
            name="Ransomware_Inhibit_System_Recovery",
            meta={
                "description": "Command lines used by Ransomware to inhibit recovery by deleting shadow copies",
                "author": "Vanguard SOC",
                "severity": "CRITICAL",
                "threat_family": "Ransomware.Generic",
                "mitre_technique": "T1490"
            },
            strings={
                "$vss1": {"type": "text", "pattern": "vssadmin delete shadows", "nocase": True},
                "$vss2": {"type": "text", "pattern": "vssadmin.exe Delete Shadows /All /Quiet", "nocase": True},
                "$wmic": {"type": "text", "pattern": "wmic shadowcopy delete", "nocase": True},
                "$bcd1": {"type": "text", "pattern": "bcdedit /set {default} recoveryenabled No", "nocase": True},
                "$bcd2": {"type": "text", "pattern": "bcdedit /set {default} bootstatuspolicy ignoreallfailures", "nocase": True},
                "$wbadmin": {"type": "text", "pattern": "wbadmin delete catalog -quiet", "nocase": True}
            },
            condition="any of them"
        ))

        # 3. WannaCry Ransomware Artifacts
        self.add_rule(YaraRule(
            name="Ransomware_WannaCry_Indicators",
            meta={
                "description": "WannaCryptor / WanaCrypt0r 2.0 signatures and mutexes",
                "author": "Vanguard SOC",
                "severity": "CRITICAL",
                "threat_family": "Ransomware.WannaCry",
                "mitre_technique": "T1486"
            },
            strings={
                "$wnry": {"type": "text", "pattern": ".WNCRY", "nocase": True},
                "$mutex": {"type": "text", "pattern": "Global\\MsWinZonesCacheCounterMutexA", "nocase": True},
                "$c2_kill": {"type": "text", "pattern": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "nocase": True},
                "$msg": {"type": "text", "pattern": "Ooops, your files have been encrypted!", "nocase": True},
                "$tasksche": {"type": "text", "pattern": "tasksche.exe", "nocase": True}
            },
            condition="any of them"
        ))

        # 4. RedLine / Stealer Generic Browser Credential Harvesting
        self.add_rule(YaraRule(
            name="Infostealer_Browser_Credential_Theft",
            meta={
                "description": "Infostealer routines targeting Chromium/Firefox Login Data and Cookies",
                "author": "Vanguard SOC",
                "severity": "HIGH",
                "threat_family": "Infostealer.RedLine",
                "mitre_technique": "T1555.003"
            },
            strings={
                "$s1": {"type": "text", "pattern": "\\Login Data", "nocase": True},
                "$s2": {"type": "text", "pattern": "SELECT action_url, username_value, password_value FROM logins", "nocase": True},
                "$s3": {"type": "text", "pattern": "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "nocase": True},
                "$s4": {"type": "text", "pattern": "logins.json", "nocase": True},
                "$s5": {"type": "text", "pattern": "\\Wallets\\", "nocase": True},
                "$s6": {"type": "text", "pattern": "api.telegram.org/bot", "nocase": True}
            },
            condition="2 of them"
        ))

        # 5. PowerShell Obfuscated Download & Exec Cradle
        self.add_rule(YaraRule(
            name="PowerShell_Obfuscated_Download_Cradle",
            meta={
                "description": "Heuristic detection of malicious PowerShell download cradles and bypass flags",
                "author": "Vanguard SOC",
                "severity": "HIGH",
                "threat_family": "Trojan.Downloader",
                "mitre_technique": "T1059.001"
            },
            strings={
                "$p1": {"type": "regex", "pattern": r"powershell(\.exe)?\s+(-[a-zA-Z]*w(indowstyle)?\s+hidden)", "nocase": True},
                "$p2": {"type": "regex", "pattern": r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "nocase": True},
                "$p3": {"type": "text", "pattern": "Net.WebClient).DownloadString(", "nocase": True},
                "$p4": {"type": "text", "pattern": "Invoke-Expression", "nocase": True},
                "$p5": {"type": "text", "pattern": "IEX(", "nocase": True},
                "$p6": {"type": "text", "pattern": "Bypass -ExecutionPolicy", "nocase": True}
            },
            condition="2 of them"
        ))

        # 6. Malicious Office VBA Macro Execution
        self.add_rule(YaraRule(
            name="Malicious_Office_VBA_Macro",
            meta={
                "description": "Office document containing suspicious auto-execution macros and shell invocation",
                "author": "Vanguard SOC",
                "severity": "HIGH",
                "threat_family": "Exploit.Macro.Generic",
                "mitre_technique": "T1204.002"
            },
            strings={
                "$auto1": {"type": "text", "pattern": "AutoOpen", "nocase": True},
                "$auto2": {"type": "text", "pattern": "Workbook_Open", "nocase": True},
                "$auto3": {"type": "text", "pattern": "Document_Open", "nocase": True},
                "$exec1": {"type": "text", "pattern": "WScript.Shell", "nocase": True},
                "$exec2": {"type": "text", "pattern": "CreateObject(\"Shell.Application\")", "nocase": True},
                "$exec3": {"type": "text", "pattern": "CallByName", "nocase": True}
            },
            condition="2 of them"
        ))

        # 7. Cobalt Strike Beacon & Meterpreter Shellcode
        self.add_rule(YaraRule(
            name="CobaltStrike_Beacon_Signatures",
            meta={
                "description": "Known memory config strings and beacon patterns for Cobalt Strike",
                "author": "Vanguard SOC",
                "severity": "CRITICAL",
                "threat_family": "Backdoor.CobaltStrike",
                "mitre_technique": "T1071.001"
            },
            strings={
                "$cs1": {"type": "text", "pattern": "%s as %s\\%s: %d", "nocase": False},
                "$cs2": {"type": "text", "pattern": "beacon.dll", "nocase": True},
                "$cs3": {"type": "text", "pattern": "/activity", "nocase": True},
                "$cs4": {"type": "text", "pattern": "ReflectiveLoader", "nocase": False},
                "$cs5": {"type": "text", "pattern": "\\\\.\\pipe\\msse-", "nocase": True}
            },
            condition="2 of them"
        ))

        # 8. WebShell PHP Backdoor
        self.add_rule(YaraRule(
            name="WebShell_PHP_Generic",
            meta={
                "description": "Common PHP webshell execution functions and obfuscation patterns",
                "author": "Vanguard SOC",
                "severity": "HIGH",
                "threat_family": "WebShell.PHP",
                "mitre_technique": "T1505.003"
            },
            strings={
                "$w1": {"type": "text", "pattern": "eval(base64_decode(", "nocase": True},
                "$w2": {"type": "text", "pattern": "system($_GET[", "nocase": True},
                "$w3": {"type": "text", "pattern": "system($_POST[", "nocase": True},
                "$w4": {"type": "text", "pattern": "passthru($_POST[", "nocase": True},
                "$w5": {"type": "text", "pattern": "shell_exec($_POST[", "nocase": True},
                "$w6": {"type": "text", "pattern": "assert($_POST[", "nocase": True}
            },
            condition="any of them"
        ))

        # 9. UPX Packed Executable
        self.add_rule(YaraRule(
            name="Executable_UPX_Packed",
            meta={
                "description": "Executable packed with UPX compressor",
                "author": "Vanguard SOC",
                "severity": "LOW",
                "threat_family": "Packer.UPX",
                "mitre_technique": "T1027.002"
            },
            strings={
                "$upx0": {"type": "text", "pattern": "UPX0"},
                "$upx1": {"type": "text", "pattern": "UPX1"},
                "$upx2": {"type": "text", "pattern": "UPX!"}
            },
            condition="any of them"
        ))

        # 10. Process Injection API Patterns
        self.add_rule(YaraRule(
            name="Process_Injection_API_Chain",
            meta={
                "description": "Imports or references typical process injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)",
                "author": "Vanguard SOC",
                "severity": "HIGH",
                "threat_family": "Trojan.Injector",
                "mitre_technique": "T1055"
            },
            strings={
                "$api1": {"type": "text", "pattern": "VirtualAllocEx"},
                "$api2": {"type": "text", "pattern": "WriteProcessMemory"},
                "$api3": {"type": "text", "pattern": "CreateRemoteThread"},
                "$api4": {"type": "text", "pattern": "QueueUserAPC"},
                "$api5": {"type": "text", "pattern": "NtQueueApcThread"}
            },
            condition="2 of them"
        ))
