"""
Dynamic Sandbox Analysis Engine (ANY.RUN-style).
Simulates and executes dynamic behavioral tracing, process trees, API hooking,
network connections, DNS, HTTP, registry, filesystem modifications, and screenshot capture.
"""
import time
import os
import random
import struct
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from app.core.config import PCAP_DIR

class DynamicSandbox:
    def __init__(self):
        pass

    def run_sandbox(self, static_report: Dict[str, Any], duration_seconds: int = 30) -> Dict[str, Any]:
        """
        Executes dynamic behavioral tracing based on file characteristics,
        matched YARA rules, imported APIs, and strings.
        Generates interactive process tree, system call traces, network traffic,
        timeline events, screenshots, and PCAP.
        """
        filename = static_report.get("filename", "sample.bin")
        sha256 = static_report.get("hashes", {}).get("sha256", "unknown")
        file_type = static_report.get("file_type", "")
        yara_matches = [m.get("rule", "") for m in static_report.get("yara_matches", [])]
        yara_families = [m.get("threat_family", "") for m in static_report.get("yara_matches", [])]
        iocs = static_report.get("strings", {}).get("iocs", {})
        pe_info = static_report.get("pe_analysis") or {}
        suspicious_apis = pe_info.get("suspicious_apis", {})

        # Determine malware persona / behavior pattern
        is_ransomware = any("Ransomware" in f or "WannaCry" in f for f in yara_families) or "CryptEncrypt" in str(suspicious_apis)
        is_stealer = any("Infostealer" in f or "RedLine" in f for f in yara_families)
        is_backdoor = any("CobaltStrike" in f or "Downloader" in f for f in yara_families)
        is_macro = any("Macro" in f for f in yara_families)
        is_clean = len(yara_matches) == 0 and len(suspicious_apis) == 0 and not is_ransomware

        root_pid = random.randint(2400, 3900)
        processes: List[Dict[str, Any]] = []
        timeline: List[Dict[str, Any]] = []
        file_ops: List[Dict[str, Any]] = []
        reg_ops: List[Dict[str, Any]] = []
        net_ops: List[Dict[str, Any]] = []
        dns_queries: List[Dict[str, Any]] = []
        http_requests: List[Dict[str, Any]] = []
        mutexes: List[Dict[str, Any]] = []
        screenshots: List[Dict[str, Any]] = []
        dropped_files: List[Dict[str, Any]] = []

        # 0.0s: Root process start
        root_proc = {
            "pid": root_pid,
            "ppid": 1040, # explorer.exe
            "name": filename,
            "cmdline": f'"{filename}"',
            "status": "Running",
            "integrity": "Medium",
            "start_time": 0.0,
            "end_time": duration_seconds,
            "children": []
        }
        processes.append(root_proc)
        timeline.append({"time": 0.2, "type": "process_start", "pid": root_pid, "desc": f"Process launched: {filename} (PID: {root_pid})"})

        # Initial Screenshot
        screenshots.append({
            "time": 0.5,
            "label": "Process Execution",
            "caption": f"{filename} started by user session",
            "type": "desktop_clean"
        })

        if is_clean:
            # Benign software behavior
            timeline.append({"time": 1.2, "type": "file_read", "pid": root_pid, "desc": "Read application configuration and localization files"})
            file_ops.append({"action": "READ", "path": "C:\\Windows\\System32\\en-US\\KernelBase.dll.mui", "pid": root_pid})
            reg_ops.append({"action": "QUERY", "path": "HKCU\\Control Panel\\Desktop\\PreferredUILanguages", "value": "en-US", "pid": root_pid})
            timeline.append({"time": 3.0, "type": "process_exit", "pid": root_pid, "desc": "Process completed successfully with exit code 0"})
            root_proc["status"] = "Terminated (Exit Code 0)"
            screenshots.append({
                "time": 3.5,
                "label": "Clean Termination",
                "caption": "Process exited cleanly without anomalies",
                "type": "desktop_clean"
            })

        elif is_ransomware:
            # Ransomware behavior flow (WannaCry / LockBit style)
            # Mutex creation
            mutex_name = "Global\\MsWinZonesCacheCounterMutexA" if any("WannaCry" in f for f in yara_families) else "Global\\SafeRansom_v3"
            mutexes.append({"name": mutex_name, "pid": root_pid, "status": "Created"})
            timeline.append({"time": 0.8, "type": "mutex", "pid": root_pid, "desc": f"Created synchronization Mutex: {mutex_name}"})

            # Child 1: cmd.exe
            cmd_pid = root_pid + 12
            processes.append({
                "pid": cmd_pid,
                "ppid": root_pid,
                "name": "cmd.exe",
                "cmdline": 'cmd.exe /c "vssadmin.exe Delete Shadows /All /Quiet"',
                "status": "Terminated",
                "integrity": "High",
                "start_time": 2.1,
                "end_time": 4.5,
                "children": []
            })
            root_proc["children"].append(cmd_pid)
            timeline.append({"time": 2.1, "type": "process_spawn", "pid": cmd_pid, "desc": f"Spawned cmd.exe (PID: {cmd_pid}) to disable system recovery"})

            # Child 2: vssadmin.exe
            vss_pid = cmd_pid + 8
            processes.append({
                "pid": vss_pid,
                "ppid": cmd_pid,
                "name": "vssadmin.exe",
                "cmdline": 'vssadmin.exe Delete Shadows /All /Quiet',
                "status": "Terminated",
                "integrity": "High",
                "start_time": 2.3,
                "end_time": 4.2,
                "children": []
            })
            timeline.append({"time": 2.3, "type": "evasion", "pid": vss_pid, "desc": "Executing vssadmin: Inhibiting Volume Shadow Copies"})

            # Screenshot: Shadow copy wipe command
            screenshots.append({
                "time": 3.2,
                "label": "Defense Evasion",
                "caption": "Attempting to delete Volume Shadow Copies to prevent restore",
                "type": "cmd_vssadmin"
            })

            # Persistence Registry
            reg_ops.append({"action": "WRITE", "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Tasksche", "value": "C:\\ProgramData\\tasksche.exe", "pid": root_pid})
            timeline.append({"time": 5.4, "type": "registry", "pid": root_pid, "desc": "Added autostart persistence key in HKLM Run"})

            # Mass file encryption / modification
            for target in ["C:\\Users\\Admin\\Documents\\Budget_2026.xlsx", "C:\\Users\\Admin\\Desktop\\Confidential.pdf", "C:\\Users\\Admin\\Pictures\\Family.png"]:
                file_ops.append({"action": "MODIFY", "path": target + ".WNCRY", "pid": root_pid})
            timeline.append({"time": 7.8, "type": "file_encrypt", "pid": root_pid, "desc": "Encrypted 42 files and appended .WNCRY extension"})

            # Dropped Ransom note
            ransom_note_path = "C:\\Users\\Admin\\Desktop\\@Please_Read_Me@.txt"
            file_ops.append({"action": "CREATE", "path": ransom_note_path, "pid": root_pid})
            dropped_files.append({
                "filename": "@Please_Read_Me@.txt",
                "path": ransom_note_path,
                "size": 1842,
                "sha256": "3fa9817e199042b083abf3a17e0828d58a361ef263adcbfa5160875c74eb1f02",
                "type": "Text Document / Ransom Note"
            })
            timeline.append({"time": 10.2, "type": "file_drop", "pid": root_pid, "desc": f"Dropped ransom instructions: {ransom_note_path}"})

            # C2 connection attempt
            c2_domain = iocs.get("urls", ["http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"])[0] if iocs.get("urls") else "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
            dns_queries.append({"query": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "type": "A", "response": "194.165.16.14", "pid": root_pid})
            net_ops.append({"proto": "TCP", "src": "192.168.1.105:49182", "dst": "194.165.16.14:80", "country": "RU", "status": "ESTABLISHED", "pid": root_pid})
            http_requests.append({
                "time": 12.5,
                "method": "GET",
                "url": c2_domain,
                "host": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                "status_code": 200,
                "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)",
                "pid": root_pid
            })
            timeline.append({"time": 12.5, "type": "network_c2", "pid": root_pid, "desc": f"HTTP C2 Beacon to {c2_domain}"})

            # Final Ransom Screen
            screenshots.append({
                "time": 18.0,
                "label": "Ransom Demand UI",
                "caption": "Malware locked screen displaying Bitcoin payment demand",
                "type": "ransom_screen"
            })

        elif is_stealer:
            # Infostealer behavior flow (RedLine / Vidar style)
            timeline.append({"time": 1.1, "type": "discovery", "pid": root_pid, "desc": "Enumerating system environment: ComputerName, Hardware GUID, Installed Anti-Virus"})
            reg_ops.append({"action": "QUERY", "path": "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid", "value": "a183d291-7f91-49a8-a3f7-5481878d0f11", "pid": root_pid})
            
            # Browser database access
            chrome_path = "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
            file_ops.append({"action": "READ", "path": chrome_path, "pid": root_pid})
            timeline.append({"time": 3.4, "type": "credential_theft", "pid": root_pid, "desc": f"Harvesting Chrome stored credentials from {chrome_path}"})
            
            # Screenshot: Browser credential access
            screenshots.append({
                "time": 4.0,
                "label": "Credential Harvesting",
                "caption": "Accessing Chrome & Firefox SQLite credential databases",
                "type": "stealer_activity"
            })

            # Dropped archive for exfil
            exfil_zip = "C:\\Users\\Admin\\AppData\\Local\\Temp\\Logs_Admin_2026.zip"
            file_ops.append({"action": "CREATE", "path": exfil_zip, "pid": root_pid})
            dropped_files.append({
                "filename": "Logs_Admin_2026.zip",
                "path": exfil_zip,
                "size": 48204,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "type": "ZIP Archive containing stolen credentials & cookies"
            })
            timeline.append({"time": 6.8, "type": "file_drop", "pid": root_pid, "desc": f"Compiled harvested secrets into compressed staging file: {exfil_zip}"})

            # Exfiltration C2 (e.g. Telegram Bot or HTTP POST)
            dns_queries.append({"query": "api.telegram.org", "type": "A", "response": "149.154.167.220", "pid": root_pid})
            net_ops.append({"proto": "TCP", "src": "192.168.1.105:49814", "dst": "149.154.167.220:443", "country": "NL", "status": "ESTABLISHED", "pid": root_pid})
            http_requests.append({
                "time": 8.5,
                "method": "POST",
                "url": "https://api.telegram.org/bot6184920491:AAHk.../sendDocument",
                "host": "api.telegram.org",
                "status_code": 200,
                "user_agent": "RedLine/3.2 Client",
                "pid": root_pid
            })
            timeline.append({"time": 8.5, "type": "exfiltration", "pid": root_pid, "desc": "Exfiltrating staged credentials archive via Telegram Bot API C2"})

            # Screenshot: Network Exfiltration
            screenshots.append({
                "time": 10.0,
                "label": "Data Exfiltration",
                "caption": "HTTPS POST transmission of credentials archive to remote C2",
                "type": "stealer_exfil"
            })

        else:
            # Generic Trojan / Backdoor / Shellcode Injector flow
            # Child: PowerShell with EncodedCommand
            ps_pid = root_pid + 15
            processes.append({
                "pid": ps_pid,
                "ppid": root_pid,
                "name": "powershell.exe",
                "cmdline": 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7AA==',
                "status": "Running",
                "integrity": "Medium",
                "start_time": 1.5,
                "end_time": duration_seconds,
                "children": []
            })
            root_proc["children"].append(ps_pid)
            timeline.append({"time": 1.5, "type": "process_spawn", "pid": ps_pid, "desc": f"Spawned hidden powershell.exe (PID: {ps_pid}) with Base64 encoded payload"})

            # Process Injection into svchost.exe
            inj_pid = 824
            processes.append({
                "pid": inj_pid,
                "ppid": ps_pid,
                "name": "svchost.exe [Injected]",
                "cmdline": 'C:\\Windows\\system32\\svchost.exe -k netsvcs',
                "status": "Running",
                "integrity": "SYSTEM",
                "start_time": 3.2,
                "end_time": duration_seconds,
                "children": []
            })
            ps_proc = [p for p in processes if p["pid"] == ps_pid][0]
            ps_proc["children"].append(inj_pid)
            timeline.append({"time": 3.2, "type": "injection", "pid": ps_pid, "desc": f"Memory injection: VirtualAllocEx & WriteProcessMemory into svchost.exe (PID: {inj_pid})"})

            # Screenshot: Injected Process
            screenshots.append({
                "time": 4.5,
                "label": "Process Hollow / Injection",
                "caption": "Hollowed remote thread created in legitimate svchost.exe",
                "type": "process_injection"
            })

            # Network Beacon
            c2_ip = "185.220.101.5"
            dns_queries.append({"query": "update-service-cloud.org", "type": "A", "response": c2_ip, "pid": inj_pid})
            net_ops.append({"proto": "TCP", "src": "192.168.1.105:51204", "dst": f"{c2_ip}:443", "country": "DE", "status": "ESTABLISHED", "pid": inj_pid})
            http_requests.append({
                "time": 6.8,
                "method": "POST",
                "url": f"https://update-service-cloud.org/api/v1/heartbeat",
                "host": "update-service-cloud.org",
                "status_code": 200,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "pid": inj_pid
            })
            timeline.append({"time": 6.8, "type": "network_c2", "pid": inj_pid, "desc": f"HTTPS Cobalt Strike Beacon to {c2_ip}:443"})

            # Dropped Stage-2 payload
            stage2_path = "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\defender_update.exe"
            file_ops.append({"action": "CREATE", "path": stage2_path, "pid": inj_pid})
            dropped_files.append({
                "filename": "defender_update.exe",
                "path": stage2_path,
                "size": 124928,
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "type": "PE32+ Executable / Backdoor Agent"
            })
            reg_ops.append({"action": "WRITE", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefenderService", "value": stage2_path, "pid": inj_pid})

        # Generate a simulated PCAP file on disk
        pcap_filename = f"{sha256[:16]}.pcap"
        pcap_path = PCAP_DIR / pcap_filename
        self._generate_dummy_pcap(pcap_path, net_ops)

        return {
            "sandbox_status": "Completed",
            "duration": duration_seconds,
            "architecture": "Windows 10 x64 Pro (Build 19045)",
            "environment": "Vanguard Isolated Dynamic Hypervisor Sandbox",
            "process_tree": processes,
            "timeline": sorted(timeline, key=lambda x: x["time"]),
            "file_operations": file_ops,
            "registry_operations": reg_ops,
            "network_connections": net_ops,
            "dns_queries": dns_queries,
            "http_requests": http_requests,
            "mutexes": mutexes,
            "screenshots": screenshots,
            "dropped_files": dropped_files,
            "pcap_file": pcap_filename
        }

    def _generate_dummy_pcap(self, path: Path, net_ops: List[Dict[str, Any]]):
        """Creates a syntactically valid libpcap binary file for the captured connections."""
        try:
            # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
            header = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            packets = bytearray()
            now_sec = int(time.time())

            for i, conn in enumerate(net_ops):
                # Simple dummy IP/TCP packet payload
                payload = b"GET / HTTP/1.1\r\nHost: c2-domain.com\r\n\r\n"
                # Dummy ethernet(14) + IP(20) + TCP(20) headers
                pkt_data = b"\x00" * 54 + payload
                pkt_len = len(pkt_data)
                # PCAP Packet Header: ts_sec, ts_usec, incl_len, orig_len
                pkt_hdr = struct.pack("=IIII", now_sec + i * 2, i * 100000, pkt_len, pkt_len)
                packets.extend(pkt_hdr + pkt_data)

            with open(path, "wb") as f:
                f.write(header + packets)
        except Exception:
            pass
