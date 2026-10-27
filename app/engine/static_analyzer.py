"""
Static File Analysis Engine.
Provides comprehensive binary, PE, document, script, entropy, and IOC analysis.
"""
import hashlib
import math
import re
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
import pefile

from app.engine.ssdeep_compat import compute_ssdeep
from app.engine.yara_engine import YaraEngine

yara_scanner = YaraEngine()

IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
REGISTRY_REGEX = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[a-zA-Z0-9_\\]+', re.IGNORECASE)
FILEPATH_REGEX = re.compile(r'(?:[a-zA-Z]:\\(?:[a-zA-Z0-9_.\- ]+\\)+[a-zA-Z0-9_.\- ]+|/(?:usr|etc|var|tmp|home)/[a-zA-Z0-9_.\-/]+)')
BASE64_REGEX = re.compile(r'\b[A-Za-z0-9+/]{28,}={0,2}\b')
BTC_REGEX = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b')
ETH_REGEX = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

SUSPICIOUS_APIS = {
    "Process Injection": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext", "NtQueueApcThread"],
    "Persistence": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "CreateServiceA", "CreateServiceW", "SetWindowsHookExA"],
    "Defense Evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "FindWindowA", "Sleep", "GetTickCount", "ZwSetInformationThread"],
    "Cryptography / Ransomware": ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt"],
    "Network / C2": ["WSAStartup", "connect", "InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "URLDownloadToFileA", "InternetReadFile"],
    "Command Execution": ["WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "system"]
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    for count in occurrences:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_entropy_distribution(data: bytes, blocks: int = 32) -> List[float]:
    if not data:
        return [0.0] * blocks
    block_size = max(1, len(data) // blocks)
    distribution = []
    for i in range(blocks):
        chunk = data[i * block_size: (i + 1) * block_size]
        if not chunk:
            distribution.append(0.0)
        else:
            distribution.append(calculate_entropy(chunk))
    return distribution


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = 500) -> Dict[str, Any]:
    # Extract ASCII strings
    ascii_re = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    ascii_matches = [m.group(0).decode('ascii', errors='ignore') for m in ascii_re.finditer(data)]
    
    # Extract Unicode / UTF-16LE strings
    unicode_re = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')
    unicode_matches = [m.group(0).decode('utf-16le', errors='ignore') for m in unicode_re.finditer(data)]

    all_strings = list(dict.fromkeys(ascii_matches + unicode_matches))
    full_text = " \n".join(all_strings)

    # Categorize IOCs
    iocs = {
        "urls": list(dict.fromkeys(URL_REGEX.findall(full_text)))[:100],
        "ips": [ip for ip in dict.fromkeys(IPV4_REGEX.findall(full_text)) if not ip.startswith(("127.", "0.", "255."))][:100],
        "emails": list(dict.fromkeys(EMAIL_REGEX.findall(full_text)))[:100],
        "registry_keys": list(dict.fromkeys(REGISTRY_REGEX.findall(full_text)))[:100],
        "file_paths": list(dict.fromkeys(FILEPATH_REGEX.findall(full_text)))[:100],
        "crypto_wallets": list(dict.fromkeys(BTC_REGEX.findall(full_text) + ETH_REGEX.findall(full_text)))[:50],
        "base64_candidates": list(dict.fromkeys(BASE64_REGEX.findall(full_text)))[:30]
    }

    return {
        "total_extracted": len(all_strings),
        "sample": all_strings[:max_strings],
        "iocs": iocs
    }


def analyze_pe(file_path: str, data: bytes) -> Dict[str, Any]:
    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        return {"is_pe": False, "error": str(e)}

    # Machine architecture
    machine_arch = "x86 (32-bit)"
    if pe.FILE_HEADER.Machine == 0x8664:
        machine_arch = "x64 (64-bit)"
    elif pe.FILE_HEADER.Machine == 0xaa64:
        machine_arch = "ARM64"

    # Compile timestamp
    try:
        compile_time = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() + "Z"
    except Exception:
        compile_time = f"0x{pe.FILE_HEADER.TimeDateStamp:08X}"

    # Sections
    sections = []
    suspicious_sections = []
    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
        entropy = calculate_entropy(s.get_data())
        is_exec = bool(s.Characteristics & 0x20000000)
        is_write = bool(s.Characteristics & 0x80000000)
        is_read = bool(s.Characteristics & 0x40000000)

        is_suspicious = False
        reasons = []
        if entropy > 7.1:
            is_suspicious = True
            reasons.append(f"High entropy ({entropy:.2f}) indicates packed/encrypted content")
        if is_write and is_exec:
            is_suspicious = True
            reasons.append("Writable and Executable (W+X) section")
        if name in ["UPX0", "UPX1", "UPX2", ".aspack", ".fsg", ".themida"]:
            is_suspicious = True
            reasons.append(f"Known packer section name: {name}")

        sec_info = {
            "name": name,
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": entropy,
            "permissions": f"{'R' if is_read else '-'}{'W' if is_write else '-'}{'X' if is_exec else '-'}",
            "is_suspicious": is_suspicious,
            "reasons": reasons
        }
        sections.append(sec_info)
        if is_suspicious:
            suspicious_sections.append(sec_info)

    # Imports & API categorization
    imports_by_dll = {}
    matched_suspicious_apis = {}
    imphash = ""
    try:
        imphash = pe.get_imphash()
    except Exception:
        pass

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            imports_by_dll[dll_name] = []
            for imp in entry.imports:
                api_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal({imp.ordinal})"
                imports_by_dll[dll_name].append(api_name)
                # Check for suspicious API
                for category, api_list in SUSPICIOUS_APIS.items():
                    for target_api in api_list:
                        if target_api.lower() == api_name.lower():
                            if category not in matched_suspicious_apis:
                                matched_suspicious_apis[category] = []
                            matched_suspicious_apis[category].append(api_name)

    # Exports
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal({exp.ordinal})"
            exports.append(exp_name)

    # Digital Signature Check
    has_signature = False
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        has_signature = (sec_dir.VirtualAddress != 0 and sec_dir.Size > 0)
    except Exception:
        pass

    return {
        "is_pe": True,
        "machine": machine_arch,
        "compile_time": compile_time,
        "imphash": imphash,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "has_digital_signature": has_signature,
        "sections": sections,
        "suspicious_sections": suspicious_sections,
        "imports": imports_by_dll,
        "suspicious_apis": matched_suspicious_apis,
        "exports": exports[:50]
    }


def analyze_file(data: bytes, original_filename: str) -> Dict[str, Any]:
    file_size = len(data)
    
    # Hashes
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    ssdeep_hash = compute_ssdeep(data)

    # File magic & MIME detection
    file_type = "Generic Binary / Unknown"
    magic_hex = data[:8].hex().upper()
    if data.startswith(b'MZ'):
        file_type = "Windows Executable / DLL (PE)"
    elif data.startswith(b'\x7fELF'):
        file_type = "Linux Executable (ELF)"
    elif data.startswith(b'\xfe\xed\xfa\xce') or data.startswith(b'\xcf\xfa\xed\xfe') or data.startswith(b'\xca\xfe\xba\xbe'):
        file_type = "macOS Mach-O Binary"
    elif data.startswith(b'%PDF'):
        file_type = "PDF Document"
    elif data.startswith(b'PK\x03\x04'):
        file_type = "ZIP / Office OpenXML Archive"
    elif data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        file_type = "Microsoft Office OLE Document"
    elif data.startswith(b'X5O!P%@AP[4'):
        file_type = "EICAR Standard AV Test File"
    elif b'#!/bin/' in data[:64] or b'powershell' in data[:200].lower() or b'<html' in data[:200].lower():
        file_type = "Script / Markup"

    # Entropy
    entropy = calculate_entropy(data)
    entropy_dist = calculate_entropy_distribution(data)

    # Strings & IOCs
    strings_res = extract_strings(data)

    # PE details
    pe_details = None
    if data.startswith(b'MZ'):
        pe_details = analyze_pe("", data)

    # YARA scanning
    yara_matches = yara_scanner.scan(data)

    # Specific format heuristics
    doc_heuristics = []
    if file_type == "PDF Document":
        if b'/JavaScript' in data or b'/JS' in data:
            doc_heuristics.append("Embedded JavaScript (/JavaScript) found in PDF")
        if b'/OpenAction' in data or b'/Launch' in data:
            doc_heuristics.append("Automatic Launch Action (/OpenAction, /Launch) found in PDF")
        if b'/EmbeddedFiles' in data:
            doc_heuristics.append("Embedded hidden payload files (/EmbeddedFiles) in PDF")

    elif file_type == "Microsoft Office OLE Document" or file_type == "ZIP / Office OpenXML Archive":
        if b'vbaProject.bin' in data or b'AutoOpen' in data or b'Workbook_Open' in data:
            doc_heuristics.append("Embedded VBA Macros / AutoOpen execution found in Document")
        if b'WScript.Shell' in data or b'powershell' in data.lower():
            doc_heuristics.append("Office document invokes external script/shell process")

    return {
        "filename": original_filename,
        "file_size": file_size,
        "magic_hex": magic_hex,
        "file_type": file_type,
        "entropy": entropy,
        "entropy_distribution": entropy_dist,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512,
            "ssdeep": ssdeep_hash,
            "imphash": pe_details.get("imphash", "") if pe_details else ""
        },
        "pe_analysis": pe_details,
        "strings": strings_res,
        "yara_matches": yara_matches,
        "doc_heuristics": doc_heuristics
    }
