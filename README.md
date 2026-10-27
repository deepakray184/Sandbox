# Vanguard MSA - SOC Malware Sandbox & Email Analysis Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?style=for-the-badge&logo=github)](https://deepakray184.github.io/Sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20FastAPI%20%7C%20Client--Side-orange?style=for-the-badge)](#)

> 🚀 **Live Demo on GitHub Pages**: **[https://deepakray184.github.io/Sandbox/](https://deepakray184.github.io/Sandbox/)**  
> Run full malware sandbox traces, multi-engine AV evaluations, and email phishing analyses directly in your browser with **zero installation or backend server required**!

---

**Vanguard MSA** is an enterprise-grade, web-based Malware Analysis and Threat Intelligence platform designed specifically for **Security Operations Center (SOC)** teams, Incident Responders, and Malware Analysts.

It combines the interactive dynamic execution visualization of **ANY.RUN**, the multi-engine antivirus detection grid of **VirusTotal**, and a dedicated **Email Header & Phishing Investigation Workbench** into a unified, high-performance console.

---

## 🌟 Key Capabilities

### 1. Interactive Dynamic Sandbox (ANY.RUN-style)
* **Interactive Process Tree**: Hierarchical parent/child process graph tracking PIDs, PPIDs, command lines, exit codes, and integrity levels.
* **Execution Timeline & Scrubber**: Step-by-step playback (0s to 60s) of chronological events (process spawns, file drops, registry writes, C2 beacons).
* **Desktop Session Captures**: Visual screenshot gallery at critical phases (initial launch, recovery inhibition, credential theft, ransomware locking screens).
* **System Call Tracing**:
  * **Filesystem**: Real-time tracking of created, modified, encrypted, and deleted files.
  * **Registry**: Detection of autostart persistence (`HKCU\...\Run`), security feature tampering, and environment queries.
  * **Synchronization**: Detection of mutex creation used to prevent multi-infection.
  * **Memory Injection**: Flags `VirtualAllocEx`, `WriteProcessMemory`, and remote thread creation.
* **Network & PCAP**:
  * DNS query resolution table.
  * HTTP / HTTPS C2 beacon log (Method, URL, User-Agent, status codes).
  * Direct download of generated `.pcap` packet capture files for Wireshark inspection.
* **Dropped Artifacts Extraction**: Automatically isolates dropped files with SHA256 hashes and download staging.

### 2. Deep Static & Multi-Engine AV Inspection (VirusTotal-style)
* **Cryptographic & Fuzzy Hashes**: MD5, SHA-1, SHA-256, SHA-512, **SSDEEP** (CTPH fuzzy hash for variant matching), and **IMPHASH** (Import Hash).
* **Entropy Analysis**: Shannon entropy calculation (0.0 to 8.0) and 32-block entropy distribution chart to identify packed or encrypted payloads.
* **PE Header & Section Analysis**: Machine architecture, compilation timestamps, entry points, and section permissions (flagging W+X permissions and packed sections like UPX).
* **Suspicious API Categorization**: Grouped by attacker intent (Process Injection, Persistence, Defense Evasion, Ransomware Cryptography, Network C2).
* **Pure-Python YARA Rule Engine**: High-performance signature matching for Ransomware (WannaCry, LockBit), Infostealers (RedLine, Vidar), Backdoors (Cobalt Strike), and WebShells without fragile C-compiler dependencies.
* **Multi-Engine Antivirus Grid**: Evaluates samples against 65+ commercial and open-source AV vendors (CrowdStrike, Defender, Kaspersky, Bitdefender, SentinelOne, Sophos, ESET, etc.) with detection ratios and community reputation scores.

### 3. Dedicated Email Header & Phishing Analysis Workbench
* **MIME & RFC 822 Parser**: Full support for `.eml`, `.msg`, and raw pasted email headers.
* **Authentication Scorecard**:
  * **SPF**: Evaluates sender IP authorization against envelope domains.
  * **DKIM**: Inspects cryptographic signatures, selectors, and signing domains.
  * **DMARC**: Checks domain alignment and enforcement policies (`none`, `quarantine`, `reject`).
* **Hop-by-Hop Relay Latency Timeline**: Chronologically visualizes MTA delivery hops with calculated transit delay between servers to spot anomalous mail delays or rogue relays.
* **Phishing & Fraud Heuristics**:
  * **Display Name Spoofing**: Detects when display names contain external email addresses or trusted brands.
  * **Return-Path vs From Mismatch**: Alerts on envelope sender divergence.
  * **Deceptive Anchor Links**: Flags links where visible text claims one domain but points to an attacker destination.
* **Attachment Sandbox Integration**: One-click extraction of email attachments with direct routing into the malware sandbox!
* **Safe HTML Preview**: Script-blocked, beacon-stripped preview of email body.

### 4. Domain, IP, File Hash & CVE Vulnerability Intelligence
* **CVE Deep-Dive & Exploitability**:
  * CVSS v3.1 base score, severity rating, and vector string breakdown.
  * EPSS (Exploit Prediction Scoring System) exploitation probability and global percentile.
  * **CISA Known Exploited Vulnerabilities (KEV)** catalog tracking (due dates, active federal mandates).
  * Weaponized public PoC availability and framework tracking (Metasploit, Nuclei, GitHub PoCs).
  * Automated Snort & Suricata network IDS detection signatures.
* **IP Address Threat Profiling**:
  * Geolocation, country flag, ASN / ISP reputation, and autonomous system name.
  * Tor exit node identification, public proxy / VPN flags, and open attack surface ports.
  * Abuse Confidence Score and historical malicious activity verdicts.
* **Domain & DGA Intelligence**:
  * Algorithmic Shannon entropy and Domain Generation Algorithm (DGA) risk assessment.
  * WHOIS registration timeline, age verification, and registrar data.
  * Real-time DNS record resolution (A, MX, TXT, NS).
* **Cryptographic Hash Attribution**:
  * Instant MD5, SHA-1, and SHA-256 cross-referencing with threat family naming and AV consensus.
* **Universal IOC Extractor & Bulk Defanger**:
  * Pastes unformatted text, incident reports, or raw threat feeds.
  * Automatically parses and categorizes all CVEs, IPs, domains, URLs, and hashes.
  * Generates sanitized defanged text (`hxxps[://]`, `evil[.]com`, `192[.]168[.]1[.]1`) to prevent accidental clicks in ticketing systems.

### 5. MITRE ATT&CK Matrix Mapping
* Maps all observed static patterns and dynamic execution behaviors directly to the **MITRE ATT&CK Enterprise Matrix** (Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Command & Control, Impact) with concrete evidence logs.

### 6. Transparent Threat Scoring & SOC IOC Export
* **Explainable 0-100 Threat Score**: Clear breakdown itemizing every contributing factor and point weight.
* **Automated IOC Export Formats**:
  * **STIX 2.1 JSON Bundle** (OASIS standard)
  * **MISP Event JSON**
  * **Suricata / Snort Network IDS Rules**
  * **Auto-generated YARA Signatures**
  * **CSV Threat Intelligence list** (Defanged)

---

## 🚀 Quick Start Guide

### 1. Launch Platform
Simply run the included startup script:
```bash
./run.sh
```
Or run directly with the virtual environment:
```bash
./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Access Web Console
Open your browser to:
* **Web UI**: [http://localhost:8000](http://localhost:8000)
* **Interactive API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🧪 Pre-Loaded Threat Samples / SOC Playground

The platform includes built-in realistic threat simulations so your team can test the platform immediately without handling live malware:
1. **WannaCry Ransomware Simulator**: Volume shadow copy wiping (`vssadmin delete shadows`), `.WNCRY` encryption, killswitch domain beacon, and ransom screen.
2. **RedLine Infostealer Simulator**: Browser SQLite credential harvesting, staging archive, and Telegram Bot C2 exfiltration.
3. **Malicious Macro Document**: Office OpenXML document with AutoOpen VBA macro launching an obfuscated PowerShell download cradle.
4. **EICAR Standard AV Test**: Standard antivirus test file for validating multi-engine detection grids.
5. **CEO / Banking Spearphishing Email**: Spearphish email with SPF/DKIM/DMARC failure, display name spoofing, deceptive anchor link mismatch, and embedded executable attachment.
6. **Clean SOC Diagnostic Utility**: Benign executable demonstrating 0/65 detections and clean sandbox execution.

---

## 🔌 SOAR & SIEM Automation API

The REST API allows easy integration with automation platforms such as **Cortex XSOAR**, **Splunk SOAR**, **Shuffle**, **TheHive**, or custom Python scripts:

### Submit File for Analysis
```bash
curl -X POST "http://localhost:8000/api/analyze/file" \
     -F "file=@/path/to/suspicious.exe" \
     -F "duration=30"
```

### Submit Email for Phishing Inspection
```bash
curl -X POST "http://localhost:8000/api/analyze/email" \
     -F "file=@/path/to/phishing.eml"
```

### Export IOCs as STIX 2.1
```bash
curl -s "http://localhost:8000/api/export/<SUBMISSION_ID>/stix21" > stix_bundle.json
```

### Download Captured PCAP
```bash
curl -s "http://localhost:8000/api/download/pcap/<SUBMISSION_ID>" -o network_capture.pcap
```

---

## 📂 Project Directory Structure

```
MSA/
├── app/
│   ├── main.py                     # FastAPI application routes & endpoints
│   ├── core/
│   │   ├── config.py               # Platform settings & directory layout
│   │   └── database.py             # SQLite submission store, stats, and notes
│   ├── engine/
│   │   ├── static_analyzer.py      # PE, PDF, Office, Archive, Strings, Entropy
│   │   ├── ssdeep_compat.py        # Pure-Python SSDEEP / CTPH fuzzy hashing
│   │   ├── yara_engine.py          # High-performance signature scanning
│   │   ├── sandbox_engine.py       # Dynamic execution, process trees, and PCAP
│   │   ├── virustotal_engine.py    # 65+ AV detection grid & threat intelligence
│   │   ├── email_analyzer.py       # SPF/DKIM/DMARC, hop relays, phishing heuristics
│   │   ├── ioc_intelligence.py     # CVE, IP, Domain, Hash & Bulk Defanger engine
│   │   ├── mitre_mapper.py         # MITRE ATT&CK Matrix mapping
│   │   ├── threat_scorer.py        # 0-100 severity score & transparent breakdown
│   │   └── ioc_exporter.py         # STIX 2.1, MISP, Suricata, YARA, CSV
│   ├── samples/
│   │   └── loader.py               # Pre-loaded malware & phishing samples
│   ├── static/
│   │   ├── css/custom.css          # Dark SOC styling, radar pulses, badges
│   │   └── js/app.js               # Reactive frontend, process trees, timeline
│   └── templates/
│       └── index.html              # Unified SOC Analyst Console
├── tests/
│   └── test_pipeline.py            # Automated pipeline test suite
├── run.sh                          # One-click startup script
└── README.md                       # Documentation & API reference
```
