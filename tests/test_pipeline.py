"""
Automated Pipeline Verification Test.
Verifies all static, dynamic, AV, email, MITRE ATT&CK, scoring, and export modules.
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.database import init_db, list_submissions, get_stats
from app.engine.static_analyzer import analyze_file
from app.engine.sandbox_engine import DynamicSandbox
from app.engine.virustotal_engine import VirusTotalEngine
from app.engine.email_analyzer import EmailAnalyzer
from app.engine.mitre_mapper import MitreMapper
from app.engine.threat_scorer import ThreatScorer
from app.engine.ioc_exporter import IocExporter
from app.samples.loader import SAMPLES_CATALOG, get_sample_by_id

def test_full_pipeline():
    print("[*] Initializing Database...")
    init_db()

    # 1. Test WannaCry Sample
    print("\n[+] Testing File Pipeline on WannaCry Sample...")
    wc_sample = get_sample_by_id("sample-wannacry")
    assert wc_sample is not None, "WannaCry sample missing"

    # Static
    static_rep = analyze_file(wc_sample["data"], wc_sample["filename"])
    print(f"    - Hashes: SHA256={static_rep['hashes']['sha256'][:16]}..., SSDEEP={static_rep['hashes']['ssdeep'][:20]}...")
    print(f"    - Entropy: {static_rep['entropy']}/8.0")
    print(f"    - YARA Hits: {[m['rule'] for m in static_rep['yara_matches']]}")
    assert len(static_rep["yara_matches"]) > 0, "Expected YARA rule hit for WannaCry"

    # Dynamic Sandbox
    sandbox = DynamicSandbox()
    dyn_rep = sandbox.run_sandbox(static_rep, duration_seconds=30)
    print(f"    - Process Tree Nodes: {len(dyn_rep['process_tree'])}")
    print(f"    - Timeline Events: {len(dyn_rep['timeline'])}")
    print(f"    - Screenshots Captured: {len(dyn_rep['screenshots'])}")
    print(f"    - Network Operations: {len(dyn_rep['network_connections'])}")
    print(f"    - PCAP File Generated: {dyn_rep['pcap_file']}")
    assert len(dyn_rep["process_tree"]) >= 2, "Expected child processes spawned in dynamic trace"

    # VirusTotal Multi-Engine
    vt = VirusTotalEngine()
    vt_rep = vt.scan_multi_engine(static_rep)
    print(f"    - AV Detection Ratio: {vt_rep['detection_ratio']} ({vt_rep['detection_rate_pct']}%)")
    assert vt_rep["detected_count"] >= 30, "Expected high AV detection for WannaCry"

    # MITRE ATT&CK
    mitre = MitreMapper()
    mitre_rep = mitre.map_analysis(static_rep, dyn_rep)
    print(f"    - MITRE Techniques Mapped: {len(mitre_rep)} techniques")
    for t in mitre_rep:
        print(f"      * {t['technique_id']}: {t['technique_name']} ({t['tactic']})")
    assert len(mitre_rep) >= 2, "Expected MITRE ATT&CK techniques"

    # Threat Scorer
    scorer = ThreatScorer()
    score, verdict, breakdown = scorer.compute_score(static_rep, dyn_rep, vt_rep)
    print(f"    - Final Threat Score: {score}/100 | Verdict: {verdict}")
    print(f"    - Score Factors: {len(breakdown)} factors contributing")
    assert score >= 80, "Expected Malicious score for WannaCry"
    assert verdict == "Malicious", f"Expected Malicious verdict, got {verdict}"

    # IOC Exporter
    full_report = {
        "filename": wc_sample["filename"],
        "hashes": static_rep["hashes"],
        "verdict": verdict,
        "threat_score": score,
        "sandbox": dyn_rep,
        "strings": static_rep["strings"]
    }
    exporter = IocExporter()
    stix = exporter.export_stix21(full_report)
    misp = exporter.export_misp(full_report)
    suricata = exporter.export_suricata(full_report)
    yara = exporter.export_yara(full_report)
    csv = exporter.export_csv(full_report)

    print(f"    - STIX 2.1 Bundle: {len(stix['objects'])} objects generated")
    print(f"    - MISP Attributes: {len(misp['Event']['Attribute'])} attributes generated")
    print(f"    - Suricata Rules Generated: {len(suricata.splitlines())} lines")
    print(f"    - YARA Rule Generated: {len(yara.splitlines())} lines")
    print(f"    - CSV Rows: {len(csv.splitlines())} rows")

    # 2. Test Email Pipeline
    print("\n[+] Testing Email Pipeline on Phishing Sample...")
    phish_sample = get_sample_by_id("sample-phishing")
    assert phish_sample is not None, "Phishing sample missing"

    email_eng = EmailAnalyzer()
    email_rep = email_eng.parse_email(phish_sample["data"], filename=phish_sample["filename"])
    print(f"    - Subject: {email_rep['headers']['subject']}")
    print(f"    - From: {email_rep['headers']['from']}")
    print(f"    - SPF Status: {email_rep['authentication']['spf']['status']}")
    print(f"    - DKIM Status: {email_rep['authentication']['dkim']['status']}")
    print(f"    - DMARC Status: {email_rep['authentication']['dmarc']['status']}")
    print(f"    - Total Hops: {len(email_rep['hops'])} | Relay Delay: {email_rep['relay_latency']['total_delay_formatted']}")
    print(f"    - Extracted URLs: {len(email_rep['urls'])}")
    print(f"    - Extracted Attachments: {len(email_rep['attachments'])}")
    print(f"    - Phishing Heuristics Triggered: {len(email_rep['heuristics'])}")
    print(f"    - Email Threat Score: {email_rep['threat_score']}/100 | Verdict: {email_rep['verdict']}")

    assert email_rep["authentication"]["spf"]["status"] == "FAIL", "Expected SPF FAIL"
    assert email_rep["authentication"]["dmarc"]["status"] == "FAIL", "Expected DMARC FAIL"
    assert len(email_rep["attachments"]) >= 1, "Expected extracted attachment"
    assert email_rep["threat_score"] >= 70, "Expected high phishing score"

    # 3. Test Clean Utility Sample
    print("\n[+] Testing Clean Utility Sample...")
    clean_sample = get_sample_by_id("sample-clean")
    c_static = analyze_file(clean_sample["data"], clean_sample["filename"])
    c_dyn = sandbox.run_sandbox(c_static, duration_seconds=10)
    c_vt = vt.scan_multi_engine(c_static)
    c_score, c_verdict, _ = scorer.compute_score(c_static, c_dyn, c_vt)
    print(f"    - Clean Sample Score: {c_score}/100 | Verdict: {c_verdict} | AV: {c_vt['detection_ratio']}")
    assert c_verdict == "Clean", f"Expected Clean verdict for benign binary, got {c_verdict}"

    print("\n[✓] ALL TESTS PASSED! Full SOC analysis pipeline verified successfully.")

if __name__ == "__main__":
    test_full_pipeline()
