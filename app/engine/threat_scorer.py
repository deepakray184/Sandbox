"""
Threat Scoring and Risk Verdict Computation Engine.
Calculates a normalized 0-100 severity score with full transparent breakdown of risk factors.
"""
from typing import Dict, Any, List, Tuple

class ThreatScorer:
    def __init__(self):
        pass

    def compute_score(
        self,
        static_report: Dict[str, Any],
        dynamic_report: Dict[str, Any],
        vt_report: Dict[str, Any]
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        breakdown = []
        raw_score = 0

        # 1. YARA Rule Matches
        yara_matches = static_report.get("yara_matches", [])
        for y in yara_matches:
            sev = y.get("severity", "MEDIUM")
            pts = 40 if sev == "CRITICAL" else (25 if sev == "HIGH" else 10)
            breakdown.append({
                "factor": f"YARA Match: {y.get('rule')}",
                "severity": sev,
                "points": pts,
                "description": y.get("meta", {}).get("description", "Signature matched malicious pattern")
            })
            raw_score += pts

        # 2. Multi-Engine Antivirus Ratio
        detected_count = vt_report.get("detected_count", 0)
        total_engines = vt_report.get("total_engines", 70)
        if detected_count > 0:
            av_points = min(40, int((detected_count / total_engines) * 50))
            breakdown.append({
                "factor": f"Multi-Engine AV Detection ({detected_count}/{total_engines})",
                "severity": "CRITICAL" if detected_count >= 20 else ("HIGH" if detected_count >= 5 else "MEDIUM"),
                "points": av_points,
                "description": f"{detected_count} security vendors flagged sample as malicious"
            })
            raw_score += av_points

        # 3. High Entropy / Packing
        entropy = static_report.get("entropy", 0.0)
        if entropy > 7.2:
            breakdown.append({
                "factor": f"High Entropy ({entropy:.2f}/8.0)",
                "severity": "MEDIUM",
                "points": 15,
                "description": "File exhibits high entropy indicating packing or encrypted payload"
            })
            raw_score += 15

        # 4. PE Suspicious Sections
        pe_info = static_report.get("pe_analysis") or {}
        susp_sections = pe_info.get("suspicious_sections", [])
        if susp_sections:
            breakdown.append({
                "factor": f"Suspicious PE Sections ({len(susp_sections)})",
                "severity": "HIGH",
                "points": 15,
                "description": f"Sections flagged: {', '.join([s['name'] for s in susp_sections])}"
            })
            raw_score += 15

        # 5. Dynamic Process Injection
        timeline = dynamic_report.get("timeline", [])
        inj_events = [e for e in timeline if e.get("type") == "injection"]
        if inj_events:
            breakdown.append({
                "factor": "Process Memory Injection (Hollowing/APC)",
                "severity": "CRITICAL",
                "points": 30,
                "description": "Dynamic execution attempted to inject code into remote process memory"
            })
            raw_score += 30

        # 6. Recovery Inhibition
        evasion_events = [e for e in timeline if e.get("type") == "evasion" or "vssadmin" in e.get("desc", "").lower()]
        if evasion_events:
            breakdown.append({
                "factor": "Inhibit System Recovery (Shadow Copy Wipe)",
                "severity": "CRITICAL",
                "points": 35,
                "description": "Attempted to delete volume shadow copies to prevent file recovery"
            })
            raw_score += 35

        # 7. Persistence Mechanism
        reg_ops = dynamic_report.get("registry_operations", [])
        run_keys = [r for r in reg_ops if "run" in r.get("path", "").lower()]
        if run_keys:
            breakdown.append({
                "factor": "Autostart Run Key Persistence",
                "severity": "HIGH",
                "points": 20,
                "description": f"Created autostart persistence key in Windows registry: {run_keys[0].get('path')}"
            })
            raw_score += 20

        # 8. C2 Network Activity
        c2_reqs = dynamic_report.get("http_requests", [])
        if c2_reqs:
            breakdown.append({
                "factor": "Outbound Command & Control (C2) Activity",
                "severity": "HIGH",
                "points": 25,
                "description": f"Initiated {len(c2_reqs)} beacon HTTP sessions to external servers"
            })
            raw_score += 25

        # Normalize score between 0 and 100
        final_score = min(100, max(0, raw_score))

        # Verdict
        if final_score >= 80:
            verdict = "Malicious"
        elif final_score >= 50:
            verdict = "Suspicious"
        elif final_score >= 20:
            verdict = "Low Risk"
        else:
            verdict = "Clean"

        return final_score, verdict, breakdown
