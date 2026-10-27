"""
Vanguard MSA - Malware Sandbox & Email Analysis Platform.
Main FastAPI Web Application and SOC Analyst API Endpoints.
"""
import uuid
import os
import json
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.templating import Jinja2Templates
from starlette.requests import Request

from app.core.config import (
    APP_NAME, APP_VERSION, BASE_DIR, UPLOAD_DIR, PCAP_DIR, REPORTS_DIR
)
from app.core.database import (
    init_db, save_submission, get_submission, list_submissions,
    get_stats, add_analyst_note, get_analyst_notes
)
from app.engine.static_analyzer import analyze_file
from app.engine.sandbox_engine import DynamicSandbox
from app.engine.virustotal_engine import VirusTotalEngine
from app.engine.email_analyzer import EmailAnalyzer
from app.engine.mitre_mapper import MitreMapper
from app.engine.threat_scorer import ThreatScorer
from app.engine.ioc_exporter import IocExporter
from app.engine.ioc_intelligence import IocIntelligenceEngine
from app.samples.loader import SAMPLES_CATALOG, get_sample_by_id

# Initialize database
init_db()

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Interactive Malware Sandbox, Multi-Engine AV & Email Header Analysis Platform for SOC Teams"
)

# Enable CORS for SOC tools integration (SOAR, SIEM, Cortex XSOAR, Splunk)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
STATIC_DIR = BASE_DIR / "app" / "static"
TEMPLATES_DIR = BASE_DIR / "app" / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Core engine singletons
sandbox_engine = DynamicSandbox()
vt_engine = VirusTotalEngine()
email_analyzer = EmailAnalyzer()
mitre_mapper = MitreMapper()
threat_scorer = ThreatScorer()
ioc_exporter = IocExporter()
ioc_intel = IocIntelligenceEngine()


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Serves the primary SOC Analyst Web Console."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": APP_NAME,
            "app_version": APP_VERSION
        }
    )


@app.get("/api/stats")
async def api_stats():
    """Returns SOC dashboard operational statistics."""
    stats = get_stats()
    return {"status": "success", "stats": stats}


@app.get("/api/samples")
async def api_samples():
    """Returns catalog of pre-loaded malware and phishing test samples."""
    return {
        "status": "success",
        "samples": [
            {
                "id": s["id"],
                "name": s["name"],
                "filename": s["filename"],
                "type": s["type"],
                "verdict": s["verdict"],
                "description": s["description"]
            }
            for s in SAMPLES_CATALOG
        ]
    }


@app.get("/api/submissions")
async def api_list_submissions(limit: int = Query(50, ge=1, le=200)):
    """Lists recent submissions and scan history."""
    items = list_submissions(limit=limit)
    return {"status": "success", "submissions": items}


@app.get("/api/submission/{sub_id}")
async def api_get_submission(sub_id: str):
    """Retrieves full analysis report for a given submission ID."""
    sub = get_submission(sub_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    return {"status": "success", "submission": sub}


@app.post("/api/analyze/file")
async def api_analyze_file(
    file: UploadFile = File(...),
    duration: int = Form(30)
):
    """
    Full pipeline file analysis:
    Static analysis + ANY.RUN dynamic sandbox + VirusTotal multi-engine + MITRE ATT&CK + Scoring.
    """
    sub_id = str(uuid.uuid4())
    content = await file.read()
    filename = file.filename or "uploaded_sample.bin"
    file_size = len(content)

    # 1. Static Analysis
    static_rep = analyze_file(content, filename)

    # 2. Dynamic Sandbox Execution
    dyn_rep = sandbox_engine.run_sandbox(static_rep, duration_seconds=min(60, max(10, duration)))

    # 3. Multi-Engine AV Scan
    vt_rep = vt_engine.scan_multi_engine(static_rep)

    # 4. MITRE ATT&CK Mapping
    mitre_rep = mitre_mapper.map_analysis(static_rep, dyn_rep)

    # 5. Threat Scoring & Verdict
    score, verdict, breakdown = threat_scorer.compute_score(static_rep, dyn_rep, vt_rep)

    # Assemble unified report
    report = {
        "id": sub_id,
        "target_type": "file",
        "filename": filename,
        "file_size": file_size,
        "verdict": verdict,
        "threat_score": score,
        "score_breakdown": breakdown,
        "hashes": static_rep["hashes"],
        "entropy": static_rep["entropy"],
        "entropy_distribution": static_rep["entropy_distribution"],
        "file_type": static_rep["file_type"],
        "magic_hex": static_rep["magic_hex"],
        "pe_analysis": static_rep["pe_analysis"],
        "yara_matches": static_rep["yara_matches"],
        "doc_heuristics": static_rep["doc_heuristics"],
        "strings": static_rep["strings"],
        "sandbox": dyn_rep,
        "virustotal": vt_rep,
        "mitre_attack": mitre_rep,
        "summary": f"File '{filename}' ({static_rep['file_type']}) analyzed. Verdict: {verdict} ({score}/100) with {vt_rep['detection_ratio']} AV detections."
    }

    # Save to database
    save_submission(
        sub_id=sub_id,
        target_type="file",
        filename=filename,
        file_size=file_size,
        sha256=static_rep["hashes"]["sha256"],
        verdict=verdict,
        threat_score=score,
        tags=vt_rep["tags"],
        summary=report["summary"],
        report_data=report
    )

    return {"status": "success", "submission_id": sub_id, "report": report}


@app.post("/api/analyze/email")
async def api_analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_headers: Optional[str] = Form(None)
):
    """
    Dedicated Email Header & Phishing Analysis:
    RFC 822 parsing, SPF/DKIM/DMARC, hop relays & latency, heuristics, link defanging, attachment discovery.
    """
    sub_id = str(uuid.uuid4())
    filename = "email_inspection.eml"

    if file and file.filename:
        filename = file.filename
        raw_bytes = await file.read()
    elif raw_headers:
        raw_bytes = raw_headers.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Please upload an .eml/.msg file or paste raw email headers")

    file_size = len(raw_bytes)
    email_rep = email_analyzer.parse_email(raw_bytes, filename=filename)
    email_rep["id"] = sub_id

    # Save to database
    sha256_hash = email_rep.get("headers", {}).get("message_id") or str(uuid.uuid4())
    tags = ["email", "phishing-investigation"]
    if email_rep["verdict"] == "Malicious / Phishing":
        tags.append("phishing-confirmed")
    elif email_rep["verdict"] == "Suspicious":
        tags.append("phishing-suspicious")

    save_submission(
        sub_id=sub_id,
        target_type="email",
        filename=filename,
        file_size=file_size,
        sha256=sha256_hash,
        verdict=email_rep["verdict"],
        threat_score=email_rep["threat_score"],
        tags=tags,
        summary=email_rep["summary"],
        report_data=email_rep
    )

    return {"status": "success", "submission_id": sub_id, "report": email_rep}


@app.post("/api/analyze/sample/{sample_id}")
async def api_analyze_sample(sample_id: str):
    """Executes full analysis pipeline on one of the pre-loaded SOC samples."""
    sample = get_sample_by_id(sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    content = sample["data"]
    filename = sample["filename"]
    sub_id = str(uuid.uuid4())
    file_size = len(content)

    if sample["type"] == "email":
        email_rep = email_analyzer.parse_email(content, filename=filename)
        email_rep["id"] = sub_id
        save_submission(
            sub_id=sub_id,
            target_type="email",
            filename=filename,
            file_size=file_size,
            sha256=email_rep.get("headers", {}).get("message_id") or sub_id,
            verdict=email_rep["verdict"],
            threat_score=email_rep["threat_score"],
            tags=["sample", "email", "phishing"],
            summary=email_rep["summary"],
            report_data=email_rep
        )
        return {"status": "success", "submission_id": sub_id, "report": email_rep}

    # File sample
    static_rep = analyze_file(content, filename)
    dyn_rep = sandbox_engine.run_sandbox(static_rep, duration_seconds=30)
    vt_rep = vt_engine.scan_multi_engine(static_rep)
    mitre_rep = mitre_mapper.map_analysis(static_rep, dyn_rep)
    score, verdict, breakdown = threat_scorer.compute_score(static_rep, dyn_rep, vt_rep)

    report = {
        "id": sub_id,
        "target_type": "file",
        "filename": filename,
        "file_size": file_size,
        "verdict": verdict,
        "threat_score": score,
        "score_breakdown": breakdown,
        "hashes": static_rep["hashes"],
        "entropy": static_rep["entropy"],
        "entropy_distribution": static_rep["entropy_distribution"],
        "file_type": static_rep["file_type"],
        "magic_hex": static_rep["magic_hex"],
        "pe_analysis": static_rep["pe_analysis"],
        "yara_matches": static_rep["yara_matches"],
        "doc_heuristics": static_rep["doc_heuristics"],
        "strings": static_rep["strings"],
        "sandbox": dyn_rep,
        "virustotal": vt_rep,
        "mitre_attack": mitre_rep,
        "summary": f"Sample '{filename}' ({sample['name']}) analyzed. Verdict: {verdict} ({score}/100) with {vt_rep['detection_ratio']} AV detections."
    }

    save_submission(
        sub_id=sub_id,
        target_type="file",
        filename=filename,
        file_size=file_size,
        sha256=static_rep["hashes"]["sha256"],
        verdict=verdict,
        threat_score=score,
        tags=["sample"] + vt_rep["tags"],
        summary=report["summary"],
        report_data=report
    )

    return {"status": "success", "submission_id": sub_id, "report": report}


@app.get("/api/export/{sub_id}/{export_format}")
async def api_export_ioc(sub_id: str, export_format: str):
    """Exports IOCs into STIX 2.1, MISP JSON, Suricata rules, YARA rules, or CSV."""
    sub = get_submission(sub_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    report = sub["report_data"]

    fmt = export_format.lower()
    if fmt == "stix" or fmt == "stix21":
        stix_bundle = ioc_exporter.export_stix21(report)
        return JSONResponse(content=stix_bundle, headers={"Content-Disposition": f"attachment; filename=vanguard_stix_{sub_id[:8]}.json"})

    elif fmt == "misp":
        misp_event = ioc_exporter.export_misp(report)
        return JSONResponse(content=misp_event, headers={"Content-Disposition": f"attachment; filename=vanguard_misp_{sub_id[:8]}.json"})

    elif fmt == "suricata" or fmt == "snort":
        rules = ioc_exporter.export_suricata(report)
        return Response(content=rules, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename=vanguard_{sub_id[:8]}.rules"})

    elif fmt == "yara":
        yara_code = ioc_exporter.export_yara(report)
        return Response(content=yara_code, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename=vanguard_{sub_id[:8]}.yar"})

    elif fmt == "csv":
        csv_data = ioc_exporter.export_csv(report)
        return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=vanguard_iocs_{sub_id[:8]}.csv"})

    else:
        raise HTTPException(status_code=400, detail="Supported export formats: stix, misp, suricata, yara, csv")


@app.get("/api/download/pcap/{sub_id}")
async def api_download_pcap(sub_id: str):
    """Downloads network traffic capture (PCAP) for Wireshark inspection."""
    sub = get_submission(sub_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    report = sub["report_data"]
    pcap_filename = report.get("sandbox", {}).get("pcap_file")
    if not pcap_filename:
        raise HTTPException(status_code=404, detail="No PCAP capture recorded for this submission")

    pcap_path = PCAP_DIR / pcap_filename
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail="PCAP file not found on server")

    return FileResponse(path=str(pcap_path), filename=f"traffic_{sub_id[:8]}.pcap", media_type="application/vnd.tcpdump.pcap")


@app.post("/api/submission/{sub_id}/note")
async def api_add_note(sub_id: str, author: str = Form("SOC Analyst"), note: str = Form(...)):
    """Adds an analyst case investigation note."""
    add_analyst_note(sub_id, author, note)
    notes = get_analyst_notes(sub_id)
    return {"status": "success", "notes": notes}


@app.get("/api/submission/{sub_id}/notes")
async def api_get_notes(sub_id: str):
    """Retrieves all analyst investigation notes for a case."""
    notes = get_analyst_notes(sub_id)
    return {"status": "success", "notes": notes}


# ============================================================================
# IOC & CVE INTELLIGENCE ENDPOINTS
# ============================================================================

@app.post("/api/ioc/analyze")
async def api_analyze_ioc(ioc: str = Form(...)):
    """Universal IOC analyzer: auto-detects CVE, IP, Domain, or Hash."""
    ioc_type = ioc_intel.detect_ioc_type(ioc)
    if ioc_type == "cve":
        res = ioc_intel.analyze_cve(ioc)
    elif ioc_type == "ip":
        res = ioc_intel.analyze_ip(ioc)
    elif ioc_type in ["sha256", "sha1", "md5"]:
        res = ioc_intel.analyze_hash(ioc)
    elif ioc_type == "domain":
        res = ioc_intel.analyze_domain(ioc)
    else:
        res = ioc_intel.analyze_domain(ioc)
    return {"status": "success", "ioc_type": ioc_type, "data": res}


@app.get("/api/ioc/cve/{cve_id}")
async def api_get_cve(cve_id: str):
    """Retrieve detailed vulnerability analysis for a given CVE ID."""
    return {"status": "success", "data": ioc_intel.analyze_cve(cve_id)}


@app.get("/api/ioc/ip/{ip}")
async def api_get_ip(ip: str):
    """Retrieve IP address reputation, geolocation, and ASN info."""
    return {"status": "success", "data": ioc_intel.analyze_ip(ip)}


@app.get("/api/ioc/domain/{domain}")
async def api_get_domain(domain: str):
    """Retrieve domain WHOIS, DNS records, and DGA scoring."""
    return {"status": "success", "data": ioc_intel.analyze_domain(domain)}


@app.get("/api/ioc/hash/{hash_val}")
async def api_get_hash(hash_val: str):
    """Retrieve threat intelligence for a file hash."""
    return {"status": "success", "data": ioc_intel.analyze_hash(hash_val)}


@app.post("/api/ioc/extract")
async def api_extract_iocs(text: str = Form(...)):
    """Extract and defang all IOCs from unstructured text."""
    return {"status": "success", "data": ioc_intel.extract_and_defang_all(text)}

