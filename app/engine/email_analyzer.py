"""
Comprehensive Email Header and Phishing Analysis Engine.
Parses RFC 822 / MIME emails (.eml, .msg, raw headers),
verifies SPF / DKIM / DMARC authentication, visualizes hop-by-hop relay latency,
detects display-name spoofing and lookalike domains, extracts defanged URLs and attachments.
"""
import email
from email import policy
from email.parser import BytesParser, HeaderParser
import re
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

def defang_url(url: str) -> str:
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    url = url.replace(".", "[.]")
    return url

class EmailAnalyzer:
    def __init__(self):
        pass

    def parse_email(self, raw_bytes: bytes, filename: str = "email.eml") -> Dict[str, Any]:
        """Parses raw email bytes into structured SOC phishing report."""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception:
            # Fallback to compat32
            msg = email.message_from_bytes(raw_bytes)

        # Basic Headers
        subject = msg.get("Subject", "(No Subject)")
        from_hdr = msg.get("From", "")
        to_hdr = msg.get("To", "")
        cc_hdr = msg.get("Cc", "")
        date_hdr = msg.get("Date", "")
        reply_to_hdr = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        message_id = msg.get("Message-ID", "")
        x_mailer = msg.get("X-Mailer") or msg.get("User-Agent") or "Unknown"

        # Extract From Address & Display Name
        from_display, from_email = self._extract_display_and_email(from_hdr)
        return_display, return_email = self._extract_display_and_email(return_path)
        reply_display, reply_email = self._extract_display_and_email(reply_to_hdr)

        # Authentication headers
        auth_results = msg.get_all("Authentication-Results", [])
        received_spf = msg.get_all("Received-SPF", [])
        dkim_signatures = msg.get_all("DKIM-Signature", [])

        auth_evaluation = self._evaluate_authentication(
            auth_results, received_spf, dkim_signatures, from_email, return_email
        )

        # Hop Analysis from Received headers
        received_hdrs = msg.get_all("Received", [])
        hops, relay_latency = self._analyze_hops(received_hdrs)

        # Body parsing & link extraction
        plain_body, html_body = self._extract_bodies(msg)
        extracted_urls = self._extract_and_inspect_urls(plain_body, html_body)

        # Attachments extraction
        attachments = self._extract_attachments(msg)

        # Phishing Heuristic Checks
        heuristics, phishing_score = self._compute_phishing_heuristics(
            from_display, from_email, return_email, reply_email,
            subject, plain_body, auth_evaluation, extracted_urls, attachments
        )

        # Overall verdict
        verdict = "Clean"
        if phishing_score >= 70:
            verdict = "Malicious / Phishing"
        elif phishing_score >= 35:
            verdict = "Suspicious"

        return {
            "target_type": "email",
            "filename": filename,
            "verdict": verdict,
            "threat_score": phishing_score,
            "summary": f"Email from '{from_display}' <{from_email}> - Verdict: {verdict}",
            "headers": {
                "subject": subject,
                "from": from_hdr,
                "from_display": from_display,
                "from_email": from_email,
                "to": to_hdr,
                "cc": cc_hdr,
                "date": date_hdr,
                "reply_to": reply_to_hdr,
                "reply_email": reply_email,
                "return_path": return_path,
                "return_email": return_email,
                "message_id": message_id,
                "x_mailer": x_mailer
            },
            "authentication": auth_evaluation,
            "hops": hops,
            "relay_latency": relay_latency,
            "urls": extracted_urls,
            "attachments": attachments,
            "heuristics": heuristics,
            "body_preview": {
                "plain_text": plain_body[:2000] if plain_body else "",
                "has_html": bool(html_body),
                "sanitized_html": self._sanitize_html_preview(html_body) if html_body else ""
            }
        }

    def _extract_display_and_email(self, hdr_val: str) -> Tuple[str, str]:
        if not hdr_val:
            return "", ""
        match = re.search(r'(.*?)(?:<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>|$)', hdr_val)
        if match:
            display = match.group(1).strip().strip('"\'')
            addr = match.group(2) if match.group(2) else ""
            if not addr and "@" in display:
                addr = display
                display = ""
            return display, addr.lower()
        return hdr_val.strip(), ""

    def _evaluate_authentication(
        self,
        auth_results: List[str],
        received_spf: List[str],
        dkim_sigs: List[str],
        from_email: str,
        return_email: str
    ) -> Dict[str, Any]:
        combined_auth = " ".join(auth_results + received_spf).lower()

        # SPF
        spf_status = "NONE"
        spf_details = "No SPF record or verification found"
        if "spf=pass" in combined_auth or "pass (google.com:" in combined_auth:
            spf_status = "PASS"
            spf_details = "Sender IP authorized in SPF record"
        elif "spf=fail" in combined_auth or "softfail" in combined_auth:
            spf_status = "FAIL"
            spf_details = "Sender IP is NOT authorized in domain SPF record"
        elif "spf=neutral" in combined_auth:
            spf_status = "NEUTRAL"
            spf_details = "SPF record does not assert authorization (+?)"

        # DKIM
        dkim_status = "NONE"
        dkim_details = "No DKIM signature present"
        dkim_domain = ""
        if dkim_sigs:
            sig0 = dkim_sigs[0]
            d_match = re.search(r'd=([a-zA-Z0-9.-]+)', sig0)
            if d_match:
                dkim_domain = d_match.group(1)

            if "dkim=pass" in combined_auth:
                dkim_status = "PASS"
                dkim_details = f"Valid cryptographic signature from domain '{dkim_domain}'"
            elif "dkim=fail" in combined_auth:
                dkim_status = "FAIL"
                dkim_details = f"DKIM signature verification failed for '{dkim_domain}'"
            else:
                dkim_status = "PRESENT"
                dkim_details = f"Signature present for '{dkim_domain}' (unverified in header)"

        # DMARC
        dmarc_status = "NONE"
        dmarc_details = "No DMARC evaluation in header"
        dmarc_policy = "none"
        if "dmarc=pass" in combined_auth:
            dmarc_status = "PASS"
            dmarc_details = "Domain alignment and policy checks passed"
        elif "dmarc=fail" in combined_auth:
            dmarc_status = "FAIL"
            dmarc_details = "DMARC authentication failed (SPF/DKIM alignment mismatch)"
            if "p=reject" in combined_auth:
                dmarc_policy = "reject"
            elif "p=quarantine" in combined_auth:
                dmarc_policy = "quarantine"
        else:
            # Check domain alignment between From and Return-Path
            from_domain = from_email.split("@")[-1] if "@" in from_email else ""
            ret_domain = return_email.split("@")[-1] if "@" in return_email else ""
            if from_domain and ret_domain and from_domain != ret_domain:
                dmarc_status = "MISALIGNED"
                dmarc_details = f"Alignment warning: From domain ({from_domain}) differs from Return-Path ({ret_domain})"

        return {
            "spf": {"status": spf_status, "details": spf_details},
            "dkim": {"status": dkim_status, "details": dkim_details, "domain": dkim_domain},
            "dmarc": {"status": dmarc_status, "details": dmarc_details, "policy": dmarc_policy}
        }

    def _analyze_hops(self, received_hdrs: List[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        hops = []
        # Received headers are prepended by each MTA, so reverse to read chronologically
        chronological_hdrs = list(reversed(received_hdrs))
        prev_dt = None
        total_delay_sec = 0

        for idx, hdr in enumerate(chronological_hdrs):
            hop_num = idx + 1
            # Extract from host / by host
            from_match = re.search(r'from\s+([^\s;]+)', hdr, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s;]+)', hdr, re.IGNORECASE)
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hdr)

            from_host = from_match.group(1) if from_match else "unknown"
            by_host = by_match.group(1) if by_match else "unknown"
            ip = ip_match.group(1) if ip_match else ""

            # Attempt date extraction
            delay_str = "0s"
            hop_dt = None
            date_match = re.search(r';\s*(.*)$', hdr, re.DOTALL)
            if date_match:
                date_str = date_match.group(1).strip()
                # parse date
                try:
                    hop_dt = email.utils.parsedate_to_datetime(date_str)
                    if prev_dt:
                        diff = (hop_dt - prev_dt).total_seconds()
                        if diff >= 0:
                            total_delay_sec += diff
                            if diff > 60:
                                delay_str = f"{int(diff // 60)}m {int(diff % 60)}s"
                            else:
                                delay_str = f"{int(diff)}s"
                        else:
                            delay_str = "- clock skew"
                    prev_dt = hop_dt
                except Exception:
                    pass

            hops.append({
                "hop": hop_num,
                "from": from_host,
                "by": by_host,
                "ip": ip,
                "delay": delay_str,
                "raw": hdr.strip().replace("\n", " ").replace("\t", " ")
            })

        relay_latency = {
            "total_hops": len(hops),
            "total_delay_seconds": int(total_delay_sec),
            "total_delay_formatted": f"{int(total_delay_sec // 60)}m {int(total_delay_sec % 60)}s" if total_delay_sec > 60 else f"{int(total_delay_sec)}s"
        }
        return hops, relay_latency

    def _extract_bodies(self, msg: Any) -> Tuple[str, str]:
        plain_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disp:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="ignore")

                    if content_type == "text/plain" and not plain_body:
                        plain_body = decoded
                    elif content_type == "text/html" and not html_body:
                        html_body = decoded
                except Exception:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="ignore")
                    if msg.get_content_type() == "text/html":
                        html_body = decoded
                    else:
                        plain_body = decoded
            except Exception:
                pass

        return plain_body, html_body

    def _extract_and_inspect_urls(self, plain: str, html: str) -> List[Dict[str, Any]]:
        found_urls = []
        seen = set()

        # URLs in plain text
        raw_urls = re.findall(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', plain + " " + html)
        for u in raw_urls:
            if u not in seen:
                seen.add(u)
                found_urls.append({
                    "url": u,
                    "defanged": defang_url(u),
                    "anchor_text": "",
                    "is_mismatch": False
                })

        # Check anchor text mismatches in HTML
        if html:
            anchor_matches = re.finditer(r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL)
            for m in anchor_matches:
                href = m.group(1)
                text = re.sub(r'<[^>]+>', '', m.group(2)).strip()
                # If text looks like a URL but points elsewhere: Phishing red flag!
                is_mismatch = False
                if re.match(r'https?://', text) and not href.startswith(text.split("/")[2]):
                    is_mismatch = True

                for item in found_urls:
                    if item["url"] == href:
                        item["anchor_text"] = text[:60]
                        item["is_mismatch"] = is_mismatch

        return found_urls[:40]

    def _extract_attachments(self, msg: Any) -> List[Dict[str, Any]]:
        attachments = []
        if not msg.is_multipart():
            return attachments

        suspicious_exts = {".exe", ".scr", ".pif", ".bat", ".vbs", ".js", ".hta", ".iso", ".img", ".xlsm", ".docm", ".zip", ".rar", ".7z"}

        for part in msg.walk():
            content_disp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename or "attachment" in content_disp:
                fname = filename or "unnamed_attachment.bin"
                payload = part.get_payload(decode=True) or b""
                fsize = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
                
                # Check extension
                ext = "." + fname.split(".")[-1].lower() if "." in fname else ""
                is_dangerous = ext in suspicious_exts

                attachments.append({
                    "filename": fname,
                    "size": fsize,
                    "content_type": part.get_content_type(),
                    "sha256": sha256,
                    "is_dangerous": is_dangerous,
                    "payload_preview_b64": payload[:100].hex()
                })

        return attachments

    def _compute_phishing_heuristics(
        self,
        from_display: str,
        from_email: str,
        return_email: str,
        reply_email: str,
        subject: str,
        body: str,
        auth: Dict[str, Any],
        urls: List[Dict[str, Any]],
        attachments: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        heuristics = []
        score = 0

        # 1. Display Name Spoofing
        # e.g. Display Name contains an email address different from sending address
        if "@" in from_display and from_email:
            display_inner_email = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_display)
            if display_inner_email and display_inner_email.group(1).lower() != from_email.lower():
                heuristics.append({
                    "rule": "Display Name Email Spoofing",
                    "severity": "CRITICAL",
                    "points": 35,
                    "desc": f"Display name contains fake email address '{display_inner_email.group(1)}' masking sender '{from_email}'"
                })
                score += 35

        # Brand impersonation in display name
        trusted_brands = ["paypal", "microsoft", "google", "apple", "amazon", "bank of america", "chase", "dhl", "fedex", "support team", "security alert"]
        for brand in trusted_brands:
            if brand in from_display.lower() and brand not in from_email.lower():
                heuristics.append({
                    "rule": "Executive / Brand Impersonation",
                    "severity": "HIGH",
                    "points": 25,
                    "desc": f"Display name pretends to be '{from_display}' but sending address is '{from_email}'"
                })
                score += 25
                break

        # 2. Return-Path Mismatch
        if return_email and from_email and return_email != from_email:
            ret_domain = return_email.split("@")[-1]
            from_domain = from_email.split("@")[-1]
            if ret_domain != from_domain:
                heuristics.append({
                    "rule": "Sender Domain Mismatch (From vs Return-Path)",
                    "severity": "MEDIUM",
                    "points": 15,
                    "desc": f"Visible sender domain '{from_domain}' differs from delivery envelope '{ret_domain}'"
                })
                score += 15

        # 3. Reply-To Redirection
        if reply_email and from_email and reply_email != from_email:
            heuristics.append({
                "rule": "Reply-To Address Divergence",
                "severity": "HIGH",
                "points": 20,
                "desc": f"Replies are rerouted to external address: '{reply_email}'"
            })
            score += 20

        # 4. SPF / DKIM / DMARC Failures
        if auth["spf"]["status"] == "FAIL":
            heuristics.append({
                "rule": "SPF Authentication Failure",
                "severity": "HIGH",
                "points": 20,
                "desc": "Originating IP address is not authorized in sender SPF record"
            })
            score += 20
        if auth["dmarc"]["status"] == "FAIL":
            heuristics.append({
                "rule": "DMARC Alignment Failure",
                "severity": "HIGH",
                "points": 20,
                "desc": "Message failed DMARC validation"
            })
            score += 20

        # 5. Dangerous Attachments
        for att in attachments:
            if att["is_dangerous"]:
                heuristics.append({
                    "rule": "Dangerous Executable/Script Attachment",
                    "severity": "CRITICAL",
                    "points": 35,
                    "desc": f"Contains potentially executable attachment: '{att['filename']}'"
                })
                score += 35
                break

        # 6. Anchor Text Link Mismatches
        mismatches = [u for u in urls if u.get("is_mismatch")]
        if mismatches:
            heuristics.append({
                "rule": "Deceptive Hyperlink Mismatch",
                "severity": "HIGH",
                "points": 25,
                "desc": f"Hyperlink display text claims one destination but navigates to another: {mismatches[0]['url']}"
            })
            score += 25

        # 7. Urgency / Social Engineering Keywords in Subject & Body
        urgent_phrases = ["immediate action required", "account suspended", "verify your account", "wire transfer", "unauthorized login", "password expires", "urgent request", "tax refund", "invoice payment"]
        combined_text = f"{subject} {body}".lower()
        matched_triggers = [p for p in urgent_phrases if p in combined_text]
        if matched_triggers:
            heuristics.append({
                "rule": "Urgency & Psychological Coercion Triggers",
                "severity": "MEDIUM",
                "points": 15,
                "desc": f"Detected social engineering pressure keywords: {', '.join(matched_triggers[:3])}"
            })
            score += 15

        return heuristics, min(100, score)

    def _sanitize_html_preview(self, html: str) -> str:
        # Strip script tags and dangerous onload handlers for safe SOC viewing
        sanitized = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'on\w+\s*=', 'data-blocked=', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'<iframe.*?>.*?</iframe>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        return sanitized
