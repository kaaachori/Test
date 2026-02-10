#!/usr/bin/env python3
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8000
INDEX_PATH = Path(__file__).with_name("index.html")
REPORT_STORE: dict[str, dict] = {}

COMMON_SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "High",
        "recommendation": "Set HSTS with long max-age (>=31536000), includeSubDomains, and preload if possible.",
        "validate": lambda v: "max-age=" in v.lower(),
    },
    "content-security-policy": {
        "severity": "High",
        "recommendation": "Deploy a strict CSP using nonces/hashes and avoid unsafe-inline/unsafe-eval.",
        "validate": lambda v: len(v.strip()) > 0 and "unsafe-inline" not in v.lower(),
    },
    "x-content-type-options": {
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
        "validate": lambda v: v.strip().lower() == "nosniff",
    },
    "x-frame-options": {
        "severity": "Medium",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        "validate": lambda v: v.strip().upper() in {"DENY", "SAMEORIGIN"},
    },
    "referrer-policy": {
        "severity": "Low",
        "recommendation": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "permissions-policy": {
        "severity": "Low",
        "recommendation": "Use Permissions-Policy to disable unneeded browser features.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-opener-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Opener-Policy: same-origin when feasible.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-resource-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Resource-Policy appropriately (same-origin/same-site).",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-embedder-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Embedder-Policy if cross-origin isolation is required.",
        "validate": lambda v: len(v.strip()) > 0,
    },
}

SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/phpinfo.php",
    "/server-status",
    "/wp-admin/install.php",
    "/wp-login.php",
]


def severity_score(severity: str) -> int:
    return {"Critical": 20, "High": 14, "Medium": 9, "Low": 5, "Info": 0}.get(severity, 0)


def add_finding(findings: list, category: str, title: str, severity: str, evidence: str, recommendation: str):
    findings.append(
        {
            "category": category,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def build_opener():
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )


def fetch_url(url: str, method: str = "GET", timeout: int = 12):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "DeepVAPTScanner/2.0",
            "Accept": "*/*",
            "Connection": "close",
        },
        method=method,
    )
    opener = build_opener()
    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read(200000)
            headers = {k.lower(): v for k, v in response.getheaders()}
            return response.status, headers, body.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        body = exc.read(200000).decode("utf-8", errors="ignore") if exc.fp else ""
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, headers, body


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


def extract_internal_links(base_url: str, html: str, max_links: int = 8):
    parser = LinkExtractor()
    parser.feed(html)
    root = urllib.parse.urlparse(base_url)
    out = []
    for href in parser.links:
        full = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc != root.netloc:
            continue
        clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        if clean not in out:
            out.append(clean)
        if len(out) >= max_links:
            break
    return out


def check_tls(target_url: str):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme != "https":
        return {"checked": False, "message": "TLS checks skipped for non-HTTPS URL."}

    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()

    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version() or "unknown"

    expiry_raw = cert.get("notAfter")
    expiry_days = None
    if expiry_raw:
        expiry_dt = datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expiry_days = (expiry_dt - datetime.now(timezone.utc)).days

    return {
        "checked": True,
        "protocol": protocol,
        "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {},
        "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {},
        "expiry_days": expiry_days,
    }


def scan_target(target_url: str):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    findings = []
    analyzed_pages = []

    root_status, root_headers, root_body = fetch_url(target_url)
    analyzed_pages.append({"url": target_url, "status": root_status})

    # Security headers checks (root)
    for hname, rule in COMMON_SECURITY_HEADERS.items():
        val = root_headers.get(hname)
        if val is None:
            add_finding(
                findings,
                "HTTP Headers",
                f"Missing {hname}",
                rule["severity"],
                f"Header '{hname}' was not found in primary response.",
                rule["recommendation"],
            )
        elif not rule["validate"](val):
            add_finding(
                findings,
                "HTTP Headers",
                f"Weak {hname}",
                rule["severity"],
                f"Header value observed: {val}",
                rule["recommendation"],
            )

    # Information disclosure headers
    if "server" in root_headers and root_headers["server"].strip():
        add_finding(
            findings,
            "Information Disclosure",
            "Server banner exposed",
            "Low",
            f"Server header reveals technology: {root_headers['server']}",
            "Suppress or generalize server banner details in production.",
        )

    powered_by = root_headers.get("x-powered-by")
    if powered_by:
        add_finding(
            findings,
            "Information Disclosure",
            "X-Powered-By exposed",
            "Low",
            f"X-Powered-By: {powered_by}",
            "Remove X-Powered-By to reduce stack fingerprinting.",
        )

    # CORS review
    aco = root_headers.get("access-control-allow-origin", "")
    acc = root_headers.get("access-control-allow-credentials", "")
    if aco.strip() == "*" and acc.strip().lower() == "true":
        add_finding(
            findings,
            "CORS",
            "Potentially dangerous CORS policy",
            "High",
            "Access-Control-Allow-Origin is '*' with credentials enabled.",
            "Do not use wildcard origins with credentials; explicitly allow trusted origins only.",
        )

    # Cookies flags
    set_cookie = root_headers.get("set-cookie", "")
    if set_cookie:
        lc = set_cookie.lower()
        if "secure" not in lc:
            add_finding(
                findings,
                "Session Security",
                "Cookie missing Secure flag",
                "Medium",
                f"Set-Cookie observed without Secure flag: {set_cookie[:160]}",
                "Set Secure on session/auth cookies.",
            )
        if "httponly" not in lc:
            add_finding(
                findings,
                "Session Security",
                "Cookie missing HttpOnly flag",
                "Medium",
                f"Set-Cookie observed without HttpOnly flag: {set_cookie[:160]}",
                "Set HttpOnly on session/auth cookies.",
            )
        if "samesite" not in lc:
            add_finding(
                findings,
                "Session Security",
                "Cookie missing SameSite attribute",
                "Medium",
                f"Set-Cookie observed without SameSite attribute: {set_cookie[:160]}",
                "Set SameSite=Lax or Strict for session cookies.",
            )

    # HTTP methods via OPTIONS
    try:
        _, options_headers, _ = fetch_url(target_url, method="OPTIONS")
        allow = options_headers.get("allow", "")
        if allow:
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                add_finding(
                    findings,
                    "HTTP Methods",
                    "Potentially risky methods enabled",
                    "Medium",
                    f"Allow header includes: {allow}",
                    "Disable unnecessary methods such as PUT/DELETE/TRACE/CONNECT on public endpoints.",
                )
    except Exception:
        pass

    # Sensitive file checks
    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    for path in SENSITIVE_PATHS:
        try:
            status, _, body = fetch_url(base + path, method="GET", timeout=8)
            if status < 400 and body.strip():
                add_finding(
                    findings,
                    "Sensitive Exposure",
                    f"Potential exposed sensitive path: {path}",
                    "High" if path in {"/.git/config", "/.env"} else "Medium",
                    f"Path returned status {status} with response content.",
                    "Restrict public access and return 404/403 for internal or sensitive files.",
                )
        except Exception:
            continue

    # robots/security.txt checks
    for path, sev in [("/robots.txt", "Info"), ("/.well-known/security.txt", "Low")]:
        try:
            status, _, _ = fetch_url(base + path, method="GET", timeout=8)
            if status >= 400:
                add_finding(
                    findings,
                    "Best Practices",
                    f"{path} not available",
                    sev,
                    f"Endpoint {path} returned HTTP {status}.",
                    "Provide this file where appropriate to improve crawler/security contact handling.",
                )
        except Exception:
            continue

    # Basic reflected payload pattern check (non-intrusive)
    test_param = "vaptprobe"
    probe_value = "VAPT_UNIQUE_9137"
    q = urllib.parse.urlencode({test_param: probe_value})
    probe_url = f"{target_url}{'&' if urllib.parse.urlparse(target_url).query else '?'}{q}"
    try:
        _, _, probe_body = fetch_url(probe_url, method="GET", timeout=10)
        if probe_value in probe_body:
            add_finding(
                findings,
                "Input Handling",
                "Reflected input detected",
                "Medium",
                "A unique test payload appeared in the HTTP response body.",
                "Apply strict contextual output encoding and robust input validation.",
            )
    except Exception:
        pass

    # Crawl a few internal pages and check header consistency
    links = extract_internal_links(target_url, root_body, max_links=6)
    inconsistent_pages = []
    for link in links:
        try:
            status, headers, _ = fetch_url(link, timeout=8)
            analyzed_pages.append({"url": link, "status": status})
            missing = [h for h in COMMON_SECURITY_HEADERS if h not in headers]
            if missing:
                inconsistent_pages.append((link, missing[:3]))
        except Exception:
            continue

    if inconsistent_pages:
        sample = "; ".join(f"{u} missing {', '.join(m)}" for u, m in inconsistent_pages[:3])
        add_finding(
            findings,
            "Configuration Consistency",
            "Security headers inconsistent across pages",
            "Medium",
            sample,
            "Apply uniform security headers at reverse proxy/web server level for all application routes.",
        )

    # TLS checks
    tls_info = check_tls(target_url)
    if tls_info.get("checked"):
        proto = tls_info.get("protocol", "")
        if proto in {"TLSv1", "TLSv1.1"}:
            add_finding(
                findings,
                "TLS",
                "Legacy TLS protocol supported",
                "High",
                f"Negotiated protocol: {proto}",
                "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
            )
        exp_days = tls_info.get("expiry_days")
        if isinstance(exp_days, int) and exp_days < 30:
            add_finding(
                findings,
                "TLS",
                "Certificate expiry approaching",
                "Medium",
                f"Certificate expires in {exp_days} days.",
                "Rotate/renew certificate before expiry and automate renewal where possible.",
            )

    # Score and risk
    penalty = sum(severity_score(f["severity"]) for f in findings)
    score = max(0, 100 - penalty)
    risk = "Low" if score >= 80 else "Medium" if score >= 55 else "High"

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1

    report = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target_url,
        "http_status": root_status,
        "score": score,
        "risk_rating": risk,
        "summary": (
            "Automated deep baseline scan completed (headers, cookies, CORS, TLS, methods, "
            "sensitive paths, and lightweight reflection checks). Use manual + authenticated testing for full VAPT coverage."
        ),
        "finding_counts": counts,
        "findings": findings,
        "root_headers": root_headers,
        "tls": tls_info,
        "pages_analyzed": analyzed_pages,
    }

    REPORT_STORE[report["report_id"]] = report
    return report


def pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_simple_pdf(lines: list[str]) -> bytes:
    y = 800
    content_lines = ["BT", "/F1 10 Tf", "72 820 Td"]
    first = True
    for line in lines[:300]:
        if not first:
            content_lines.append("0 -14 Td")
        first = False
        content_lines.append(f"({pdf_escape(line[:140])}) Tj")
        y -= 14
        if y < 50:
            break
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(f"5 0 obj << /Length {len(stream)} >> stream\n".encode("ascii") + stream + b"\nendstream endobj\n")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF".encode("ascii"))
    return bytes(pdf)


def report_to_pdf(report: dict) -> bytes:
    lines = [
        "Web Vulnerability Scan Report",
        f"Generated: {report.get('generated_at', '')}",
        f"Target: {report.get('target', '')}",
        f"HTTP Status: {report.get('http_status', '')}",
        f"Score: {report.get('score', '')}/100",
        f"Risk Rating: {report.get('risk_rating', '')}",
        "",
        "Finding Counts:",
    ]
    for sev, cnt in report.get("finding_counts", {}).items():
        lines.append(f"- {sev}: {cnt}")

    lines.append("")
    lines.append("Detailed Findings:")
    for idx, f in enumerate(report.get("findings", []), start=1):
        evidence = re.sub(r"\s+", " ", f["evidence"])
        recommendation = re.sub(r"\s+", " ", f["recommendation"])
        lines.extend(
            [
                f"{idx}. [{f['severity']}] {f['title']} ({f['category']})",
                f"   Evidence: {evidence}",
                f"   Recommendation: {recommendation}",
            ]
        )

    lines.append("")
    lines.append("Note: This is an automated baseline assessment, not a substitute for complete manual VAPT.")
    return make_simple_pdf(lines)


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, code=200):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_pdf(self, payload: bytes, filename: str = "vapt-report.pdf"):
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


    def do_HEAD(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            content = INDEX_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            content = INDEX_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if parsed.path == "/api/check":
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get("url", [""])[0].strip()
            if not target:
                self._send_json({"error": "Missing url query parameter."}, code=400)
                return
            try:
                report = scan_target(target)
                self._send_json(report)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, code=400)
            except Exception as exc:
                self._send_json({"error": f"Scan failed: {exc}"}, code=502)
            return

        if parsed.path == "/api/report/pdf":
            query = urllib.parse.parse_qs(parsed.query)
            rid = query.get("id", [""])[0].strip()
            report = REPORT_STORE.get(rid)
            if not report:
                self._send_json({"error": "Unknown report id."}, code=404)
                return
            pdf = report_to_pdf(report)
            self._send_pdf(pdf, filename=f"vapt-report-{rid[:8]}.pdf")
            return

        self._send_json({"error": "Not found"}, code=404)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Serving on http://{HOST}:{PORT}")
    server.serve_forever()
