#!/usr/bin/env python3
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8000
INDEX_PATH = Path(__file__).with_name("index.html")


HEADER_RULES = {
    "strict-transport-security": {
        "severity": "High",
        "recommendation": "Set HSTS with a long max-age and includeSubDomains; preload if eligible.",
        "validate": lambda v: "max-age=" in v.lower(),
    },
    "content-security-policy": {
        "severity": "High",
        "recommendation": "Define a strict CSP that avoids unsafe-inline/unsafe-eval and uses nonces/hashes.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "x-content-type-options": {
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
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
        "recommendation": "Set Permissions-Policy to disable unnecessary browser features.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-opener-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Opener-Policy to same-origin where possible.",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-resource-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Resource-Policy appropriately (e.g., same-origin/site).",
        "validate": lambda v: len(v.strip()) > 0,
    },
    "cross-origin-embedder-policy": {
        "severity": "Low",
        "recommendation": "Set Cross-Origin-Embedder-Policy to require-corp if cross-origin isolation is required.",
        "validate": lambda v: len(v.strip()) > 0,
    },
}


def build_report(target_url: str, status_code: int, headers: dict[str, str]):
    findings = []
    score = 100

    for header_name, rule in HEADER_RULES.items():
        actual = headers.get(header_name)
        if actual is None:
            findings.append(
                {
                    "header": header_name,
                    "status": "missing",
                    "severity": rule["severity"],
                    "impact": f"{header_name} is missing; this can weaken browser-enforced security controls.",
                    "recommendation": rule["recommendation"],
                }
            )
            score -= 15 if rule["severity"] == "High" else 10 if rule["severity"] == "Medium" else 6
        elif not rule["validate"](actual):
            findings.append(
                {
                    "header": header_name,
                    "status": "misconfigured",
                    "severity": rule["severity"],
                    "impact": f"{header_name} exists but appears weak/misconfigured.",
                    "recommendation": f"Current value: {actual}. {rule['recommendation']}",
                }
            )
            score -= 8 if rule["severity"] == "High" else 5
        else:
            findings.append(
                {
                    "header": header_name,
                    "status": "good",
                    "severity": "Info",
                    "impact": "Header is present with an acceptable baseline value.",
                    "recommendation": "No immediate action required; continue monitoring.",
                }
            )

    if status_code >= 500:
        score -= 10
    elif status_code >= 400:
        score -= 5

    score = max(0, min(100, score))
    risk = "Low" if score >= 80 else "Medium" if score >= 55 else "High"

    return {
        "target": target_url,
        "http_status": status_code,
        "score": score,
        "risk_rating": risk,
        "summary": (
            "Automated, header-focused VAPT-style assessment generated from HTTP response headers. "
            "Use this as a preliminary report and complement with authenticated, manual, and dynamic testing."
        ),
        "findings": findings,
        "all_headers": headers,
    }


def fetch_headers(target_url: str):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "HeaderScanner/1.0",
            "Accept": "*/*",
        },
        method="GET",
    )

    context = ssl.create_default_context()

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )

    try:
        with opener.open(req, timeout=15) as response:
            raw_headers = {k.lower(): v for k, v in response.getheaders()}
            return response.status, raw_headers
    except urllib.error.HTTPError as exc:
        raw_headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, raw_headers


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, code=200):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

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
                status_code, headers = fetch_headers(target)
                report = build_report(target, status_code, headers)
                self._send_json(report)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, code=400)
            except Exception as exc:
                self._send_json({"error": f"Scan failed: {exc}"}, code=502)
            return

        self._send_json({"error": "Not found"}, code=404)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Serving on http://{HOST}:{PORT}")
    server.serve_forever()
