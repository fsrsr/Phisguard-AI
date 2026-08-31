#!/usr/bin/env python3
"""
PhishGuard AI Recon Server
Full website reconnaissance: fetch, extract, DNS, SSL → AI analysis.
"""

import hashlib
import json
import logging
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import bs4
import dns.resolver
import requests
from flask import Flask, jsonify, request

# ─── Config ──────────────────────────────────────────────────────────────
# OpenRouter direct (9router API keys don't work for /v1/chat/completions)
AI_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
AI_API_KEY = "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"
AI_MODEL = "google/gemini-3.7-flash"  # model name for AI analysis via OpenRouter
REQUEST_TIMEOUT = 15  # seconds for fetching target website
AI_TIMEOUT = 60       # seconds for AI response
MAX_HTML_SIZE = 500_000  # 500KB max HTML to analyze

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("phishguard-recon")

app = Flask(__name__)

# ─── Form extractor ──────────────────────────────────────────────────────

class FormExtractor(HTMLParser):
    """Extract forms, inputs, scripts, iframes from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.scripts = []
        self.iframes = []
        self.meta_tags = []
        self.links = []
        self.images = []
        self._current_form = None
        self._tag_stack = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        self._tag_stack.append(tag)

        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
                "has_password": False,
            }

        elif tag == "input" and self._current_form is not None:
            input_type = attrs_dict.get("type", "text").lower()
            self._current_form["inputs"].append({
                "type": input_type,
                "name": attrs_dict.get("name", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
            })
            if input_type == "password":
                self._current_form["has_password"] = True

        elif tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                self.scripts.append(src)

        elif tag == "iframe":
            self.iframes.append({
                "src": attrs_dict.get("src", ""),
                "width": attrs_dict.get("width", ""),
                "height": attrs_dict.get("height", ""),
            })

        elif tag == "meta":
            self.meta_tags.append({
                "name": attrs_dict.get("name", ""),
                "property": attrs_dict.get("property", ""),
                "content": attrs_dict.get("content", ""),
            })

        elif tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                self.links.append(href)

        elif tag == "img":
            self.images.append(attrs_dict.get("src", ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()

    def get_result(self):
        return {
            "forms": self.forms,
            "scripts": self.scripts,
            "iframes": self.iframes,
            "meta_tags": self.meta_tags,
            "links": self.links[:100],  # cap at 100
            "images": self.images[:50],
            "form_count": len(self.forms),
            "password_forms": sum(1 for f in self.forms if f["has_password"]),
            "external_scripts": [s for s in self.scripts if s.startswith("http")],
            "iframe_count": len(self.iframes),
        }


# ─── Website fetcher ─────────────────────────────────────────────────────

def fetch_website(url: str) -> dict:
    """Fetch website and extract content."""
    result = {
        "url": url,
        "status_code": None,
        "final_url": None,
        "html": "",
        "title": "",
        "content_length": 0,
        "headers": {},
        "redirects": [],
        "fetch_error": None,
        "fetch_time_ms": 0,
    }

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            result["url"] = url

        start = time.time()

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        session.max_redirects = 5

        resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=True, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["headers"] = dict(resp.headers)
        result["fetch_time_ms"] = int((time.time() - start) * 1000)

        # Track redirects
        if resp.history:
            result["redirects"] = [r.url for r in resp.history]

        # Get HTML (truncate if too large)
        html = resp.text[:MAX_HTML_SIZE]
        result["html"] = html
        result["content_length"] = len(resp.content)

        # Parse with BeautifulSoup
        soup = bs4.BeautifulSoup(html, "html.parser")

        # Title
        title_tag = soup.find("title")
        result["title"] = title_tag.get_text(strip=True) if title_tag else ""

    except requests.exceptions.SSLError as e:
        result["fetch_error"] = f"SSL Error: {str(e)[:200]}"
    except requests.exceptions.ConnectionError as e:
        result["fetch_error"] = f"Connection Error: {str(e)[:200]}"
    except requests.exceptions.Timeout:
        result["fetch_error"] = "Timeout after 15s"
    except Exception as e:
        result["fetch_error"] = f"Error: {str(e)[:200]}"

    return result


def extract_content(html: str, base_url: str) -> dict:
    """Extract structured content from HTML."""
    if not html:
        return {"error": "No HTML to parse"}

    try:
        extractor = FormExtractor()
        extractor.feed(html)

        soup = bs4.BeautifulSoup(html, "html.parser")

        # Extract visible text (simplified)
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        visible_text = soup.get_text(separator=" ", strip=True)[:3000]

        result = extractor.get_result()
        result["visible_text_preview"] = visible_text
        result["password_field_count"] = sum(
            1 for f in result["forms"] for inp in f["inputs"] if inp["type"] == "password"
        )
        return result

    except Exception as e:
        return {"error": f"Parse error: {str(e)[:200]}"}


# ─── DNS analysis ────────────────────────────────────────────────────────

def analyze_dns(domain: str) -> dict:
    """Resolve DNS records."""
    result = {
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
        "reverse_dns": None,
        "geo_locations": [],
    }

    try:
        # A records
        answers = dns.resolver.resolve(domain, "A")
        for rdata in answers:
            ip = str(rdata)
            result["a_records"].append(ip)
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)
                result["reverse_dns"] = hostname[0]
            except socket.herror:
                pass

        # MX records
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                result["mx_records"].append({"priority": rdata.preference, "exchange": str(rdata.exchange)})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # NS records
        try:
            answers = dns.resolver.resolve(domain, "NS")
            for rdata in answers:
                result["ns_records"].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # TXT records (SPF, DMARC, etc.)
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                result["txt_records"].append(str(rdata).strip('"'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # CNAME
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                result["cname"] = str(rdata)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ─── SSL analysis ────────────────────────────────────────────────────────

def analyze_ssl(domain: str) -> dict:
    """Analyze SSL certificate."""
    result = {
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "san": [],
        "days_until_expiry": None,
        "is_self_signed": False,
        "protocol_version": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

            result["valid"] = True
            result["protocol_version"] = s.version()

            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

            # Subject
            subject = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject.get("commonName", "Unknown")

            # Validity
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            result["not_before"] = not_before
            result["not_after"] = not_after

            # Calculate days until expiry
            if not_after:
                try:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (expire_date - datetime.now()).days
                    result["days_until_expiry"] = days
                except ValueError:
                    pass

            # Serial number
            serial_raw = cert.get("serialNumber", 0)
            try:
                result["serial_number"] = format(serial_raw, "X")
            except (ValueError, TypeError):
                result["serial_number"] = str(serial_raw)

            # SAN (Subject Alternative Names)
            san_list = cert.get("subjectAltName", ())
            result["san"] = [entry[1] for entry in san_list]

            # Self-signed check
            issuer_cn = issuer.get("commonName", "")
            subject_cn = subject.get("commonName", "")
            result["is_self_signed"] = (issuer_cn == subject_cn)

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {str(e)[:200]}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)[:200]}"
    except socket.timeout:
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["error"] = "Port 443 refused"
    except Exception as e:
        result["error"] = f"Error: {str(e)[:200]}"

    return result


# ─── Local heuristic pattern detection ───────────────────────────────────

def detect_scam_patterns(url: str, domain: str, website_data: dict,
                         content_data: dict, dns_data: dict, ssl_data: dict) -> dict:
    """Local heuristic detection for known scam patterns. Returns patterns, risk, conclusion."""
    patterns = []
    risk_boost = 0
    risk = "MEDIUM"
    conclusion = ""

    # 1. IP Tracker / Grabify-like detection
    SHORT_URL_DOMAINS = [
        "urlto.me", "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at",
    ]
    parsed_url = urlparse(url if url.startswith("http") else "https://" + url)
    if any(d in parsed_url.hostname for d in SHORT_URL_DOMAINS if parsed_url.hostname):
        patterns.append("IP_TRACKER: URL pendek digunakan → bisa jadi pelacak IP (Grabify-like)")
        risk_boost += 25

    # Check if final URL differs significantly from original
    final_url = website_data.get("final_url", "")
    if final_url:
        final_domain = urlparse(final_url).hostname or ""
        if domain != final_domain:
            patterns.append(f"REDIRECT: Domain berubah dari {domain} ke {final_domain}")
            risk_boost += 10
            # Check if destination has minimal content (IP tracker pattern)
            if content_data.get("form_count", 0) == 0 and len(content_data.get("links", [])) < 3:
                patterns.append("MINIMAL_CONTENT: Halaman kosong/tanpa konten nyata → indikasi IP tracker")
                risk_boost += 25

    # 2. Payment scam detection (Indonesian payment methods on suspicious domain)
    PAYMENT_KEYWORDS = ["qris", "dana", "ovo", "gopay", "shopeepay", "linkaja",
                        "transfer bank", "bca", "bri", "mandiri", "bni", "bank bri",
                        "virtual account", "ewallet", "e-wallet"]
    visible_text = content_data.get("visible_text_preview", "").lower()
    forms = content_data.get("forms", [])

    has_payment_kw = any(kw in visible_text for kw in PAYMENT_KEYWORDS)
    has_login_form = any(f.get("has_password") for f in forms)
    has_payment_form = any("pay" in str(f.get("action", "")).lower() for f in forms)

    if has_payment_kw and (has_login_form or has_payment_form):
        # Check if this is NOT a legitimate Indonesian payment site
        LEGIT_DOMAINS = ["bca.co.id", "bri.co.id", "mandiri.co.id", "bni.co.id",
                         "dana.id", "ovo.id", "gopay.id", "shopee.co.id", "tokopedia.com",
                         "bukalapak.com", "blibli.com", "traveloka.com", "grab.com"]
        if not any(d in domain for d in LEGIT_DOMAINS):
            patterns.append("PAYMENT_SCAM: Form pembayaran/transfer di domain tidak resmi")
            risk_boost += 35
            risk = "HIGH"

    # 3. Gambling/Judol detection
    JUDOL_KEYWORDS = ["slot", "casino", "betting", "togel", "poker", "jackpot",
                      "pragmatic", "habanero", "pgsoft", "scatter", "gacor",
                      "maxwin", "rtp live", "deposit pulsa", "bet"]
    judol_count = sum(1 for kw in JUDOL_KEYWORDS if kw in visible_text)
    if judol_count >= 2:
        patterns.append(f"JUDOL: {judol_count} kata kunci judi ditemukan ({', '.join([k for k in JUDOL_KEYWORDS if k in visible_text][:5])})")
        risk_boost += 40
        risk = "HIGH"
        conclusion = f"Ini website judi online (JUDOL). Ditemukan {judol_count} indikator perjudian. JANGAN bermain atau deposit uang."

    # 4. Brand impersonation detection
    BRAND_PATTERNS = {
        "bca": ["bca", "bank central asia"],
        "bri": ["bri", "bank rakyat indonesia"],
        "mandiri": ["mandiri", "bank mandiri"],
        "bni": ["bni", "bank negara indonesia"],
        "shopee": ["shopee"],
        "tokopedia": ["tokopedia"],
        "dana": ["dana"],
        "ovo": ["ovo"],
        "gopay": ["gopay"],
        "gojek": ["gojek"],
        "grab": ["grab"],
    }

    title = website_data.get("title", "").lower()
    for brand, keywords in BRAND_PATTERNS.items():
        # Check if brand mentioned in title/content but domain doesn't match
        brand_mentioned = any(kw in title or kw in visible_text[:500] for kw in keywords)
        brand_in_domain = any(kw in domain for kw in keywords)

        if brand_mentioned and not brand_in_domain:
            patterns.append(f"BRAND_IMPERSONATION: Brand '{brand}' disebutkan tapi domain '{domain}' bukan domain resmi")
            risk_boost += 30
            risk = "HIGH"
            conclusion = f"Ini website yang menirukan {brand.upper()} tetapi bukan website resmi. JANGAN masukkan data login atau pembayaran."

    # 5. Investment scam detection
    INVEST_KEYWORDS = ["investasi", "invest", "profit", "return", "trading",
                       "crypto", "bitcoin", "forex", "saham", "bisnis",
                       "peluang usaha", "reseller", "dropship", "multi level"]
    invest_count = sum(1 for kw in INVEST_KEYWORDS if kw in visible_text)
    if invest_count >= 2:
        patterns.append(f"INVESTMENT_SCAM: {invest_count} kata kunci investasi/MLM ditemukan")
        risk_boost += 25
        risk = "HIGH"
        conclusion = f"Ini website investasi/MLM yang mencurigakan. Hati-hati dengan janji keuntungan besar."

    # 6. Credential harvesting detection
    if has_login_form and content_data.get("password_forms", 0) > 0:
        # Check for suspicious patterns
        external_scripts = content_data.get("external_scripts", [])
        suspicious_scripts = [s for s in external_scripts if any(x in s.lower() for x in ["tracker", "analytics", "facebook", "pixel", "webhook"])]
        if len(suspicious_scripts) > 2:
            patterns.append("CREDENTIAL_HARVEST: Form login dengan banyak script pelacak")
            risk_boost += 20

    # 7. SSL analysis patterns
    if ssl_data.get("is_self_signed"):
        patterns.append("SSL_SELF_SIGNED: Sertifikat SSL self-signed (tidak terverifikasi)")
        risk_boost += 15

    if ssl_data.get("days_until_expiry") is not None and ssl_data["days_until_expiry"] < 7:
        patterns.append(f"SSL_SHORT_LIVED: SSL akan habis dalam {ssl_data['days_until_expiry']} hari")
        risk_boost += 10

    # 8. DNS analysis patterns
    if dns_data.get("a_records"):
        # Check for Cloudflare IP (common for hiding real server)
        cf_ips = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                  "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                  "104.28.", "104.29.", "104.30.", "104.31.",
                  "172.67.", "172.66."]
        is_cloudflare = any(any(ip.startswith(cf) for cf in cf_ips) for ip in dns_data["a_records"])
        if is_cloudflare:
            patterns.append("CLOUDFLARE_PROXY: IP tersembunyi di balik Cloudflare CDN")
            risk_boost += 5

    # Build conclusion if patterns found and no AI conclusion
    if patterns and not conclusion:
        if risk_boost >= 40:
            risk = "HIGH"
            conclusion = f"Situs ini berisiko TINGGI. Ditemukan {len(patterns)} indikator mencurigakan. JANGAN masukkan data apapun."
        elif risk_boost >= 25:
            risk = "MEDIUM"
            conclusion = f"Situs ini perlu diwaspadai. Ada {len(patterns)} hal mencurigakan. Berhati-hatilah."
        else:
            risk = "LOW"
            conclusion = f"Ditemukan {len(patterns)} hal yang perlu diperhatikan pada situs ini."

    return {
        "detected": len(patterns) > 0,
        "patterns": patterns,
        "risk_boost": risk_boost,
        "risk": risk,
        "conclusion": conclusion,
    }


# ─── AI analysis ─────────────────────────────────────────────────────────

def call_ai_analysis(url: str, domain: str, website_data: dict,
                     content_data: dict, dns_data: dict, ssl_data: dict) -> dict:
    """Send all recon data to AI for comprehensive analysis."""

    # Build context for AI
    prompt_parts = [
        "You are a cybersecurity expert. Analyze this website for phishing, scam, and social engineering threats.",
        "You have access to the ACTUAL website content, not just the URL.",
        "",
        f"=== TARGET ===",
        f"URL: {url}",
        f"Domain: {domain}",
        f"HTTP Status: {website_data.get('status_code')}",
        f"Final URL (after redirects): {website_data.get('final_url')}",
        f"Redirects: {json.dumps(website_data.get('redirects', []))}",
        f"Title: {website_data.get('title')}",
        "",
        f"=== SSL CERTIFICATE ===",
        f"Valid: {ssl_data.get('valid')}",
        f"Issuer: {ssl_data.get('issuer')}",
        f"Subject: {ssl_data.get('subject')}",
        f"Self-signed: {ssl_data.get('is_self_signed')}",
        f"Expires: {ssl_data.get('not_after')} ({ssl_data.get('days_until_expiry')} days)",
        f"SAN domains: {json.dumps(ssl_data.get('san', []))}",
        f"Error: {ssl_data.get('error')}",
        "",
        f"=== DNS RECORDS ===",
        f"A records: {json.dumps(dns_data.get('a_records', []))}",
        f"MX records: {json.dumps(dns_data.get('mx_records', []))}",
        f"NS records: {json.dumps(dns_data.get('ns_records', []))}",
        f"TXT records: {json.dumps(dns_data.get('txt_records', [])[:5])}",
        f"Reverse DNS: {dns_data.get('reverse_dns')}",
        f"DNS Error: {dns_data.get('error')}",
    ]

    # Website content analysis
    forms = content_data.get("forms", [])
    if forms:
        prompt_parts.append("")
        prompt_parts.append(f"=== FORMS FOUND ({len(forms)}) ===")
        for i, form in enumerate(forms[:5]):
            prompt_parts.append(f"Form {i+1}: action={form.get('action')}, method={form.get('method')}, "
                              f"has_password={form.get('has_password')}, inputs={[inp['type'] for inp in form.get('inputs', [])]}")

    iframes = content_data.get("iframes", [])
    if iframes:
        prompt_parts.append("")
        prompt_parts.append(f"=== IFRAMES ({len(iframes)}) ===")
        for iframe in iframes[:5]:
            prompt_parts.append(f"iframe src={iframe.get('src')}")

    scripts = content_data.get("external_scripts", [])
    if scripts:
        prompt_parts.append("")
        prompt_parts.append(f"=== EXTERNAL SCRIPTS ({len(scripts)}) ===")
        for s in scripts[:10]:
            prompt_parts.append(f"script: {s}")

    # Visible text (truncated)
    visible_text = content_data.get("visible_text_preview", "")
    if visible_text:
        prompt_parts.append("")
        prompt_parts.append(f"=== VISIBLE TEXT (first 2000 chars) ===")
        prompt_parts.append(visible_text[:2000])

    prompt_parts.extend([
        "",
        "=== ANALYSIS INSTRUCTIONS ===",
        "Based on ALL the above data (actual website content, forms, scripts, DNS, SSL), analyze:",
        "1. Is this website legitimate or phishing/scam?",
        "2. Does it impersonate a known brand? Which brand?",
        "3. Are there suspicious login forms collecting credentials?",
        "4. Do external scripts come from suspicious sources?",
        "5. Is the SSL certificate suspicious (self-signed, wrong domain, short validity)?",
        "6. Do DNS records match the claimed brand?",
        "7. Are there hidden iframes or suspicious redirects?",
        "8. Social engineering patterns in the visible text?",
        "9. Overall risk assessment with confidence score.",
        "10. SPECIFIC PATTERNS TO CHECK:",
        "    - IP Tracker / Grabify-like: short URL (urlto.me, bit.ly, tinyurl) → redirects to page that only collects IP, no real content",
        "    - Payment scam: fake payment page with Indonesian methods (QRIS, DANA, OVO, GoPay, bank transfer) on non-official domain",
        "    - Brand impersonation: domain similar to known brand (typosquatting, combosquatting) + login/payment form",
        "    - Investment scam: promises high returns, crypto, trading, 'business opportunity', 'reseller'",
        "    - Gambling/Judol: 'slot', 'casino', 'betting', 'togel', 'poker' on unofficial domain",
        "    - Package/delivery scam: 'verifikasi', 'tracking', 'kirim ulang' with fake logistics brand",
        "",
        "Reply in Indonesian. Return JSON:",
        '{"risk":"LOW|MEDIUM|HIGH|CRITICAL","score":0-100,"reasons":["..."],"brand_impersonation":"...or null","suspicious_forms":["..."],"se_patterns":["..."],"conclusion":"Kesimpulan singkat dalam bahasa Indonesia sederhana untuk orang awam: apakah ini phishing/scam/judol/penipuan/bukan, dan kenapa. Contoh: Ini website penipuan (scam) yang menirukan BCA untuk mencuri data login Anda. JANGAN masukkan data apapun.","ai_summary":"detailed analysis in Indonesian"}'
    ])

    prompt = "\n".join(prompt_parts)

    try:
        body = json.dumps({
            "model": AI_MODEL,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing websites for phishing and social engineering. Reply in Indonesian."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 2048,
            "temperature": 0.3,
            "stream": False,
        })

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AI_API_KEY}",
        }

        start = time.time()
        resp = requests.post(AI_ENDPOINT, data=body, headers=headers, timeout=AI_TIMEOUT)
        elapsed_ms = int((time.time() - start) * 1000)

        log.info(f"AI response: status={resp.status_code}, time={elapsed_ms}ms")

        if resp.status_code == 200:
            raw = resp.text
            # Strip SSE suffix
            raw = re.sub(r"\ndata: \[DONE\]$", "", raw).strip()

            data = json.loads(raw)
            content = ""
            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            content = msg.get("content") or choice.get("delta", {}).get("content", "")

            # Also check reasoning field for thinking models
            if not content:
                content = msg.get("reasoning", "")

            if content:
                # Strip markdown code blocks if present
                cleaned = content.strip()
                if cleaned.startswith("```json"):
                    cleaned = cleaned[7:]
                elif cleaned.startswith("```"):
                    cleaned = cleaned[3:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                cleaned = cleaned.strip()

                # Try parse as JSON
                try:
                    # Lenient parse
                    ai_result = json.loads(cleaned)
                    return {
                        "ai_risk": ai_result.get("risk", "MEDIUM"),
                        "ai_score": ai_result.get("score", 50),
                        "ai_reasons": ai_result.get("reasons", []),
                        "ai_brand_impersonation": ai_result.get("brand_impersonation"),
                        "ai_suspicious_forms": ai_result.get("suspicious_forms", []),
                        "ai_se_patterns": ai_result.get("se_patterns", []),
                        "ai_summary": ai_result.get("ai_summary", cleaned[:1000]),
                        "ai_conclusion": ai_result.get("conclusion", ""),
                        "ai_model": data.get("model", AI_MODEL),
                        "ai_time_ms": elapsed_ms,
                    }
                except json.JSONDecodeError:
                    # Non-JSON response — use as summary
                    return {
                        "ai_risk": "MEDIUM",
                        "ai_score": 50,
                        "ai_reasons": [],
                        "ai_summary": content[:2000],
                        "ai_model": data.get("model", AI_MODEL),
                        "ai_time_ms": elapsed_ms,
                    }
            else:
                return {"ai_error": "Empty AI response", "ai_time_ms": elapsed_ms}
        else:
            return {"ai_error": f"AI API error {resp.status_code}: {resp.text[:200]}"}

    except requests.exceptions.Timeout:
        return {"ai_error": f"AI timeout after {AI_TIMEOUT}s"}
    except Exception as e:
        return {"ai_error": f"AI error: {str(e)[:200]}"}


# ─── Main recon endpoint ────────────────────────────────────────────────

@app.route("/v1/recon", methods=["POST"])
def recon():
    """Full website reconnaissance endpoint.
    
    Request: {"url": "https://example.com"}
    Response: { ... comprehensive recon data ... }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400

    # Parse domain
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    domain = parsed.hostname or url

    log.info(f"Recon request: url={url}, domain={domain}")
    start_time = time.time()

    # Phase 1: Parallel fetch + DNS + SSL
    website_data = fetch_website(url)
    dns_data = analyze_dns(domain)
    ssl_data = analyze_ssl(domain)

    # Phase 2: Extract content from HTML
    content_data = extract_content(website_data.get("html", ""), url)

    # Phase 2.5: Local heuristic pattern detection
    local_patterns = detect_scam_patterns(url, domain, website_data, content_data, dns_data, ssl_data)

    # Phase 3: AI analysis with ALL data
    ai_result = call_ai_analysis(url, domain, website_data, content_data, dns_data, ssl_data)

    # Merge local patterns into AI result
    if local_patterns.get("detected"):
        ai_result.setdefault("ai_local_patterns", local_patterns["patterns"])
        ai_result.setdefault("ai_local_risk_boost", local_patterns.get("risk_boost", 0))
        # Override risk if local detection is confident — and keep score consistent
        # with the overridden label, otherwise UI shows e.g. risk=HIGH score=55 (looks MEDIUM).
        if local_patterns.get("risk_boost", 0) > 30:
            overridden_risk = local_patterns.get("risk", ai_result.get("ai_risk", "MEDIUM"))
            ai_result["ai_risk"] = overridden_risk
            min_score_for_risk = {"HIGH": 70, "MEDIUM": 40, "LOW": 0}.get(overridden_risk, 0)
            ai_result["ai_score"] = max(ai_result.get("ai_score", 0), min_score_for_risk)
        # Add local conclusion
        if local_patterns.get("conclusion"):
            ai_result["ai_conclusion"] = local_patterns["conclusion"]

    # Build final result
    total_time_ms = int((time.time() - start_time) * 1000)

    result = {
        "success": True,
        "url": url,
        "domain": domain,
        "total_time_ms": total_time_ms,
        "website": {
            "status_code": website_data.get("status_code"),
            "final_url": website_data.get("final_url"),
            "title": website_data.get("title"),
            "content_length": website_data.get("content_length"),
            "redirects": website_data.get("redirects", []),
            "fetch_time_ms": website_data.get("fetch_time_ms"),
            "fetch_error": website_data.get("fetch_error"),
        },
        "content": content_data,
        "dns": dns_data,
        "ssl": ssl_data,
        "ai": ai_result,
    }

    # Overall risk from AI
    result["overall_risk"] = ai_result.get("ai_risk", "UNKNOWN")
    result["overall_score"] = ai_result.get("ai_score", 0)
    result["reasons"] = ai_result.get("ai_reasons", [])

    log.info(f"Recon complete: domain={domain}, risk={result['overall_risk']}, "
             f"score={result['overall_score']}, time={total_time_ms}ms")

    return jsonify(result)


@app.route("/v1/models", methods=["GET"])
def models():
    """Proxy to 9router models list."""
    auth = request.headers.get("Authorization", "")
    try:
        resp = requests.get("http://localhost:20128/v1/models",
                          headers={"Authorization": auth}, timeout=10)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "phishguard-recon", "version": "2.0"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    log.info(f"Starting PhishGuard Recon Server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
