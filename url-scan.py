#!/usr/bin/env python3
import sys, json, re, ssl, secrets, difflib, urllib.request, urllib.error
from urllib.parse import urljoin, urlparse
SENSITIVE = [".env", ".git/config", ".git/HEAD", "composer.json", "composer.lock",
    "phpinfo.php", "info.php", "storage/logs/laravel.log", "wp-config.php.bak",
    "config.php.bak", "backup.sql", "dump.sql", ".htaccess", ".DS_Store"]
LOW_SEVERITY = {"composer.json", "composer.lock"}   # publicos en proyectos open source
SOFT_404_SIMILARITY = 0.9
MAX_URL_LEN = 2048
TLS_INSECURE_HOSTS = set()   # hosts cuyo certificado no se pudo verificar

def valid_target(url):
    """Solo http/https con host y sin credenciales (bloquea file://, ftp://, data:...)."""
    if not url or len(url) > MAX_URL_LEN: return False
    u = urlparse(url)
    return u.scheme in ("http", "https") and bool(u.hostname) and not (u.username or u.password)

class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Sigue redirecciones solo dentro del mismo host y solo http/https."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        a, b = urlparse(req.full_url), urlparse(newurl)
        if b.scheme not in ("http", "https") or (b.hostname or "").lower() != (a.hostname or "").lower():
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def make_opener(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.OpenerDirector()
    # Manual a proposito: sin FileHandler, FTPHandler, DataHandler ni ProxyHandler.
    for h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(context=ctx),
              urllib.request.HTTPDefaultErrorHandler(), SameHostRedirect(),
              urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
        op.add_handler(h)
    return op

def _open(url, timeout, verify):
    req = urllib.request.Request(url, headers={"User-Agent": "php-sec/1.0 (+audit)"})
    with make_opener(verify).open(req, timeout=timeout) as r:
        return r.status, r.headers, r.read(200_000).decode("utf-8", errors="ignore")

def fetch(url, timeout=10):
    if not valid_target(url): return 0, {}, "URL no permitida (solo http/https)"
    host = urlparse(url).hostname
    try:
        return _open(url, timeout, verify=host not in TLS_INSECURE_HOSTS)
    except urllib.error.HTTPError as e: return e.code, e.headers, ""
    except Exception as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            TLS_INSECURE_HOSTS.add(host)          # reintento sin verificar, pero se reporta
            try: return _open(url, timeout, verify=False)
            except urllib.error.HTTPError as e2: return e2.code, e2.headers, ""
            except Exception as e2: return 0, {}, str(e2)
        return 0, {}, str(e)
def soft_404_baseline(base):
    """Cuerpo que el sitio devuelve para una ruta que NO existe, o None si responde 404 normal."""
    s, _, b = fetch(urljoin(base + "/", "php-sec-" + secrets.token_hex(6)), timeout=6)
    return b if s == 200 else None

def is_soft_404(body, baseline):
    """True si el cuerpo es (casi) la pagina generica que el sitio sirve con 200 para todo."""
    if baseline is None: return False
    return difflib.SequenceMatcher(None, body[:4000], baseline[:4000]).ratio() >= SOFT_404_SIMILARITY

def scan(url):
    findings = []
    status, headers, body = fetch(url)
    if status == 0:
        return [{"severity": "info", "category": "network",
            "description": f"No conecta: {body}", "file": url}]
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    if urlparse(url).hostname in TLS_INSECURE_HOSTS:
        findings.append({"severity": "medium", "category": "tls",
            "description": "Certificado TLS no verificable (autofirmado, expirado o host no coincide)",
            "file": url, "cwe": "CWE-295"})
    for h in ("X-Powered-By", "Server"):
        for k, v in headers.items():
            if k.lower() == h.lower() and v and (h != "Server" or "/" in v):
                findings.append({"severity": "low", "category": "header",
                    "description": f"{h} revela: {v}", "file": url, "cwe": "CWE-200"})
    for pat, sev, cwe, desc in [
        (r"(Fatal error|Parse error|Warning:\s|Notice:\s)", "high", "CWE-209", "Errores PHP visibles"),
        (r"/var/www/|/home/\w+/public_html", "high", "CWE-209", "Rutas internas expuestas"),
        (r"xdebug|Xdebug", "high", "CWE-209", "Xdebug en produccion"),
        (r"Stack trace:|#\d+\s+/.*\.php", "high", "CWE-209", "Stack trace expuesto")]:
        if re.search(pat, body, re.I):
            findings.append({"severity": sev, "category": "debug",
                "description": desc, "file": url, "cwe": cwe})
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            for c in (v if isinstance(v, list) else [v]):
                if "httponly" not in c.lower():
                    findings.append({"severity": "medium", "category": "cookie",
                        "description": f"Cookie sin HttpOnly: {c.split('=')[0]}",
                        "file": url, "cwe": "CWE-1004"})
                if url.startswith("https") and "secure" not in c.lower():
                    findings.append({"severity": "medium", "category": "cookie",
                        "description": f"Cookie sin Secure en HTTPS: {c.split('=')[0]}",
                        "file": url, "cwe": "CWE-614"})
    for f in re.findall(r'<form[^>]*method=["\']post["\'][^>]*>(.*?)</form>', body, re.I | re.S):
        if not re.search(r'csrf|_token|authenticity_token', f, re.I):
            findings.append({"severity": "medium", "category": "csrf",
                "description": "Form POST sin token CSRF", "file": url, "cwe": "CWE-352"})
    baseline = soft_404_baseline(base)
    for path in SENSITIVE:
        full = urljoin(base + "/", path)
        s, _, b = fetch(full, timeout=6)
        if s == 200 and len(b) > 10 and not is_soft_404(b, baseline):
            if path in LOW_SEVERITY: sev = "low"
            else: sev = "critical" if path.endswith((".env", ".sql", "config")) else "high"
            findings.append({"severity": sev, "category": "exposed",
                "description": f"Archivo sensible accesible: /{path}",
                "file": full, "cwe": "CWE-538",
                "remediation": f"Bloquear /{path} en servidor"})
    return findings
def main():
    sys.stdout.reconfigure(encoding="utf-8")   # serve.py decodifica esta salida como UTF-8
    if len(sys.argv) < 2: print(json.dumps({"error": "uso: url-scan.py <URL>"})); sys.exit(1)
    url = sys.argv[1]
    if not valid_target(url): print(json.dumps({"error": "URL no valida: solo http/https"})); sys.exit(1)
    findings = scan(url)
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings: summary[f["severity"]] += 1
    print(json.dumps({"project": url, "mode": "url-live",
        "summary": summary, "total": len(findings), "findings": findings},
        indent=2, ensure_ascii=False))
if __name__ == "__main__": main()
