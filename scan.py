#!/usr/bin/env python3
import json, shutil, subprocess, sys, re
from pathlib import Path
MAX_FILE = 2_000_000          # no leer archivos PHP gigantes
SKIP_DIRS = {"vendor", "node_modules", ".git"}
def run(cmd, cwd=None, timeout=300):
    """cmd es una LISTA (sin shell). stdin cerrado."""
    exe = shutil.which(cmd[0])          # ruta completa: en Windows composer es un .bat
    if exe: cmd = [exe] + list(cmd[1:])
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, cwd=cwd,
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except OSError as e:
        return "", str(e), 127
RULES = {
    "eval": (r"\beval\s*\(", "critical", "CWE-95", "Ejecucion dinamica"),
    "exec": (r"\b(exec|system|shell_exec|passthru|popen)\s*\(", "high", "CWE-78", "Ejecucion comandos"),
    "unserialize": (r"\bunserialize\s*\(", "high", "CWE-502", "Deserializacion insegura"),
    "md5_sha1": (r"\b(md5|sha1)\s*\(", "medium", "CWE-327", "Hash debil"),
    "sql_concat": (r"(->query|->prepare|->exec|mysqli_query|mysql_query)\s*\([^;]*\.\s*\$", "critical", "CWE-89", "SQLi: consulta con concatenacion"),
    "user_input_concat": (r"\.\s*\$_(GET|POST|REQUEST|COOKIE)", "medium", "CWE-20", "Concatenacion de input sin contexto"),
    "xss_echo": (r"\b(echo|print|printf)\b[^;]*\.\s*\$_(GET|POST|REQUEST|COOKIE)", "high", "CWE-79", "XSS: salida sin escapar"),
    "ssrf": (r"\b(file_get_contents|curl_init|curl_exec|fsockopen|fopen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "high", "CWE-918", "SSRF probable"),
    "include_var": (r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)", "critical", "CWE-98", "LFI/RFI"),
    "extract": (r"\bextract\s*\(", "medium", "CWE-621", "extract() sobre input"),
}
def scan_lines(lines, filename):
    out = []
    for i, line in enumerate(lines, 1):
        for key, (pat, sev, cwe, desc) in RULES.items():
            if re.search(pat, line):
                out.append({"id": f"PHP-{key.upper()}", "severity": sev, "category": key,
                    "tool": "grep-rules", "file": filename, "line": i,
                    "snippet": line.strip()[:140], "description": desc, "cwe": cwe,
                    "remediation": "Revisar manualmente"})
    return out
def scan_grep(project):
    out = []
    for php in Path(project).rglob("*.php"):
        if SKIP_DIRS & set(php.parts): continue
        try:
            if php.is_symlink() or not php.is_file() or php.stat().st_size > MAX_FILE: continue
            content = php.read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        out.extend(scan_lines(content.splitlines(), str(php)))
    return out
def scan_composer(project):
    if not (Path(project) / "composer.lock").exists(): return [], "sin composer.lock"
    out, err, rc = run(["composer", "audit", "--format=json", "--no-plugins", "--no-scripts", "--no-interaction"], cwd=project)
    if rc != 0 and not out: return [], f"composer fallo: {err[:80]}"
    findings = []
    try:
        data = json.loads(out)
        for advisories in data.get("advisories", {}).values():
            for adv in advisories:
                findings.append({"id": adv.get("advisoryId", "CVE-?"),
                    "severity": adv.get("severity", "unknown").lower(),
                    "category": "dependency", "tool": "composer-audit",
                    "file": "composer.lock", "line": 0,
                    "snippet": adv.get("packageName", ""),
                    "description": adv.get("title", ""), "cwe": adv.get("cve", ""),
                    "remediation": f"Actualizar a {adv.get('affectedVersions', '?')}"})
    except json.JSONDecodeError: pass
    return findings, "ok"
def scan_semgrep(project):
    if shutil.which("semgrep") is None:
        return [], "semgrep no instalado"
    out, err, rc = run(["semgrep", "--config", "p/php", "--json", "--quiet", "--no-git-ignore",
                        "--metrics=off", "--disable-version-check", "."], cwd=project)
    findings = []
    try:
        data = json.loads(out)
        for r in data.get("results", []):
            findings.append({"id": r.get("check_id", "semgrep"),
                "severity": r.get("extra", {}).get("severity", "medium").lower(),
                "category": "semgrep", "tool": "semgrep",
                "file": r.get("path"), "line": r.get("start", {}).get("line", 0),
                "snippet": r.get("extra", {}).get("lines", "")[:140],
                "description": r.get("extra", {}).get("message", ""), "cwe": "",
                "remediation": "Ver mensaje semgrep"})
    except Exception: pass
    return findings, "ok"
def build_report(project, findings, extra):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        summary[f["severity"] if f["severity"] in summary else "unknown"] += 1
    report = {"project": project, "summary": summary, "total": len(findings), "findings": findings}
    report.update(extra)
    print(json.dumps(report, indent=2, ensure_ascii=False))
def main():
    sys.stdout.reconfigure(encoding="utf-8")                     # misma salida en Windows, Linux y macOS
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    project = sys.argv[1] if len(sys.argv) > 1 else "."
    if project == "-":
        text = sys.stdin.read(MAX_FILE)
        build_report("<stdin>", scan_lines(text.splitlines(), "<stdin>"),
            {"mode": "stdin", "tools": {"composer": "n/a", "semgrep": "n/a"}}); return
    if not Path(project).is_dir():
        print(json.dumps({"error": f"no es un directorio: {project}"})); sys.exit(1)
    grep_f = scan_grep(project)
    comp_f, comp_note = scan_composer(project)
    sem_f, sem_note = scan_semgrep(project)
    build_report(str(Path(project).resolve()), grep_f + comp_f + sem_f,
        {"mode": "source", "tools": {"composer": comp_note, "semgrep": sem_note}})
if __name__ == "__main__": main()
