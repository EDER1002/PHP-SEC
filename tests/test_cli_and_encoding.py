"""Tests de portabilidad: codificacion de texto (como en Windows), lanzador CLI y composer.

Se ejecutan los scripts como subprocesos reales, igual que los usaria una persona.
Para simular la codificacion por defecto de Windows (cp1252) en cualquier sistema se
desactiva el modo UTF-8 y se fuerza un locale sin UTF-8 (ver LEGACY).
"""
import json, os, stat, subprocess, sys, tempfile, unittest
from pathlib import Path

from test_url_scan import Site, PAGE, ENV_BODY   # servidor HTTP real de pruebas

ROOT = Path(__file__).resolve().parent.parent
LEGACY = {"PYTHONUTF8": "0", "LC_ALL": "C", "LANG": "C", "PYTHONCOERCECLOCALE": "0"}


def run(args, stdin=None, env=None):
    e = os.environ.copy()
    e.pop("PYTHONIOENCODING", None)
    e.update(env or {})
    return subprocess.run([sys.executable] + [str(a) for a in args], input=stdin,
                          capture_output=True, env=e, timeout=120)


def report(proc):
    """stdout es JSON UTF-8 valido; si el script crasheo, el assert lo muestra."""
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return json.loads(proc.stdout.decode("utf-8"))


class NonAsciiUnderLegacyLocale(unittest.TestCase):
    LINE = 'echo "Hola ñandú " . $_GET["n"];'

    # Rompe si: scan.py lee los .php o imprime el JSON con la codificacion del sistema
    # (en Windows cp1252: el snippet saldria corrupto o el script lanzaria UnicodeEncodeError).
    def test_scan_directory_keeps_non_ascii_snippet_intact(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "view.php").write_bytes(("<?php\n" + self.LINE + "\n").encode("utf-8"))
            data = report(run([ROOT / "scan.py", d], env=LEGACY))
        xss = [f for f in data["findings"] if f["id"] == "PHP-XSS_ECHO"]
        self.assertEqual([f["snippet"] for f in xss], [self.LINE])

    # Rompe si: scan.py lee stdin con la codificacion del sistema.
    def test_scan_stdin_keeps_non_ascii_snippet_intact(self):
        data = report(run([ROOT / "scan.py", "-"], stdin=("<?php " + self.LINE).encode("utf-8"), env=LEGACY))
        xss = [f for f in data["findings"] if f["id"] == "PHP-XSS_ECHO"]
        self.assertEqual([f["snippet"] for f in xss], ['<?php echo "Hola ñandú " . $_GET["n"];'])

    # Rompe si: url-scan.py imprime con la codificacion del sistema (serve.py lo decodifica
    # como UTF-8, asi que en Windows la pagina mostraria texto corrupto).
    def test_url_scan_prints_non_ascii_header_as_valid_utf8(self):
        routes = lambda path: (404, "", {"X-Powered-By": "PHP/ñandú"})
        with Site(routes) as s:
            data = report(run([ROOT / "url-scan.py", s.url], env=LEGACY))
        powered = [f["description"] for f in data["findings"]
                   if f["category"] == "header" and f["description"].startswith("X-Powered-By")]
        self.assertEqual(powered, ["X-Powered-By revela: PHP/ñandú"])


class CrossPlatformLauncher(unittest.TestCase):
    # Rompe si: php_sec.py no existe o no despacha '-' hacia el modo stdin.
    def test_dash_reads_php_from_stdin(self):
        data = report(run([ROOT / "php_sec.py", "-"], stdin=b'<?php eval($_GET["x"]); ?>'))
        self.assertEqual([(f["id"], f["severity"]) for f in data["findings"]], [("PHP-EVAL", "critical")])

    # Rompe si: una ruta de carpeta (con espacios) no se despacha al modo codigo.
    def test_directory_path_with_spaces_is_scanned_as_source(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d) / "mi proyecto"
            proj.mkdir()
            (proj / "a.php").write_text('<?php eval($_GET["x"]);', encoding="utf-8")
            data = report(run([ROOT / "php_sec.py", proj]))
        self.assertEqual(data["mode"], "source")
        self.assertEqual([f["id"] for f in data["findings"]], ["PHP-EVAL"])

    # Rompe si: una URL http no se despacha al modo URL.
    def test_http_url_is_scanned_as_live_site(self):
        routes = lambda path: (200, ENV_BODY) if path == "/.env" else (404, "")
        with Site(routes) as s:
            data = report(run([ROOT / "php_sec.py", s.url]))
        self.assertEqual(data["mode"], "url-live")
        self.assertEqual([f["description"] for f in data["findings"] if f["category"] == "exposed"],
                         ["Archivo sensible accesible: /.env"])


class ComposerFoundOnPath(unittest.TestCase):
    ADV = ('{"advisories":{"pkg/x":[{"advisoryId":"A-1","severity":"high","packageName":"pkg/x",'
           '"title":"Titulo","affectedVersions":"1.x","cve":"CVE-1"}]}}')

    # Rompe si: scan.py no encuentra/lanza 'composer' tal como esta en el PATH
    # (en Windows composer es un .bat: subprocess solo lo lanza con la ruta completa).
    def test_composer_audit_findings_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            bindir = d / "bin"; bindir.mkdir()
            if os.name == "nt":
                (bindir / "composer.bat").write_text("@echo off\r\necho " + self.ADV + "\r\n")
            else:
                f = bindir / "composer"
                f.write_text("#!/bin/sh\necho '" + self.ADV + "'\n")
                f.chmod(f.stat().st_mode | stat.S_IEXEC)
            proj = d / "p"; proj.mkdir()
            (proj / "composer.lock").write_text("{}")
            data = report(run([ROOT / "scan.py", proj],
                              env={"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}))
        dep = [(f["id"], f["severity"], f["snippet"]) for f in data["findings"] if f["category"] == "dependency"]
        self.assertEqual(dep, [("A-1", "high", "pkg/x")])
        self.assertEqual(data["tools"]["composer"], "ok")


if __name__ == "__main__":
    unittest.main()
