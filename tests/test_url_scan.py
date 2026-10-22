"""Tests de url-scan.py contra servidores HTTP reales (sin mocks).

Cada test indica el cambio de produccion que lo haria fallar.
Uso:  python3 -m unittest discover -s tests -v   (desde la carpeta del proyecto)
"""
import http.server, importlib.util, os, threading, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
URLSCAN = os.environ.get("URLSCAN_PATH", os.path.join(HERE, "..", "url-scan.py"))
spec = importlib.util.spec_from_file_location("url_scan", URLSCAN)
url_scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(url_scan)

PAGE = ("<html><head><title>Ejemplo</title></head><body>"
        + "<p>Bienvenido a nuestro sitio, aqui hay contenido generico de la pagina.</p>" * 40
        + "</body></html>")


# ---- utilidades de test (no viven en produccion) ---------------------------
class Site:
    """Servidor real en un puerto libre. `routes(path) -> (status, body_str)`."""
    def __init__(self, routes):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                status, body = routes(self.path)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *a): pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def __enter__(self): return self
    def __exit__(self, *a):
        self.httpd.shutdown(); self.httpd.server_close()


def exposed(findings):
    return [f for f in findings if f["category"] == "exposed"]


ENV_BODY = "APP_KEY=base64:abcdEFGH1234\nDB_PASSWORD=supersecreto123\n"


class SoftNotFound(unittest.TestCase):
    # Rompe si: se quita la comparacion contra una ruta inexistente.
    def test_site_answering_200_to_every_path_reports_no_exposed_files(self):
        with Site(lambda path: (200, PAGE)) as s:
            self.assertEqual(exposed(url_scan.scan(s.url)), [])

    # Rompe si: la comparacion exige cuerpo identico (el 404 "bonito" repite la ruta).
    def test_soft_404_that_echoes_the_requested_path_reports_no_exposed_files(self):
        with Site(lambda path: (200, PAGE + f"<p>No encontramos {path}</p>")) as s:
            self.assertEqual(exposed(url_scan.scan(s.url)), [])

    # Rompe si: al detectar soft-404 se descarta TODO, incluso un archivo real.
    def test_real_env_is_still_critical_behind_a_soft_404_site(self):
        def routes(path):
            return (200, ENV_BODY) if path == "/.env" else (200, PAGE)
        with Site(routes) as s:
            got = exposed(url_scan.scan(s.url))
        self.assertEqual([(f["description"], f["severity"]) for f in got],
                         [("Archivo sensible accesible: /.env", "critical")])


class SeverityOfPublicComposerFiles(unittest.TestCase):
    # Rompe si: composer.json/lock vuelven a "high" (son publicos en proyectos open source).
    def test_composer_json_and_lock_are_low(self):
        def routes(path):
            if path in ("/composer.json", "/composer.lock"):
                return (200, '{"name": "vendor/app", "require": {"php": ">=8.1"}}')
            return (404, "")
        with Site(routes) as s:
            got = exposed(url_scan.scan(s.url))
        self.assertEqual(sorted((f["description"], f["severity"]) for f in got),
                         [("Archivo sensible accesible: /composer.json", "low"),
                          ("Archivo sensible accesible: /composer.lock", "low")])


class RegressionPlain404Site(unittest.TestCase):
    # Rompe si: el cambio deja de detectar un .env real en un sitio con 404 normal.
    def test_real_env_on_plain_404_site_is_critical(self):
        def routes(path):
            return (200, ENV_BODY) if path == "/.env" else (404, "")
        with Site(routes) as s:
            got = exposed(url_scan.scan(s.url))
        self.assertEqual([(f["description"], f["severity"]) for f in got],
                         [("Archivo sensible accesible: /.env", "critical")])

    # Rompe si: backup.sql real deja de ser critico.
    def test_real_sql_dump_on_plain_404_site_is_critical(self):
        def routes(path):
            return (200, "INSERT INTO users VALUES (1,'admin','hash');\n") if path == "/backup.sql" else (404, "")
        with Site(routes) as s:
            got = exposed(url_scan.scan(s.url))
        self.assertEqual([(f["description"], f["severity"]) for f in got],
                         [("Archivo sensible accesible: /backup.sql", "critical")])

    # Rompe si: un sitio limpio empieza a reportar archivos expuestos.
    def test_clean_404_site_reports_no_exposed_files(self):
        with Site(lambda path: (404, "")) as s:
            self.assertEqual(exposed(url_scan.scan(s.url)), [])


if __name__ == "__main__":
    unittest.main()
