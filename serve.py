#!/usr/bin/env python3
"""serve.py — mini servidor local Firefox <-> php-sec (versión endurecida).

Defensas:
  * Solo escucha en 127.0.0.1 y exige Host local (anti DNS-rebinding).
  * Exige cabecera Origin y que coincida con el sitio que se escanea:
    una página solo puede escanearse a sí misma. Una <img>, un formulario o
    cualquier otra web NO pueden disparar escaneos ni leer resultados.
  * CORS devuelve el Origin ya validado (nunca "*").
  * Solo http/https, sin credenciales en la URL, longitud limitada.
  * Sin shell: subprocess con lista, timeout, salida acotada y validada como JSON.
  * Hilos, máximo 2 escaneos simultáneos.
"""
import http.server, json, os, subprocess, sys, threading
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8765
DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
MAX_URL_LEN = 2048
MAX_OUT = 2_000_000
TIMEOUT = 60
SLOTS = threading.BoundedSemaphore(2)
DEFAULT_PORTS = {"http": 80, "https": 443}


def origin_of(scheme, hostname, port):
    """Origen normalizado (esquema://host[:puerto]) sin puerto por defecto."""
    host = f"[{hostname}]" if ":" in hostname else hostname
    s = f"{scheme}://{host}"
    if port and port != DEFAULT_PORTS.get(scheme):
        s += f":{port}"
    return s.lower()


def parse_target(raw):
    """Devuelve (url_limpia, origen) o lanza ValueError con el motivo."""
    if not raw or len(raw) > MAX_URL_LEN:
        raise ValueError("url vacía o demasiado larga")
    u = urlparse(raw)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("solo se permiten URLs http/https")
    if u.username or u.password:
        raise ValueError("no se permiten credenciales en la URL")
    try:
        port = u.port
    except ValueError:
        raise ValueError("puerto inválido")
    return u._replace(fragment="").geturl(), origin_of(u.scheme, u.hostname, port)


def origin_header_norm(value):
    if not value or value == "null":
        return None
    u = urlparse(value)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    try:
        return origin_of(u.scheme, u.hostname, u.port)
    except ValueError:
        return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "php-sec"
    sys_version = ""

    def _send(self, code, obj, cors_origin=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cors_origin:
            self.send_header("Access-Control-Allow-Origin", cors_origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, code, why):
        sys.stderr.write(f"php-sec: rechazado ({why}) Origin={self.headers.get('Origin')!r}\n")
        self._send(code, {"error": why})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/":
            return self._send(404, {"error": "no encontrado"})
        if (self.headers.get("Host") or "").lower() not in ALLOWED_HOSTS:
            return self._reject(403, "host no permitido")

        raw = parse_qs(parsed.query).get("url", [""])[0]
        try:
            target, target_origin = parse_target(raw)
        except ValueError as e:
            return self._reject(400, str(e))

        origin = origin_header_norm(self.headers.get("Origin"))
        if origin is None:
            return self._reject(403, "falta cabecera Origin válida")
        if origin != target_origin:
            return self._reject(403, "una página solo puede escanearse a sí misma")

        if not SLOTS.acquire(blocking=False):
            return self._send(429, {"error": "demasiados escaneos simultáneos"}, origin)
        try:
            try:
                out = subprocess.run(
                    [sys.executable, "-I", os.path.join(DIR, "url-scan.py"), target],
                    capture_output=True, timeout=TIMEOUT, check=False, stdin=subprocess.DEVNULL,
                ).stdout[:MAX_OUT]
                data = json.loads(out.decode("utf-8", errors="replace"))
            except subprocess.TimeoutExpired:
                return self._send(504, {"error": f"timeout {TIMEOUT}s"}, origin)
            except (json.JSONDecodeError, ValueError):
                return self._send(502, {"error": "el escáner devolvió salida inválida"}, origin)
            self._send(200, data, origin)
        finally:
            SLOTS.release()

    def log_message(self, *a):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as httpd:
        print(f"php-sec server on http://{HOST}:{PORT}", flush=True)
        httpd.serve_forever()
