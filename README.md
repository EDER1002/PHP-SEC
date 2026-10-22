# PHP-SEC

[![tests](https://github.com/EDER1002/PHP-SEC/actions/workflows/tests.yml/badge.svg)](https://github.com/EDER1002/PHP-SEC/actions/workflows/tests.yml)

Escáner de seguridad híbrido para PHP, escrito en Python usando **solo la librería estándar** (sin `pip install`).

| Modo | Qué hace |
|---|---|
| **Código (SAST)** | Analiza archivos `.php` con reglas de expresiones regulares: `eval`, ejecución de comandos, SQLi por concatenación, XSS, SSRF, LFI/RFI, deserialización insegura, hashes débiles. Si están instalados, suma `composer audit` y `semgrep`. |
| **URL (DAST)** | Revisa un sitio en vivo: cabeceras que filtran información, cookies sin `HttpOnly`/`Secure`, errores PHP visibles, formularios POST sin token CSRF y archivos sensibles expuestos (`/.env`, `/.git/config`, `backup.sql`…). |
| **Navegador** | Un servidor local y un *bookmarklet* de Firefox para escanear la página que estás viendo con un clic. |

La salida es siempre un **JSON** con el mismo formato (`summary`, `total`, `findings[]`), pensado para que lo lea una persona, otro programa o un agente de IA que redacte el informe y proponga parches.

> **Uso responsable:** escanea solo sitios y proyectos tuyos o con autorización expresa. El modo URL hace unas 15 peticiones a rutas sensibles, algo que en un sitio ajeno puede parecer un sondeo hostil.

## Requisitos

- Python 3.10 o superior.
- Opcionales: `composer` (auditoría de dependencias) y `semgrep` (reglas `p/php`). Si no están, se omiten sin error.

## Compatibilidad

Las pruebas automáticas corren en GitHub Actions en **Linux, Windows y macOS**, con Python 3.10 y 3.13 (ver el badge de arriba).

| Sistema | Línea de comandos (`scan.py`, `url-scan.py`, `php_sec.py`) | Servidor local + bookmarklet | Servicio automático |
|---|---|---|---|
| **Linux** | Probado (CI y uso real en Arch Linux) | Probado a mano en Firefox | systemd (`examples/php-sec.service`) |
| **Windows** | Probado en CI (`windows-latest`) | **No probado**: `serve.py` es Python estándar y debería funcionar, pero no se ha ejecutado en Windows con Firefox | No incluido; arranca `serve.py` a mano o con el Programador de tareas |
| **macOS** | Probado en CI (`macos-latest`) | **No probado** | No incluido |

Lo que **no** cubren las pruebas automáticas en ningún sistema: `serve.py`, el bookmarklet, `semgrep` (que en Windows nativo no está soportado oficialmente; úsalo desde WSL) y Python 3.14. El script `php-sec` (bash) es solo para Linux y macOS; en Windows usa `php_sec.py`.

La salida es siempre UTF-8, independientemente de la codificación del sistema (en Windows, la predeterminada suele ser cp1252).

## Instalación

```bash
git clone https://github.com/EDER1002/PHP-SEC.git
cd PHP-SEC
mkdir -p ~/.local/bin && ln -sf "$PWD/php-sec" ~/.local/bin/php-sec
```

## Uso

```bash
php-sec /ruta/al/proyecto            # código fuente
php-sec https://tu-sitio.com         # URL en vivo
echo '<?php eval($_GET["x"]); ?>' | php-sec -   # texto por stdin
```

En cualquier sistema, incluido Windows, puedes usar el lanzador en Python (hace lo mismo que `php-sec`):

```bash
python php_sec.py /ruta/al/proyecto
python php_sec.py https://tu-sitio.com
```

Ejemplo de salida:

```json
{
  "project": "<stdin>",
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0 },
  "total": 1,
  "findings": [
    { "id": "PHP-EVAL", "severity": "critical", "category": "eval", "tool": "grep-rules",
      "file": "<stdin>", "line": 1, "snippet": "<?php eval($_GET[\"x\"]); ?>",
      "description": "Ejecucion dinamica", "cwe": "CWE-95", "remediation": "Revisar manualmente" }
  ]
}
```

## Integración con Firefox

1. **Servidor local** (escucha solo en `127.0.0.1:8765`). Para dejarlo como servicio de usuario de systemd, copia `examples/php-sec.service` a `~/.config/systemd/user/`, ajusta la ruta de `ExecStart` y ejecuta:
   ```bash
   systemctl --user daemon-reload
   systemctl --user enable --now php-sec.service
   ```
   El archivo de ejemplo es solo una plantilla mínima; ajústalo a tu sistema. Para una prueba rápida basta con `python3 serve.py`.
2. **Marcador:** crea un marcador nuevo y pega como URL el contenido de `bookmarklet/bookmarklet.url.txt` (una sola línea que empieza con `javascript:`). El código legible está en `bookmarklet/bookmarklet.src.js`.
3. Abre un sitio tuyo y haz clic en el marcador. Un segundo clic cierra el panel.

Si la página define una CSP estricta (`connect-src`), el navegador bloqueará la petición al servidor local; en ese caso usa la línea de comandos.

## Modelo de seguridad del servidor local

El servidor está pensado para que **solo la propia página escaneada** pueda usarlo:

- Escucha únicamente en `127.0.0.1` y exige un `Host` local (anti DNS-rebinding).
- Exige la cabecera `Origin` y que coincida con el sitio que se escanea. Una web ajena, una `<img>` o un formulario no pueden disparar escaneos ni leer resultados.
- Responde con el `Origin` validado en `Access-Control-Allow-Origin`, nunca con `*`.
- Solo acepta URLs `http`/`https`, sin credenciales y de longitud limitada.
- Sin shell: ejecuta el escáner con lista de argumentos, `timeout` y salida acotada.
- Máximo 2 escaneos simultáneos.

Además, `url-scan.py` solo sigue redirecciones dentro del mismo host y no admite `file://`, `ftp://` ni `data:`. `scan.py` no usa shell, ejecuta `composer audit --no-plugins --no-scripts` y `semgrep --metrics=off`, para que analizar un proyecto ajeno no ejecute su código, e ignora symlinks y archivos de más de 2 MB. El panel del bookmarklet pinta los resultados con `textContent`, sin `innerHTML`.

## Falsos positivos que ya se manejan

- **Soft-404:** hay sitios que responden `200` a cualquier ruta. El escáner pide antes una ruta inexistente al azar y descarta las respuestas casi idénticas a esa página genérica (similitud ≥ 0.9). Un archivo sensible real se sigue detectando.
- `composer.json` y `composer.lock` se reportan como `low`, porque son públicos en muchos proyectos de código abierto.

## Pruebas

```bash
python3 -m unittest discover -s tests
```

Las pruebas levantan servidores HTTP reales en local, sin mocks, y ejecutan los scripts como subprocesos. Cubren los sitios soft-404, la severidad de `composer.*`, el texto con tildes y `ñ` bajo una codificación antigua (como la de Windows), el lanzador `php_sec.py` y la integración con `composer`. No hay tests automáticos de `serve.py` ni del bookmarklet: se probaron a mano.

## Limitaciones

- El análisis de código es por **líneas con expresiones regulares**: no sigue variables entre líneas ni entre archivos, así que puede dar falsos positivos y falsos negativos. Trata los hallazgos como pistas por revisar, no como veredictos.
- El modo URL no autentica ni renderiza JavaScript: solo ve lo que responde el servidor.

## Licencia

GPL-2.0, ver [LICENSE](LICENSE).
