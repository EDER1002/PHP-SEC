#!/usr/bin/env python3
"""Lanzador multiplataforma (Windows, Linux, macOS): python php_sec.py <carpeta | URL | ->"""
import os, subprocess, sys

DIR = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    arg = argv[1] if len(argv) > 1 else "-"
    script = "url-scan.py" if arg.lower().startswith(("http://", "https://")) else "scan.py"
    return subprocess.call([sys.executable, os.path.join(DIR, script), arg])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
