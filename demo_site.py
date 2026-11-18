#!/usr/bin/env python3
"""Petit site de demo VOLONTAIREMENT vulnerable (XSS reflechie), a proteger avec MiniWAF.
Ne jamais l'exposer sur Internet."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Demo(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        # Faille XSS : la recherche est renvoyee sans echappement
        html = f"""<h1>Boutique demo</h1>
<form><input name="q" value=""><button>Rechercher</button></form>
<p>Resultats pour : {q}</p>"""
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_POST = do_GET


if __name__ == "__main__":
    print("Site demo sur http://127.0.0.1:5000 (vulnerable, local uniquement)")
    HTTPServer(("127.0.0.1", 5000), Demo).serve_forever()
