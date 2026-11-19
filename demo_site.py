#!/usr/bin/env python3
"""
Site de demo VOLONTAIREMENT vulnerable, a proteger avec MiniWAF.
Les failles sont simulees (aucun vrai fichier lu, aucune vraie commande executee).
NE JAMAIS L'EXPOSER SUR INTERNET.

  /                  accueil
  /search?q=...      XSS reflechie (la recherche est renvoyee sans echappement)
  /login   (POST)    "SQL" construit par concatenation, affiche a l'ecran
  /file?name=...     path traversal simule
  /ping?host=...     injection de commande simulee
  /error             erreur 500 avec trace (fuite d'informations)
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

LAYOUT = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Boutique demo</title>
<style>body{{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px}}
nav a{{margin-right:12px}}pre{{background:#f1f5f9;padding:10px}}</style></head><body>
<nav><a href="/">Accueil</a><a href="/search?q=switch">Recherche</a><a href="/file?name=cgv.txt">CGV</a>
<a href="/ping?host=127.0.0.1">Ping</a><a href="/error">Erreur</a></nav>{content}</body></html>"""


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29 (Ubuntu) PHP/7.2.24"   # fausse banniere : le WAF doit la masquer

    def log_message(self, *args):
        pass

    def page(self, content, status=200):
        data = LAYOUT.format(content=content).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def params(self):
        url = urlsplit(self.path)
        params = parse_qs(url.query)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            params.update(parse_qs(self.rfile.read(length).decode(errors="replace")))
        return url.path, {k: v[0] for k, v in params.items()}

    def do_GET(self):
        path, p = self.params()
        if path == "/":
            self.page("""<h1>Boutique reseau</h1><p>Materiel reseau pas cher.</p>
<h2>Connexion</h2><form method="post" action="/login">
<input name="user" placeholder="utilisateur"> <input name="pass" type="password" placeholder="mot de passe">
<button>Connexion</button></form>""")
        elif path == "/search":
            q = p.get("q", "")
            # FAILLE XSS : q est insere tel quel dans la page
            self.page(f"<h1>Recherche</h1><form><input name='q'><button>OK</button></form>"
                      f"<p>Resultats pour : {q}</p>")
        elif path == "/login":
            user, pwd = p.get("user", ""), p.get("pass", "")
            # FAILLE SQLi : requete construite par concatenation
            query = f"SELECT * FROM users WHERE login='{user}' AND password='{pwd}'"
            self.page(f"<h1>Connexion</h1><p>Requete executee :</p><pre>{query}</pre>"
                      "<p>Identifiants incorrects.</p>")
        elif path == "/file":
            name = p.get("name", "cgv.txt")
            # FAILLE path traversal (simulee) : le nom n'est pas filtre
            self.page(f"<h1>Fichier</h1><pre>open('/var/www/public/{name}')</pre>")
        elif path == "/ping":
            host = p.get("host", "127.0.0.1")
            # FAILLE injection de commande (simulee)
            self.page(f"<h1>Ping</h1><pre>os.system('ping -c 1 {host}')</pre>")
        elif path == "/error":
            self.page("""<h1>Internal Server Error</h1><pre>Traceback (most recent call last):
  File "/var/www/app/views.py", line 42, in login
    cursor.execute(query)
psycopg2.errors.SyntaxError: DB=prod_shop user=admin host=10.0.0.12</pre>""", status=500)
        else:
            self.page("<h1>404</h1><p>Page introuvable.</p>", status=404)

    do_POST = do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description="Site de demo vulnerable")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    print(f"[Demo] Site vulnerable sur http://127.0.0.1:{args.port} (local uniquement)")
    HTTPServer(("127.0.0.1", args.port), DemoHandler).serve_forever()


if __name__ == "__main__":
    main()
