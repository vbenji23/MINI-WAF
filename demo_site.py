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
  /product?id=...    erreur SQL affichee dans une page 200 (fuite d'informations)
  /orders            commandes affichant les numeros de carte complets (fuite de donnees)
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

LAYOUT = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Boutique demo</title>
<style>body{{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px}}
nav a{{margin-right:12px}}pre{{background:#f1f5f9;padding:10px}}</style></head><body>
<nav><a href="/">Accueil</a><a href="/search?q=switch">Recherche</a><a href="/file?name=cgv.txt">CGV</a>
<a href="/ping?host=127.0.0.1">Ping</a><a href="/product?id=abc">Produit</a><a href="/orders">Commandes</a>
<a href="/error">Erreur</a></nav>{content}</body></html>"""


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
        elif path == "/product":
            pid = p.get("id", "1")
            if pid.isdigit():
                self.page(f"<h1>Produit {pid}</h1><p>Switch 24 ports - 89 euros</p>")
            else:
                # FAILLE : l'erreur SQL brute est affichee a l'utilisateur
                self.page("<h1>Produit</h1><pre>You have an error in your SQL syntax; check the manual "
                          f"that corresponds to your MySQL server version near '{pid}' at line 1</pre>")
        elif path == "/orders":
            # FAILLE : numeros de carte complets affiches (numeros de test, pas de vraies cartes)
            self.page("""<h1>Mes commandes</h1><table border="1" cellpadding="6">
<tr><th>Commande</th><th>Carte</th><th>Montant</th></tr>
<tr><td>#1042</td><td>4111 1111 1111 1111</td><td>89 euros</td></tr>
<tr><td>#1043</td><td>5555-5555-5555-4444</td><td>149 euros</td></tr>
<tr><td>#1044</td><td>Reference 1234567890123</td><td>12 euros</td></tr></table>""")
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
