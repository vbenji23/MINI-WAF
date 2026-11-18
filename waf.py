#!/usr/bin/env python3
"""
MiniWAF - Web Application Firewall en reverse proxy (Python, sans dependance).

Le WAF se place devant un site web :
    Client  --->  MiniWAF (:8080)  --->  Site protege (:5000)

Il inspecte chaque requete HTTP et bloque :
  - Injections SQL, XSS, path traversal, injections de commandes, LFI/RFI
  - Scanners connus (sqlmap, nikto, nmap...) via le User-Agent
  - Flood : trop de requetes par IP (HTTP 429)
  - Corps de requete trop gros (HTTP 413)
Une IP qui declenche trop d'alertes est bannie temporairement.
Chaque evenement est journalise en JSON dans waf.log.
"""

import argparse
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ------------------------------------------------------------------ config
RATE_LIMIT = 30          # requetes max...
RATE_WINDOW = 10         # ...par fenetre de X secondes
BAN_THRESHOLD = 5        # attaques avant bannissement
BAN_TIME = 300           # duree du ban (secondes)
MAX_BODY = 1_000_000     # 1 Mo max
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}

# ------------------------------------------------------------------ regles
RULES = {
    "SQLi": [
        r"(?i)\bunion\b.{0,20}\bselect\b",
        r"(?i)\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)'\s*(or|and)\s+'[^']*'\s*=\s*'",
        r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(",
        r"(?i);\s*(drop|delete|insert|update)\s",
        r"(?i)information_schema",
        r"'\s*--",
    ],
    "XSS": [
        r"(?i)<\s*script",
        r"(?i)javascript\s*:",
        r"(?i)\bon(error|load|click|mouseover|focus)\s*=",
        r"(?i)<\s*(iframe|svg|img|body)\b[^>]*\b(src|on\w+)\s*=",
        r"(?i)document\.(cookie|location)",
    ],
    "Path traversal": [
        r"\.\./",
        r"\.\.\\",
        r"(?i)/etc/(passwd|shadow|hosts)",
        r"(?i)c:\\windows",
    ],
    "Command injection": [
        r"(?i)[;|&`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
        r"\$\([^)]*\)",
    ],
    "LFI/RFI": [
        r"(?i)(php|file|data|expect)://",
        r"(?i)=\s*https?://[^&]*\.(txt|php)\b",
    ],
}
COMPILED = {cat: [re.compile(p) for p in pats] for cat, pats in RULES.items()}
BAD_AGENTS = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|hydra)")


def deep_decode(value, rounds=3):
    """Decode l'URL plusieurs fois pour dejouer le double encodage (%253C -> %3C -> <)."""
    for _ in range(rounds):
        decoded = urllib.parse.unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def inspect(text):
    """Retourne (categorie, motif) si une regle matche, sinon None."""
    text = deep_decode(text)
    for category, patterns in COMPILED.items():
        for pattern in patterns:
            if pattern.search(text):
                return category, pattern.pattern
    return None


# ------------------------------------------------------------------ etat partage
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = defaultdict(deque)   # ip -> timestamps
        self.strikes = defaultdict(int)      # ip -> nb d'attaques
        self.banned = {}                     # ip -> fin du ban
        self.stats = defaultdict(int)

    def is_banned(self, ip):
        with self.lock:
            end = self.banned.get(ip)
            if end and end > time.time():
                return True
            self.banned.pop(ip, None)
            return False

    def rate_exceeded(self, ip):
        now = time.time()
        with self.lock:
            q = self.requests[ip]
            while q and now - q[0] > RATE_WINDOW:
                q.popleft()
            q.append(now)
            return len(q) > RATE_LIMIT

    def add_strike(self, ip):
        """Ajoute une alerte ; retourne True si l'IP vient d'etre bannie."""
        with self.lock:
            self.strikes[ip] += 1
            if self.strikes[ip] >= BAN_THRESHOLD:
                self.banned[ip] = time.time() + BAN_TIME
                self.strikes[ip] = 0
                return True
            return False


STATE = State()
LOG_LOCK = threading.Lock()


def log_event(**event):
    event["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    line = json.dumps(event, ensure_ascii=False)
    with LOG_LOCK:
        with open("waf.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line)


# ------------------------------------------------------------------ proxy
class WAFHandler(BaseHTTPRequestHandler):
    backend = "http://127.0.0.1:5000"
    monitor_only = False
    server_version = "MiniWAF"
    sys_version = ""

    def log_message(self, *args):
        pass  # on utilise notre propre journal

    def client_ip(self):
        return self.client_address[0]

    # --- reponses de blocage
    def deny(self, code, reason, incident=None):
        body = (f"<h1>{code} - Requete bloquee par MiniWAF</h1>"
                f"<p>{reason}</p>"
                + (f"<p>ID incident : <code>{incident}</code></p>" if incident else "")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- point d'entree pour toutes les methodes
    def handle_any(self):
        ip = self.client_ip()
        STATE.stats["total"] += 1

        if STATE.is_banned(ip):
            STATE.stats["banned"] += 1
            return self.deny(403, "Ton adresse IP est temporairement bannie.")

        if STATE.rate_exceeded(ip):
            STATE.stats["rate_limited"] += 1
            log_event(ip=ip, action="rate_limit", path=self.path)
            return self.deny(429, "Trop de requetes, ralentis.")

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            log_event(ip=ip, action="body_too_large", size=length)
            return self.deny(413, "Corps de requete trop volumineux.")
        body = self.rfile.read(length) if length else b""

        # --- inspection : URL, corps, User-Agent, cookies, referer
        ua = self.headers.get("User-Agent", "")
        finding = None
        if BAD_AGENTS.search(ua):
            finding = ("Scanner", BAD_AGENTS.search(ua).group(0))
        else:
            targets = [self.path, body.decode(errors="replace"),
                       self.headers.get("Cookie", ""), self.headers.get("Referer", "")]
            for target in targets:
                finding = inspect(target)
                if finding:
                    break

        if finding:
            incident = uuid.uuid4().hex[:8]
            banned_now = STATE.add_strike(ip)
            STATE.stats["blocked"] += 1
            log_event(ip=ip, action="detected" if self.monitor_only else "blocked",
                      category=finding[0], rule=finding[1], method=self.command,
                      path=self.path[:300], user_agent=ua[:150], incident=incident)
            if banned_now:
                log_event(ip=ip, action="banned", duration=BAN_TIME)
            if not self.monitor_only:
                return self.deny(403, f"Attaque detectee : {finding[0]}", incident)

        self.forward(body)

    # --- transfert vers le site protege
    def forward(self, body):
        url = self.backend.rstrip("/") + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["X-Forwarded-For"] = self.client_ip()
        req = urllib.request.Request(url, data=body or None, headers=headers, method=self.command)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as e:
            resp = e  # 404, 500... : on renvoie la reponse du backend telle quelle
        except (urllib.error.URLError, TimeoutError):
            return self.deny(502, "Le site protege est injoignable.")

        data = resp.read()
        self.send_response(resp.status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP_BY_HOP and k.lower() != "server":
                self.send_header(k, v)
        # En-tetes de securite ajoutes par le WAF
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any


def main():
    parser = argparse.ArgumentParser(description="MiniWAF - reverse proxy de securite")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--backend", default="http://127.0.0.1:5000", help="URL du site a proteger")
    parser.add_argument("--monitor", action="store_true", help="mode detection seule (ne bloque rien)")
    args = parser.parse_args()

    WAFHandler.backend = args.backend
    WAFHandler.monitor_only = args.monitor
    server = ThreadingHTTPServer((args.listen, args.port), WAFHandler)
    mode = "DETECTION SEULE" if args.monitor else "BLOCAGE"
    print(f"[MiniWAF] {args.listen}:{args.port} -> {args.backend}  (mode {mode})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MiniWAF] Arret. Statistiques :", dict(STATE.stats))


if __name__ == "__main__":
    main()
