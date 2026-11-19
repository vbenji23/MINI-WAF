#!/usr/bin/env python3
"""
MiniWAF v2 - Web Application Firewall en reverse proxy (Python, sans dependance).

    Client  --->  MiniWAF (:8080)  --->  Site protege (:5000)
                     |
                     +--> waf.log (JSON)   +--> tableau de bord /__waf/

Fonctionnement :
  1. Chaque requete est normalisee (decodage URL multiple, entites HTML,
     commentaires SQL, octets nuls) pour dejouer les techniques d'evasion.
  2. Les regles de rules.json sont appliquees sur l'URL, le corps et les en-tetes.
  3. Chaque regle qui matche ajoute des points : la requete est bloquee si le
     score total atteint le seuil (anomaly scoring, comme l'OWASP Core Rule Set).
  4. Une IP qui cumule trop d'attaques est bannie temporairement.
"""

import argparse
import hmac
import html
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "2.0"

# En-tetes propres a une connexion, a ne pas retransmettre
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailers", "transfer-encoding", "upgrade", "host", "content-length"}
# En-tetes du backend qui revelent sa technologie (fingerprinting)
LEAKY_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-runtime"}
# En-tetes client qu'on n'inspecte pas (trop de faux positifs, peu de risque)
NOT_INSPECTED = {"host", "content-length", "content-type", "accept", "accept-encoding",
                 "accept-language", "connection", "cache-control", "upgrade-insecure-requests"}

DEFAULT_CONFIG = {
    "listen": "127.0.0.1",
    "port": 8080,
    "backend": "http://127.0.0.1:5000",
    "backend_timeout": 10,
    "mode": "block",                       # "block" ou "monitor"
    "anomaly_threshold": 5,
    "rate_limit": {"requests": 30, "window": 10},
    "ban": {"strikes": 5, "duration": 300},
    "max_body": 1_000_000,
    "whitelist_ips": [],
    "whitelist_paths": [],
    "trusted_proxies": [],
    "hide_backend_errors": True,
    "dashboard_token": "",
    "dashboard_ips": ["127.0.0.1", "::1"],
    "log_file": "waf.log",
    "security_headers": {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Referrer-Policy": "no-referrer"},
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_config(path=None):
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # copie profonde
    if path and os.path.exists(path):
        config.update(load_json(path))
    if not config["dashboard_token"]:
        config["dashboard_token"] = secrets.token_urlsafe(16)
    return config


def setup_logger(path, console=True):
    logger = logging.getLogger("miniwaf")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    file_handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    if console:
        logger.addHandler(logging.StreamHandler())
    return logger


# ====================================================================== normalisation
SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
SPACES = re.compile(r"\s+")


def normalize(value, rounds=4):
    """Met la valeur sous forme canonique avant l'analyse.

    %253Cscript%253E   -> <script>      (double encodage URL)
    &lt;script&gt;     -> <script>      (entites HTML)
    UNION/**/SELECT    -> UNION SELECT  (commentaires SQL)
    """
    for _ in range(rounds):
        decoded = html.unescape(urllib.parse.unquote_plus(value))
        if decoded == value:
            break
        value = decoded
    value = value.replace("\x00", "")
    value = SQL_COMMENT.sub(" ", value)
    return SPACES.sub(" ", value)


# ====================================================================== regles
class RuleSet:
    """Charge rules.json et le recharge automatiquement s'il est modifie."""

    def __init__(self, path, logger=None):
        self.path = path
        self.logger = logger or logging.getLogger("miniwaf")
        self.lock = threading.Lock()
        self.rules, self.bad_agents, self.mtime = [], None, 0
        self.reload()

    def reload(self):
        data = load_json(self.path)
        rules = [{**r, "regex": re.compile(r["pattern"], re.I)} for r in data["rules"]]
        agents = data.get("bad_agents", [])
        agents_re = re.compile("|".join(map(re.escape, agents)), re.I) if agents else None
        with self.lock:
            self.rules, self.bad_agents = rules, agents_re
        self.mtime = os.path.getmtime(self.path)

    def maybe_reload(self):
        try:
            mtime = os.path.getmtime(self.path)
            if mtime != self.mtime:
                self.reload()
                self.logger.info(json.dumps({"action": "rules_reloaded", "rules": len(self.rules)}))
        except (OSError, ValueError, KeyError, re.error) as e:
            # Fichier invalide : on garde les anciennes regles et on ne reessaie qu'a la prochaine modif
            self.mtime = os.path.getmtime(self.path) if os.path.exists(self.path) else self.mtime
            self.logger.error(json.dumps({"action": "rules_error", "error": str(e)}))

    def check_agent(self, user_agent):
        with self.lock:
            agents = self.bad_agents
        match = agents.search(user_agent) if agents else None
        return match.group(0) if match else None

    def scan(self, zones):
        """zones = {"url": "...", "body": "...", ...}. Retourne (score, correspondances)."""
        with self.lock:
            rules = self.rules
        matches, seen = [], set()
        for zone, raw in zones.items():
            if not raw:
                continue
            text = normalize(raw)
            for rule in rules:
                if rule["id"] not in seen and rule["regex"].search(text):
                    seen.add(rule["id"])
                    matches.append({"id": rule["id"], "category": rule["category"],
                                    "score": rule["score"], "zone": zone,
                                    "description": rule["description"]})
        return sum(m["score"] for m in matches), matches


# ====================================================================== etat partage
class State:
    def __init__(self, config):
        self.cfg = config
        self.lock = threading.Lock()
        self.requests = defaultdict(deque)   # ip -> horodatages des requetes
        self.strikes = defaultdict(int)      # ip -> nb d'attaques
        self.banned = {}                     # ip -> fin du ban
        self.stats = Counter()
        self.categories = Counter()
        self.attackers = Counter()
        self.events = deque(maxlen=100)
        self.started = time.time()

    def count(self, key):
        with self.lock:
            self.stats[key] += 1

    def is_banned(self, ip):
        with self.lock:
            end = self.banned.get(ip)
            if end and end > time.time():
                return True
            self.banned.pop(ip, None)
            return False

    def rate_exceeded(self, ip):
        now = time.time()
        limit, window = self.cfg["rate_limit"]["requests"], self.cfg["rate_limit"]["window"]
        with self.lock:
            q = self.requests[ip]
            while q and now - q[0] > window:
                q.popleft()
            q.append(now)
            if len(self.requests) > 10_000:  # evite une fuite memoire avec beaucoup d'IP
                for old_ip in [k for k, v in self.requests.items() if not v or now - v[-1] > window]:
                    del self.requests[old_ip]
            return len(q) > limit

    def add_strike(self, ip, categories):
        """Comptabilise une attaque. Retourne True si l'IP vient d'etre bannie."""
        with self.lock:
            self.attackers[ip] += 1
            self.categories.update(categories)
            self.strikes[ip] += 1
            if self.strikes[ip] >= self.cfg["ban"]["strikes"]:
                self.banned[ip] = time.time() + self.cfg["ban"]["duration"]
                self.strikes[ip] = 0
                return True
            return False

    def add_event(self, event):
        with self.lock:
            self.events.append(event)

    def snapshot(self):
        now = time.time()
        with self.lock:
            return {
                "version": VERSION,
                "mode": self.cfg["mode"],
                "uptime": int(now - self.started),
                "stats": dict(self.stats),
                "categories": dict(self.categories.most_common()),
                "top_attackers": self.attackers.most_common(10),
                "banned": {ip: int(end - now) for ip, end in self.banned.items() if end > now},
                "events": list(reversed(self.events)),
            }


# ====================================================================== pages HTML
BLOCK_PAGE = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>{code} - MiniWAF</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0}}
.box{{background:#1e293b;padding:2rem 3rem;border-radius:12px;border-left:6px solid #ef4444;max-width:520px}}
h1{{margin:0 0 .5rem;color:#f87171}}code{{background:#0f172a;padding:2px 6px;border-radius:4px}}</style></head>
<body><div class="box"><h1>{code} - Requete bloquee</h1><p>{reason}</p>{incident}
<p style="opacity:.6">Protege par MiniWAF</p></div></body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>MiniWAF - Tableau de bord</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
h1{margin:0 0 4px}h2{font-size:1rem;color:#94a3b8;margin:24px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:#1e293b;border-radius:10px;padding:14px}.card b{display:block;font-size:1.8rem}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden;font-size:.85rem}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #334155;word-break:break-all}
th{background:#334155}.blocked{color:#f87171}.suspicious{color:#fbbf24}.banned{color:#c084fc}
.muted{color:#94a3b8}
</style></head><body>
<h1>MiniWAF</h1><div class="muted" id="info">Chargement...</div>
<div class="cards" id="cards"></div>
<div class="grid">
 <div><h2>Attaques par categorie</h2><table id="cats"></table></div>
 <div><h2>Top attaquants</h2><table id="top"></table></div>
 <div><h2>IP bannies</h2><table id="bans"></table></div>
</div>
<h2>Derniers evenements</h2><table id="events"></table>
<script>
// Les donnees affichees viennent des attaquants : on utilise textContent (jamais innerHTML)
// pour ne pas creer une faille XSS dans le tableau de bord lui-meme.
const token = new URLSearchParams(location.search).get("token") || "";
function fill(id, headers, rows) {
  const t = document.getElementById(id); t.replaceChildren();
  const h = t.insertRow(); headers.forEach(x => { const c = document.createElement("th"); c.textContent = x; h.appendChild(c); });
  if (!rows.length) { const r = t.insertRow(); const c = r.insertCell(); c.colSpan = headers.length; c.textContent = "Aucun"; c.className = "muted"; }
  rows.forEach(row => { const r = t.insertRow(); row.forEach(v => { const c = r.insertCell(); c.textContent = v ?? ""; });
    if (row.cls) r.className = row.cls; });
}
async function refresh() {
  try {
    const res = await fetch("/__waf/api", {headers: {"X-WAF-Token": token}});
    const d = await res.json(); const s = d.stats;
    document.getElementById("info").textContent = `v${d.version} - mode ${d.mode} - actif depuis ${d.uptime}s`;
    const cards = [["Requetes", s.total], ["Autorisees", s.allowed], ["Bloquees", s.blocked],
                   ["Suspectes", s.suspicious], ["Rate limit", s.rate_limited], ["Rejets ban", s.banned_hits]];
    const box = document.getElementById("cards"); box.replaceChildren();
    cards.forEach(([k, v]) => { const c = document.createElement("div"); c.className = "card";
      const b = document.createElement("b"); b.textContent = v || 0; c.append(b, k); box.appendChild(c); });
    fill("cats", ["Categorie", "Nb"], Object.entries(d.categories));
    fill("top", ["IP", "Attaques"], d.top_attackers);
    fill("bans", ["IP", "Reste (s)"], Object.entries(d.banned));
    fill("events", ["Heure", "IP", "Action", "Categorie", "Score", "Chemin"], d.events.map(e => {
      const row = [e.time, e.ip, e.action, (e.categories || []).join(", "), e.score, e.path]; row.cls = e.action; return row; }));
  } catch (e) { document.getElementById("info").textContent = "Erreur de connexion a l'API"; }
}
refresh(); setInterval(refresh, 2000);
</script></body></html>"""


# ====================================================================== proxy
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Un reverse proxy ne suit pas les redirections : il les renvoie au client."""
    def redirect_request(self, *args, **kwargs):
        return None


# ProxyHandler({}) : on ignore les proxys systeme pour joindre le backend directement
OPENER = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


class WAFServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config, rules, logger=None):
        self.cfg = config
        self.rules = rules
        self.state = State(config)
        self.logger = logger or logging.getLogger("miniwaf")
        super().__init__((config["listen"], config["port"]), WAFHandler)

    def event(self, **event):
        event["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.state.add_event(event)
        self.logger.info(json.dumps(event, ensure_ascii=False))


class WAFHandler(BaseHTTPRequestHandler):
    server_version = "MiniWAF"
    sys_version = ""

    def log_message(self, *args):
        pass  # on utilise notre propre journal JSON

    # ------------------------------------------------------------ utilitaires
    @property
    def cfg(self):
        return self.server.cfg

    def client_ip(self):
        """X-Forwarded-For n'est cru que s'il vient d'un proxy de confiance (sinon il est falsifiable)."""
        ip = self.client_address[0]
        if ip in self.cfg["trusted_proxies"]:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return ip

    def respond(self, code, body, content_type="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in {**self.cfg["security_headers"], **(headers or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def deny(self, code, reason, incident=None, headers=None):
        extra = f"<p>ID incident : <code>{incident}</code></p>" if incident else ""
        self.respond(code, BLOCK_PAGE.format(code=code, reason=html.escape(reason), incident=extra),
                     headers=headers)

    # ------------------------------------------------------------ point d'entree
    def handle_any(self):
        server, state = self.server, self.server.state
        ip = self.client_ip()
        path = urllib.parse.urlsplit(self.path).path
        state.count("total")

        if path.startswith("/__waf"):
            return self.dashboard(ip, path)

        server.rules.maybe_reload()
        whitelisted_ip = ip in self.cfg["whitelist_ips"]

        if not whitelisted_ip and state.is_banned(ip):
            state.count("banned_hits")
            return self.deny(403, "Ton adresse IP est temporairement bannie.")

        # --- Protection contre le HTTP request smuggling
        if "Transfer-Encoding" in self.headers:
            server.event(ip=ip, action="blocked", categories=["Smuggling"], path=self.path[:200],
                         reason="Transfer-Encoding refuse")
            state.count("blocked")
            return self.deny(400, "Transfer-Encoding non supporte.")
        raw_length = self.headers.get("Content-Length", "0")
        if not raw_length.isdigit():
            state.count("blocked")
            return self.deny(400, "Content-Length invalide.")
        length = int(raw_length)
        if length > self.cfg["max_body"]:
            server.event(ip=ip, action="blocked", categories=["Body too large"], path=self.path[:200])
            state.count("blocked")
            return self.deny(413, "Corps de requete trop volumineux.")
        body = self.rfile.read(length) if length else b""

        if whitelisted_ip or any(path.startswith(p) for p in self.cfg["whitelist_paths"]):
            state.count("whitelisted")
            return self.forward(ip, body)

        if state.rate_exceeded(ip):
            state.count("rate_limited")
            server.event(ip=ip, action="rate_limit", path=self.path[:200])
            return self.deny(429, "Trop de requetes, ralentis.",
                             headers={"Retry-After": str(self.cfg["rate_limit"]["window"])})

        # --- Analyse
        zones = {"url": self.path, "body": body.decode("utf-8", errors="replace")}
        for key, value in self.headers.items():
            if key.lower() not in NOT_INSPECTED:
                zones[f"header:{key}"] = value
        score, matches = server.rules.scan(zones)

        user_agent = self.headers.get("User-Agent", "")
        scanner = server.rules.check_agent(user_agent)
        if scanner:
            score += self.cfg["anomaly_threshold"]
            matches.append({"id": 9001, "category": "Scanner", "score": self.cfg["anomaly_threshold"],
                            "zone": "header:User-Agent", "description": f"Outil detecte : {scanner}"})

        if matches:
            categories = sorted({m["category"] for m in matches})
            info = dict(ip=ip, score=score, categories=categories, method=self.command,
                        path=self.path[:300], user_agent=user_agent[:150],
                        rules=[f'{m["id"]} {m["description"]} ({m["zone"]})' for m in matches])

            if score >= self.cfg["anomaly_threshold"]:
                incident = uuid.uuid4().hex[:8]
                monitor = self.cfg["mode"] == "monitor"
                state.count("detected" if monitor else "blocked")
                server.event(action="detected" if monitor else "blocked", incident=incident, **info)
                if state.add_strike(ip, categories):
                    server.event(ip=ip, action="banned", duration=self.cfg["ban"]["duration"])
                if not monitor:
                    return self.deny(403, f"Attaque detectee : {', '.join(categories)}", incident)
            else:
                # Score sous le seuil : on laisse passer mais on garde une trace
                state.count("suspicious")
                server.event(action="suspicious", **info)

        self.forward(ip, body)

    # ------------------------------------------------------------ transfert vers le backend
    def forward(self, ip, body):
        url = self.cfg["backend"].rstrip("/") + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["X-Forwarded-For"] = ip
        headers["X-Forwarded-Proto"] = "http"
        request = urllib.request.Request(url, data=body or None, headers=headers, method=self.command)
        try:
            response = OPENER.open(request, timeout=self.cfg["backend_timeout"])
        except urllib.error.HTTPError as e:
            response = e  # 3xx/4xx/5xx du backend : on les relaie
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            self.server.event(ip=ip, action="backend_down", path=self.path[:200])
            return self.deny(502, "Le site protege est injoignable.")

        with response:
            data = response.read()
            status = response.getcode()
            backend_headers = response.headers

        # Masque les pages d'erreur du backend (traces, chemins, versions...)
        if status >= 500 and self.cfg["hide_backend_errors"]:
            self.server.event(ip=ip, action="backend_error_hidden", status=status, path=self.path[:200])
            self.server.state.count("allowed")
            return self.deny(status, "Erreur interne du serveur.")

        self.send_response(status)
        sent = set()
        for key, value in backend_headers.items():
            if key.lower() not in HOP_BY_HOP and key.lower() not in LEAKY_HEADERS:
                self.send_header(key, value)
                sent.add(key.lower())
        for key, value in self.cfg["security_headers"].items():
            if key.lower() not in sent:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.server.state.count("allowed")

    # ------------------------------------------------------------ tableau de bord
    def dashboard(self, ip, path):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        given = self.headers.get("X-WAF-Token") or query.get("token", [""])[0]
        token = self.cfg["dashboard_token"]
        # compare_digest : comparaison en temps constant (pas de timing attack sur le token)
        if ip not in self.cfg["dashboard_ips"] or not hmac.compare_digest(given.encode(), token.encode()):
            self.server.event(ip=ip, action="dashboard_denied", path=path)
            return self.deny(403, "Acces au tableau de bord refuse.")
        if path == "/__waf/api":
            return self.respond(200, json.dumps(self.server.state.snapshot(), ensure_ascii=False),
                                "application/json; charset=utf-8", {"Cache-Control": "no-store"})
        csp = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"
        self.respond(200, DASHBOARD_HTML, headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any


# ====================================================================== lancement
def main():
    parser = argparse.ArgumentParser(description="MiniWAF - reverse proxy de securite")
    parser.add_argument("--config", default=os.path.join(BASE_DIR, "config.json"))
    parser.add_argument("--rules", default=os.path.join(BASE_DIR, "rules.json"))
    parser.add_argument("--port", type=int, help="remplace le port de la config")
    parser.add_argument("--backend", help="remplace l'URL du backend")
    parser.add_argument("--monitor", action="store_true", help="detection seule, ne bloque rien")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.port:
        config["port"] = args.port
    if args.backend:
        config["backend"] = args.backend
    if args.monitor:
        config["mode"] = "monitor"

    logger = setup_logger(config["log_file"])
    rules = RuleSet(args.rules, logger)
    server = WAFServer(config, rules, logger)

    host, port = server.server_address[:2]
    print(f"[MiniWAF v{VERSION}] {host}:{port} -> {config['backend']}  "
          f"(mode {config['mode']}, {len(rules.rules)} regles, seuil {config['anomaly_threshold']})")
    print(f"[MiniWAF] Tableau de bord : http://{host}:{port}/__waf/?token={config['dashboard_token']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MiniWAF] Arret. Statistiques :", dict(server.state.stats))
        server.server_close()


if __name__ == "__main__":
    main()
