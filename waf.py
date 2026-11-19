#!/usr/bin/env python3
"""
MiniWAF v4 - Web Application Firewall en reverse proxy (Python, sans dependance).

    Client  --HTTP/HTTPS-->  MiniWAF (:8080)  --->  Site protege (:5000)
                                |
                                +--> waf.log (JSON)       +--> tableau de bord /__waf/
                                +--> bans.json (bans)     +--> metriques Prometheus /__waf/metrics
                                +--> alertes Discord / Slack (webhook)

Fonctionnement :
  0. Listes d'IP (CIDR accepte) : liste noire bloquee d'office, liste blanche jamais inspectee.
  1. Controles du protocole : methode, longueur d'URL, nombre d'en-tetes, smuggling, slowloris.
  2. Chemins pieges (/.env, /.git/, /wp-admin...) : tout visiteur qui y touche est banni.
  3. Chaque requete est normalisee (decodage URL multiple, entites HTML,
     commentaires SQL, octets nuls) pour dejouer les techniques d'evasion.
  4. Les regles de rules.json sont appliquees sur l'URL, le corps et les en-tetes.
     Chaque regle ajoute des points : la requete est bloquee si le score total
     atteint le seuil (anomaly scoring, comme l'OWASP Core Rule Set).
  5. Les reponses du site sont aussi inspectees : une fuite (erreur SQL, /etc/passwd,
     cle privee...) est bloquee, et les numeros de carte bancaire sont masques.
  6. Une IP qui cumule les attaques est bannie, et la duree double a chaque recidive.
  7. Les evenements graves (ban, piege, fuite) declenchent une alerte en temps reel.
"""

import argparse
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
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
VERSION = "4.0"

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
    "rate_limit": {"requests": 60, "window": 10},
    "ban": {"strikes": 5, "duration": 300, "max_duration": 86400},
    "ban_file": "bans.json",
    "allowed_methods": ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"],
    "max_url_length": 2048,
    "max_headers": 50,
    "max_body": 1_000_000,
    "client_timeout": 30,                  # anti-slowloris : coupe les clients trop lents
    "inspect_responses": True,
    "mask_card_numbers": True,
    "max_inspect_size": 2_000_000,
    "whitelist_ips": [],
    "blocklist_ips": [],
    "whitelist_paths": [],
    "trusted_proxies": [],
    "tls": {"cert": "", "key": ""},        # renseigner pour activer le HTTPS
    "alert_webhook": "",                   # URL de webhook Discord ou Slack
    "alert_format": "discord",             # "discord", "slack" ou "json"
    "alert_on": ["banned", "trap", "leak_blocked"],
    "alert_cooldown": 60,                  # max 1 alerte par (type, IP) toutes les 60 s
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
    for handler in list(logger.handlers):   # ferme proprement les anciens fichiers de log
        handler.close()
        logger.removeHandler(handler)
    file_handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    if console:
        logger.addHandler(logging.StreamHandler())
    return logger


# ====================================================================== listes d'IP
class IPSet:
    """Liste d'adresses et de reseaux CIDR : "1.2.3.4", "10.0.0.0/8", "2001:db8::/32".

    Une entree invalide provoque une erreur au demarrage (mieux qu'une liste ignoree en silence).
    """

    def __init__(self, entries):
        self.networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]

    def __contains__(self, ip):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.networks)


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


# ====================================================================== cartes bancaires
CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def luhn_ok(digits):
    """Algorithme de Luhn : verifie qu'une suite de chiffres est un numero de carte valide."""
    total = 0
    for i, char in enumerate(reversed(digits)):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask_cards(text):
    """Remplace les numeros de carte valides par **** **** **** 1234. Retourne (texte, nb)."""
    count = 0

    def replace(match):
        nonlocal count
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            count += 1
            return "**** **** **** " + digits[-4:]
        return match.group(0)

    return CARD_RE.sub(replace, text), count


# ====================================================================== regles
class RuleSet:
    """Charge rules.json et le recharge automatiquement s'il est modifie."""

    def __init__(self, path, logger=None):
        self.path = path
        self.logger = logger or logging.getLogger("miniwaf")
        self.lock = threading.Lock()
        self.rules, self.response_rules, self.traps, self.exclusions = [], [], [], []
        self.bad_agents, self.mtime = None, 0
        self.reload()

    def reload(self):
        data = load_json(self.path)
        rules = [{**r, "regex": re.compile(r["pattern"], re.I)} for r in data["rules"]]
        response_rules = [{**r, "regex": re.compile(r["pattern"], re.I)}
                          for r in data.get("response_rules", [])]
        traps = [t.lower() for t in data.get("traps", [])]
        # Exceptions : certaines regles sont desactivees sur certains chemins (faux positifs connus)
        exclusions = [(e["path"].lower(), set(e["rules"])) for e in data.get("exclusions", [])]
        agents = data.get("bad_agents", [])
        agents_re = re.compile("|".join(map(re.escape, agents)), re.I) if agents else None
        with self.lock:
            self.rules, self.response_rules = rules, response_rules
            self.traps, self.bad_agents, self.exclusions = traps, agents_re, exclusions
        self.mtime = os.path.getmtime(self.path)

    def is_trap(self, path):
        path = normalize(path).lower()
        with self.lock:
            return any(path.startswith(trap) for trap in self.traps)

    def scan_response(self, text):
        """Retourne la premiere regle de fuite qui matche dans la reponse, sinon None."""
        with self.lock:
            rules = self.response_rules
        for rule in rules:
            if rule["regex"].search(text):
                return rule
        return None

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

    def excluded_rules(self, path):
        path = path.lower()
        with self.lock:
            exclusions = self.exclusions
        excluded = set()
        for prefix, rule_ids in exclusions:
            if path.startswith(prefix):
                excluded |= rule_ids
        return excluded

    def scan(self, zones, path=""):
        """zones = {"url": "...", "body": "...", ...}. Retourne (score, correspondances)."""
        with self.lock:
            rules = self.rules
        matches, seen = [], self.excluded_rules(path)   # regles exclues = deja "vues"
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
        self.lock = threading.RLock()        # RLock : add_strike() appelle ban() sous le verrou
        self.requests = defaultdict(deque)   # ip -> horodatages des requetes
        self.strikes = defaultdict(int)      # ip -> nb d'attaques depuis le dernier ban
        self.banned = {}                     # ip -> fin du ban (timestamp)
        self.ban_counts = Counter()          # ip -> nb de bans (pour la recidive)
        self.stats = Counter()
        self.categories = Counter()
        self.attackers = Counter()
        self.events = deque(maxlen=100)
        self.started = time.time()
        self.load_bans()

    # --- persistance des bans : ils survivent a un redemarrage du WAF
    def load_bans(self):
        path = self.cfg.get("ban_file")
        if not path or not os.path.exists(path):
            return
        try:
            data = load_json(path)
        except (OSError, ValueError):
            return
        now = time.time()
        self.banned = {ip: end for ip, end in data.get("banned", {}).items() if end > now}
        self.ban_counts = Counter(data.get("counts", {}))

    def save_bans(self):
        path = self.cfg.get("ban_file")
        if not path:
            return
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"banned": self.banned, "counts": self.ban_counts}, f, indent=2)
        os.replace(tmp, path)  # ecriture atomique : jamais de fichier a moitie ecrit

    def ban(self, ip):
        """Bannit l'IP. La duree double a chaque recidive (plafonnee). Retourne la duree."""
        cfg = self.cfg["ban"]
        with self.lock:
            self.ban_counts[ip] += 1
            duration = min(cfg["duration"] * 2 ** (self.ban_counts[ip] - 1),
                           cfg.get("max_duration", 86400))
            self.banned[ip] = time.time() + duration
            self.strikes[ip] = 0
            self.save_bans()
            return duration

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

    def unban(self, ip):
        """Debannit une IP et remet son compteur de recidive a zero. Retourne True si elle etait bannie."""
        with self.lock:
            was_banned = self.banned.pop(ip, None) is not None
            self.strikes.pop(ip, None)
            self.ban_counts.pop(ip, None)
            self.requests.pop(ip, None)   # remet aussi a zero le compteur du rate limiting
            self.save_bans()
            return was_banned

    def add_strike(self, ip, categories):
        """Comptabilise une attaque. Retourne la duree du ban si l'IP vient d'etre bannie, sinon 0."""
        with self.lock:
            self.attackers[ip] += 1
            self.categories.update(categories)
            self.strikes[ip] += 1
            if self.strikes[ip] >= self.cfg["ban"]["strikes"]:
                return self.ban(ip)
            return 0

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

    def metrics(self):
        """Format texte Prometheus, pour brancher Grafana ou un SIEM."""
        snap = self.snapshot()
        lines = ["# HELP miniwaf_events_total Evenements du WAF par type",
                 "# TYPE miniwaf_events_total counter"]
        lines += [f'miniwaf_events_total{{type="{k}"}} {v}' for k, v in sorted(snap["stats"].items())]
        lines += ["# HELP miniwaf_attacks_total Attaques par categorie",
                  "# TYPE miniwaf_attacks_total counter"]
        lines += [f'miniwaf_attacks_total{{category="{k.replace(chr(34), "")}"}} {v}'
                  for k, v in snap["categories"].items()]
        lines += ["# TYPE miniwaf_banned_ips gauge", f"miniwaf_banned_ips {len(snap['banned'])}",
                  "# TYPE miniwaf_uptime_seconds gauge", f"miniwaf_uptime_seconds {snap['uptime']}"]
        return "\n".join(lines) + "\n"


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
th{background:#334155}.blocked,.leak_blocked{color:#f87171}.suspicious{color:#fbbf24}.banned,.trap{color:#c084fc}
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
                   ["Suspectes", s.suspicious], ["Rate limit", s.rate_limited], ["Rejets ban", s.banned_hits],
                   ["Pieges", s.traps], ["Fuites bloquees", s.leaks_blocked], ["CB masquees", s.cards_masked]];
    const box = document.getElementById("cards"); box.replaceChildren();
    cards.forEach(([k, v]) => { const c = document.createElement("div"); c.className = "card";
      const b = document.createElement("b"); b.textContent = v || 0; c.append(b, k); box.appendChild(c); });
    fill("cats", ["Categorie", "Nb"], Object.entries(d.categories));
    fill("top", ["IP", "Attaques"], d.top_attackers);
    fill("bans", ["IP", "Reste (s)", ""], Object.entries(d.banned).map(([ip, sec]) => [ip, sec, ""]));
    document.querySelectorAll("#bans tr").forEach((tr, i) => {
      if (i === 0 || !tr.cells[2]) return;
      const ip = tr.cells[0].textContent, b = document.createElement("button");
      b.textContent = "Debannir"; b.onclick = () => unban(ip); tr.cells[2].appendChild(b); });
    fill("events", ["Heure", "IP", "Action", "Categorie", "Score", "Chemin"], d.events.map(e => {
      const row = [e.time, e.ip, e.action, (e.categories || []).join(", "), e.score, e.path]; row.cls = e.action; return row; }));
  } catch (e) { document.getElementById("info").textContent = "Erreur de connexion a l'API"; }
}
async function unban(ip) {
  await fetch("/__waf/unban?ip=" + encodeURIComponent(ip), {method: "POST", headers: {"X-WAF-Token": token}});
  refresh();
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
        self.nets = {key: IPSet(config[key]) for key in
                     ("whitelist_ips", "blocklist_ips", "trusted_proxies", "dashboard_ips")}
        self.alert_lock = threading.Lock()
        self.last_alerts = {}
        super().__init__((config["listen"], config["port"]), WAFHandler)

        tls = config.get("tls") or {}
        self.tls = bool(tls.get("cert"))
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # TLS 1.0/1.1 sont obsoletes
            ctx.load_cert_chain(tls["cert"], tls["key"])
            # La poignee de main TLS se fait dans le thread du client, pas dans la boucle d'accept :
            # un client lent ne bloque pas les autres.
            self.socket = ctx.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def handle_error(self, request, client_address):
        # Clients qui coupent, handshakes TLS rates, timeouts : on journalise sans afficher de trace
        self.logger.info(json.dumps({"action": "connection_error", "ip": client_address[0]}))

    def event(self, **event):
        event["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.state.add_event(event)
        self.logger.info(json.dumps(event, ensure_ascii=False))
        if self.cfg.get("alert_webhook") and event.get("action") in self.cfg.get("alert_on", []):
            self.alert(event)

    # ------------------------------------------------------------ alertes temps reel
    def alert(self, event):
        key = (event.get("action"), event.get("ip"))
        now = time.time()
        with self.alert_lock:   # anti-spam : une seule alerte par (type, IP) pendant le cooldown
            if now - self.last_alerts.get(key, 0) < self.cfg.get("alert_cooldown", 60):
                return
            self.last_alerts[key] = now
        text = (f"[MiniWAF] {event.get('action')} | IP {event.get('ip', '?')} | "
                f"{', '.join(event.get('categories', [])) or '-'} | {event.get('path', '-')}")
        fmt = self.cfg.get("alert_format", "discord")
        payload = {"discord": {"content": text}, "slack": {"text": text}}.get(fmt, event)
        # Envoi dans un thread : un webhook lent ne doit jamais ralentir le trafic
        threading.Thread(target=self._post_alert, args=(json.dumps(payload).encode(),),
                         daemon=True).start()

    def _post_alert(self, data):
        request = urllib.request.Request(self.cfg["alert_webhook"], data=data, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": f"MiniWAF/{VERSION}"})
        try:
            urllib.request.urlopen(request, timeout=5).close()
        except Exception as e:  # le WAF continue meme si l'alerte echoue
            self.logger.error(json.dumps({"action": "alert_error", "error": str(e)}))


class WAFHandler(BaseHTTPRequestHandler):
    server_version = "MiniWAF"
    sys_version = ""
    rid = "-"

    def setup(self):
        # Anti-slowloris : un client qui envoie sa requete octet par octet est deconnecte
        self.timeout = self.server.cfg["client_timeout"]
        super().setup()

    def log_message(self, *args):
        pass  # on utilise notre propre journal JSON

    # ------------------------------------------------------------ utilitaires
    @property
    def cfg(self):
        return self.server.cfg

    @property
    def security_headers(self):
        headers = dict(self.cfg["security_headers"])
        if self.server.tls:  # HSTS : le navigateur n'utilisera plus que le HTTPS pendant 1 an
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return headers

    def client_ip(self):
        """X-Forwarded-For n'est cru que s'il vient d'un proxy de confiance (sinon il est falsifiable)."""
        ip = self.client_address[0]
        if ip in self.server.nets["trusted_proxies"]:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return ip

    def respond(self, code, body, content_type="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Request-ID", self.rid)
        for key, value in {**self.security_headers, **(headers or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def deny(self, code, reason, headers=None, show_id=True):
        extra = f"<p>ID incident : <code>{self.rid}</code></p>" if show_id else ""
        self.respond(code, BLOCK_PAGE.format(code=code, reason=html.escape(reason), incident=extra),
                     headers=headers)

    # ------------------------------------------------------------ point d'entree
    def handle_any(self):
        server, state = self.server, self.server.state
        self.rid = uuid.uuid4().hex[:12]   # identifiant unique, suivi jusqu'au backend et dans les logs
        ip = self.client_ip()
        path = urllib.parse.urlsplit(self.path).path
        state.count("total")

        if path.startswith("/__waf"):
            return self.dashboard(ip, path)

        server.rules.maybe_reload()
        whitelisted_ip = ip in server.nets["whitelist_ips"]

        if not whitelisted_ip and ip in server.nets["blocklist_ips"]:
            state.count("blocklisted")
            server.event(ip=ip, action="blocklisted", path=self.path[:200], request_id=self.rid)
            return self.deny(403, "Acces refuse.")

        # --- Controles du protocole
        if self.command not in self.cfg["allowed_methods"]:
            state.count("blocked")
            server.event(ip=ip, action="blocked", categories=["Methode interdite"],
                         method=self.command, path=self.path[:200], request_id=self.rid)
            return self.deny(405, f"Methode {self.command} interdite.",
                             headers={"Allow": ", ".join(self.cfg["allowed_methods"])})
        if len(self.path) > self.cfg["max_url_length"]:
            state.count("blocked")
            server.event(ip=ip, action="blocked", categories=["URL trop longue"],
                         path=self.path[:200], length=len(self.path), request_id=self.rid)
            return self.deny(414, "URL trop longue.")
        if len(self.headers) > self.cfg["max_headers"]:
            state.count("blocked")
            return self.deny(431, "Trop d'en-tetes HTTP.")

        if not whitelisted_ip and state.is_banned(ip):
            state.count("banned_hits")
            return self.deny(403, "Ton adresse IP est temporairement bannie.")

        # --- Protection contre le HTTP request smuggling
        if "Transfer-Encoding" in self.headers:
            server.event(ip=ip, action="blocked", categories=["Smuggling"], path=self.path[:200],
                         reason="Transfer-Encoding refuse", request_id=self.rid)
            state.count("blocked")
            return self.deny(400, "Transfer-Encoding non supporte.")
        raw_length = self.headers.get("Content-Length", "0")
        if not raw_length.isdigit() or len(self.headers.get_all("Content-Length") or []) > 1:
            state.count("blocked")
            return self.deny(400, "Content-Length invalide.")
        length = int(raw_length)
        if length > self.cfg["max_body"]:
            server.event(ip=ip, action="blocked", categories=["Body too large"], path=self.path[:200],
                         request_id=self.rid)
            state.count("blocked")
            return self.deny(413, "Corps de requete trop volumineux.")
        body = self.rfile.read(length) if length else b""

        if whitelisted_ip:
            state.count("whitelisted")
            return self.forward(ip, body)

        # --- Pieges : aucun visiteur honnete ne demande /.env ou /.git/config
        if server.rules.is_trap(path):
            state.count("traps")
            with state.lock:
                state.attackers[ip] += 1
                state.categories["Piege"] += 1
            duration = state.ban(ip)
            server.event(ip=ip, action="trap", categories=["Piege"], path=self.path[:200],
                         user_agent=self.headers.get("User-Agent", "")[:150],
                         ban_duration=duration, request_id=self.rid)
            # On repond 404 comme si la page n'existait pas : l'attaquant ne sait pas qu'il est detecte
            return self.respond(404, "<h1>404 Not Found</h1>")

        if any(path.startswith(p) for p in self.cfg["whitelist_paths"]):
            state.count("whitelisted")
            return self.forward(ip, body)

        if state.rate_exceeded(ip):
            state.count("rate_limited")
            server.event(ip=ip, action="rate_limit", path=self.path[:200], request_id=self.rid)
            return self.deny(429, "Trop de requetes, ralentis.",
                             headers={"Retry-After": str(self.cfg["rate_limit"]["window"])})

        # --- Analyse
        zones = {"url": self.path, "body": body.decode("utf-8", errors="replace")}
        for key, value in self.headers.items():
            if key.lower() not in NOT_INSPECTED:
                zones[f"header:{key}"] = value
        score, matches = server.rules.scan(zones, path)

        user_agent = self.headers.get("User-Agent", "")
        scanner = server.rules.check_agent(user_agent)
        if scanner:
            score += self.cfg["anomaly_threshold"]
            matches.append({"id": 9001, "category": "Scanner", "score": self.cfg["anomaly_threshold"],
                            "zone": "header:User-Agent", "description": f"Outil detecte : {scanner}"})

        if matches:
            categories = sorted({m["category"] for m in matches})
            info = dict(ip=ip, score=score, categories=categories, method=self.command,
                        path=self.path[:300], user_agent=user_agent[:150], request_id=self.rid,
                        rules=[f'{m["id"]} {m["description"]} ({m["zone"]})' for m in matches])

            if score >= self.cfg["anomaly_threshold"]:
                monitor = self.cfg["mode"] == "monitor"
                state.count("detected" if monitor else "blocked")
                server.event(action="detected" if monitor else "blocked", **info)
                duration = state.add_strike(ip, categories)
                if duration:
                    server.event(ip=ip, action="banned", duration=duration, request_id=self.rid)
                if not monitor:
                    return self.deny(403, f"Attaque detectee : {', '.join(categories)}")
            else:
                # Score sous le seuil : on laisse passer mais on garde une trace
                state.count("suspicious")
                server.event(action="suspicious", **info)

        self.forward(ip, body)

    # ------------------------------------------------------------ transfert vers le backend
    def forward(self, ip, body):
        url = self.cfg["backend"].rstrip("/") + self.path
        skip = HOP_BY_HOP | ({"accept-encoding"} if self.cfg["inspect_responses"] else set())
        headers = {k: v for k, v in self.headers.items() if k.lower() not in skip}
        headers["X-Forwarded-For"] = ip
        headers["X-Forwarded-Proto"] = "https" if self.server.tls else "http"
        headers["X-Request-ID"] = self.rid
        request = urllib.request.Request(url, data=body or None, headers=headers, method=self.command)
        try:
            response = OPENER.open(request, timeout=self.cfg["backend_timeout"])
        except urllib.error.HTTPError as e:
            response = e  # 3xx/4xx/5xx du backend : on les relaie
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            self.server.event(ip=ip, action="backend_down", path=self.path[:200], request_id=self.rid)
            return self.deny(502, "Le site protege est injoignable.")

        with response:
            data = response.read()
            status = response.getcode()
            backend_headers = response.headers

        # Masque les pages d'erreur du backend (traces, chemins, versions...)
        if status >= 500 and self.cfg["hide_backend_errors"]:
            self.server.event(ip=ip, action="backend_error_hidden", status=status,
                              path=self.path[:200], request_id=self.rid)
            self.server.state.count("errors_hidden")
            return self.deny(status, "Erreur interne du serveur.")

        # Inspection de la reponse (protection contre les fuites de donnees)
        content_type = backend_headers.get("Content-Type", "")
        inspectable = (self.cfg["inspect_responses"] and len(data) <= self.cfg["max_inspect_size"]
                       and not backend_headers.get("Content-Encoding")
                       and any(t in content_type for t in ("text/", "json", "xml", "javascript")))
        if inspectable:
            text = data.decode("utf-8", errors="replace")
            leak = self.server.rules.scan_response(text)
            if leak:
                self.server.state.count("leaks_blocked")
                with self.server.state.lock:
                    self.server.state.categories[leak["category"]] += 1
                self.server.event(ip=ip, action="leak_blocked", categories=[leak["category"]],
                                  rules=[f'{leak["id"]} {leak["description"]}'],
                                  path=self.path[:200], request_id=self.rid)
                return self.deny(500, "Reponse bloquee : fuite de donnees detectee.")
            if self.cfg["mask_card_numbers"]:
                masked, count = mask_cards(text)
                if count:
                    data = masked.encode("utf-8")
                    self.server.state.count("cards_masked")
                    self.server.event(ip=ip, action="cards_masked", count=count,
                                      path=self.path[:200], request_id=self.rid)

        self.send_response(status)
        sent = set()
        for key, value in backend_headers.items():
            if key.lower() not in HOP_BY_HOP and key.lower() not in LEAKY_HEADERS:
                self.send_header(key, value)
                sent.add(key.lower())
        for key, value in self.security_headers.items():
            if key.lower() not in sent:
                self.send_header(key, value)
        self.send_header("X-Request-ID", self.rid)
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
        if ip not in self.server.nets["dashboard_ips"] or not hmac.compare_digest(given.encode(), token.encode()):
            self.server.event(ip=ip, action="dashboard_denied", path=path, request_id=self.rid)
            return self.deny(403, "Acces au tableau de bord refuse.")
        no_cache = {"Cache-Control": "no-store"}
        if path == "/__waf/unban":
            # Action sensible : POST obligatoire et token dans un en-tete (un site tiers ne peut pas
            # ajouter d'en-tete personnalise a une requete : protection contre le CSRF)
            if self.command != "POST" or not self.headers.get("X-WAF-Token"):
                return self.deny(405, "Utilise POST avec l'en-tete X-WAF-Token.", headers={"Allow": "POST"})
            target = query.get("ip", [""])[0]
            was_banned = self.server.state.unban(target)
            self.server.event(ip=ip, action="unbanned", target=target, request_id=self.rid)
            return self.respond(200, json.dumps({"ip": target, "was_banned": was_banned}),
                                "application/json; charset=utf-8", no_cache)
        if path == "/__waf/api":
            return self.respond(200, json.dumps(self.server.state.snapshot(), ensure_ascii=False),
                                "application/json; charset=utf-8", no_cache)
        if path == "/__waf/metrics":
            return self.respond(200, self.server.state.metrics(), "text/plain; version=0.0.4", no_cache)
        csp = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"
        self.respond(200, DASHBOARD_HTML, headers={"Content-Security-Policy": csp, **no_cache})

    # Toutes les methodes passent par handle_any, qui refuse celles hors de allowed_methods
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any
    do_TRACE = do_CONNECT = do_PROPFIND = handle_any


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
    scheme = "https" if server.tls else "http"
    print(f"[MiniWAF v{VERSION}] {scheme}://{host}:{port} -> {config['backend']}  "
          f"(mode {config['mode']}, seuil {config['anomaly_threshold']})")
    print(f"[MiniWAF] {len(rules.rules)} regles, {len(rules.response_rules)} regles de reponse, "
          f"{len(rules.traps)} pieges, {len(server.state.banned)} IP deja bannies")
    print(f"[MiniWAF] {len(rules.exclusions)} exceptions, alertes "
          f"{'activees (' + config['alert_format'] + ')' if config['alert_webhook'] else 'desactivees'}")
    print(f"[MiniWAF] Tableau de bord : {scheme}://{host}:{port}/__waf/?token={config['dashboard_token']}")
    print(f"[MiniWAF] Metriques     : {scheme}://{host}:{port}/__waf/metrics?token={config['dashboard_token']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MiniWAF] Arret. Statistiques :", dict(server.state.stats))
        server.server_close()


if __name__ == "__main__":
    main()
