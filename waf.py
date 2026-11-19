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
        """zones = {"url":
