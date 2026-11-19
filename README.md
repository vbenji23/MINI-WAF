# MiniWAF v4 🛡️

Un **Web Application Firewall** écrit en Python, sans aucune dépendance. Il se place en reverse proxy devant un site web : il analyse chaque requête **et chaque réponse**, bloque les attaques et empêche les fuites de données.

```
Client  ──►  MiniWAF (:8080)  ──►  Site protégé (:5000)
                 │
                 ├──► waf.log        événements JSON (rotation automatique)
                 ├──► bans.json      IP bannies (conservées au redémarrage)
                 ├──► /__waf/        tableau de bord temps réel
                 └──► /__waf/metrics métriques Prometheus (Grafana, SIEM)
```

## Fonctionnalités

### 1. Analyse des requêtes (24 règles, `rules.json`)

| Catégorie | Exemples détectés |
|---|---|
| Injection SQL | `UNION SELECT`, `OR 1=1`, `admin'--`, `sleep()`, `; DROP TABLE` |
| XSS | `<script>`, `onerror=`, `javascript:`, `document.cookie` |
| Path traversal | `../`, `/etc/passwd`, `boot.ini` |
| Injection de commandes | `; cat`, `\| whoami`, `$(id)`, `&& curl` |
| Log4Shell | `${jndi:ldap://...}` (CVE-2021-44228) |
| LFI / RFI | `php://filter`, inclusion d'URL distante |
| SSRF | Accès aux métadonnées cloud `169.254.169.254` |
| Scanners | sqlmap, nikto, nmap, gobuster, ffuf, nuclei… |

- **Score d'anomalie** (comme l'OWASP Core Rule Set) : chaque règle a un score, et la requête est bloquée seulement si le total atteint le seuil. Les règles faibles seules sont notées « suspectes » sans bloquer.
- **Normalisation anti-contournement** : double encodage URL, entités HTML, commentaires SQL `/**/`, octets nuls.
- **Zones inspectées** : URL, corps, cookies et autres en-têtes.

### 2. Analyse des réponses (DLP)

Même si une attaque passe, le WAF vérifie ce que le site renvoie :

| Fuite détectée | Action |
|---|---|
| Message d'erreur SQL | Réponse bloquée |
| Contenu de `/etc/passwd` | Réponse bloquée |
| Clé privée (RSA, SSH…) | Réponse bloquée |
| Trace d'exception (Python, Java, PHP) | Réponse bloquée |
| Clé d'accès AWS | Réponse bloquée |
| Numéro de carte bancaire (validé par l'algorithme de Luhn) | Masqué : `**** **** **** 1111` |
| Erreurs 500 du site | Remplacées par une page neutre |
| En-têtes `Server`, `X-Powered-By` | Supprimés |

### 3. Pièges (deception)

Des chemins comme `/.env`, `/.git/`, `/wp-admin` ou `/backup.sql` n'existent pas sur le site, et aucun visiteur honnête ne les demande. Le premier accès bannit immédiatement l'IP, mais le WAF répond un simple `404` : l'attaquant ne sait pas qu'il a été repéré.

### 4. Bannissement

- Ban après 5 attaques, et la durée **double à chaque récidive** (5 min, 10 min, 20 min… plafonné à 24 h).
- Les bans sont enregistrés dans `bans.json` (écriture atomique) et **survivent à un redémarrage**.
- Débannissement depuis le tableau de bord ou par l'API.

### 5. Contrôles du protocole

- Méthodes autorisées uniquement (`TRACE` → 405)
- URL trop longue (414), trop d'en-têtes (431), corps trop gros (413)
- Anti request smuggling : `Transfer-Encoding` et `Content-Length` multiple ou invalide refusés
- Rate limiting par IP (429 avec `Retry-After`)
- `X-Forwarded-For` accepté uniquement depuis un proxy de confiance
- Le WAF ne suit pas les redirections du backend et ignore les proxys système

### 6. HTTPS, réseau et alertes (v4)

- **HTTPS intégré** : TLS 1.2 minimum, en-tête HSTS automatique. La négociation TLS se fait dans le thread de chaque client, pour qu'un client lent ne bloque pas les autres. `./gen_cert.sh` crée un certificat de test.
- **Anti-slowloris** : un client qui n'envoie pas sa requête en entier dans le délai `client_timeout` est déconnecté.
- **CIDR** : listes blanche et noire, proxys de confiance et accès au tableau de bord acceptent des réseaux (`10.0.0.0/8`, IPv6). La liste noire (`blocklist_ips`) est bloquée d'office.
- **Exceptions de règles** (`exclusions` dans `rules.json`) : on désactive des règles précises sur un chemin précis pour corriger un faux positif, sans affaiblir le reste du site.
- **Alertes temps réel** sur Discord ou Slack (webhook) pour les bans, les pièges et les fuites. Une seule alerte par type d'événement et par IP pendant `alert_cooldown` secondes, et l'envoi se fait en arrière-plan.
- **`waf_report.py`** : rapport des logs avec les classements (IP, chemins, règles, scanners, pièges) et une chronologie heure par heure. Il lit aussi les archives de logs et propose une sortie `--json`.

### 7. Traçabilité et supervision

- Chaque requête reçoit un **`X-Request-ID`** unique, transmis au site, renvoyé au client et écrit dans les logs : on retrouve facilement un incident de bout en bout.
- **Tableau de bord** `/__waf/` : compteurs, catégories, top attaquants, IP bannies (avec un bouton pour débannir), derniers événements. Il est réservé à localhost et protégé par un token comparé en temps constant. Les données sont affichées avec `textContent` sous une CSP stricte, pour que les payloads des attaquants ne déclenchent pas de XSS dans le tableau de bord.
- **Métriques Prometheus** `/__waf/metrics`.
- **Débannissement** `/__waf/unban` : POST obligatoire et token dans un en-tête, ce qui empêche le CSRF.

## Utilisation

Prérequis : Python 3.8+ (bibliothèque standard uniquement), et `curl` pour le script de test.

```bash
# Terminal 1 : le site de démo vulnérable
python3 demo_site.py

# Terminal 2 : le WAF (affiche le token du tableau de bord)
python3 waf.py

# Terminal 3 : les tests
WAF_TOKEN=<token> ./test_attacks.sh        # 28 vérifications en conditions réelles
python3 -m unittest discover -s tests -v   # 43 tests unitaires et d'intégration
python3 waf_report.py                      # rapport des logs
```

En HTTPS :

```bash
./gen_cert.sh
# config.json : "tls": {"cert": "certs/waf.crt", "key": "certs/waf.key"}
python3 waf.py
WAF=https://localhost:8080 WAF_TOKEN=<token> ./test_attacks.sh
```

Options : `--config`, `--rules`, `--port`, `--backend`, `--monitor` (détecte sans bloquer).

Démo rapide :

| URL | Sans WAF (:5000) | Avec WAF (:8080) |
|---|---|---|
| `/search?q=<script>alert(1)</script>` | popup XSS | bloqué (403) |
| `/product?id=abc` | erreur SQL visible | bloqué (500 neutre) |
| `/orders` | cartes bancaires en clair | `**** **** **** 1111` |
| `/error` | trace avec chemins et IP internes | page neutre |
| `/.env` | 404 | 404 + IP bannie |

## Configuration (`config.json`)

| Clé | Rôle |
|---|---|
| `mode` | `block` ou `monitor` |
| `anomaly_threshold` | Score à partir duquel une requête est bloquée |
| `rate_limit` | Requêtes autorisées par fenêtre de temps |
| `ban` | Nombre d'attaques avant le ban, durée de base, durée maximale |
| `allowed_methods` | Méthodes HTTP acceptées |
| `max_url_length` / `max_headers` / `max_body` | Limites de taille |
| `inspect_responses` / `mask_card_numbers` | Analyse des réponses |
| `whitelist_ips` / `whitelist_paths` | Ce qui n'est jamais inspecté |
| `trusted_proxies` | Proxys dont on accepte le `X-Forwarded-For` |
| `blocklist_ips` | IP ou réseaux CIDR bloqués d'office |
| `client_timeout` | Délai max pour envoyer une requête (anti-slowloris) |
| `tls` | Chemins du certificat et de la clé pour activer le HTTPS |
| `alert_webhook` / `alert_format` / `alert_on` / `alert_cooldown` | Alertes Discord/Slack |
| `dashboard_token` | Vide = token aléatoire généré au démarrage |

## Exemple de log

```json
{"ip": "127.0.0.1", "action": "trap", "categories": ["Piege"], "path": "/.env", "user_agent": "curl/8.5.0", "ban_duration": 300, "request_id": "4f1c9a2be07d", "time": "2026-11-19 09:52:10"}
```

## Structure

```
miniwaf/
├── waf.py            # le WAF
├── rules.json        # règles de requête, de réponse et pièges (rechargées à chaud)
├── config.json       # configuration
├── demo_site.py      # site volontairement vulnérable pour la démo
├── waf_report.py     # rapport d'analyse des logs
├── gen_cert.sh       # certificat HTTPS de test
├── test_attacks.sh   # tests en conditions réelles avec curl
└── tests/test_waf.py # tests unitaires et d'intégration
```

## Limites connues

- Les règles reposent sur des regex : un attaquant motivé peut les contourner, et des textes légitimes peuvent provoquer des faux positifs (« Union Select Furniture »).
- Un long identifiant numérique qui passe le test de Luhn serait masqué par erreur.
- Pour inspecter les réponses, le WAF demande au site des réponses non compressées, ce qui consomme plus de bande passante.
- Le HTTPS intégré convient pour un projet ou un petit site. En production, on confierait plutôt le TLS à nginx ou à un load balancer, avec un vrai certificat (Let's Encrypt).
- Un WAF ne remplace jamais la correction des failles dans le code.

## Avertissement

`demo_site.py` est volontairement vulnérable : ne l'expose jamais sur Internet. Les numéros de carte affichés sont des numéros de test publics. Projet pédagogique réalisé dans le cadre de ma formation à Guardia Cyber School.
