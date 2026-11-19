# MiniWAF v2 🛡️

Un **Web Application Firewall** écrit en Python, sans aucune dépendance. Il se place en reverse proxy devant un site web, analyse chaque requête HTTP et bloque les attaques avant qu'elles n'atteignent l'application.

```
Client  ──►  MiniWAF (:8080)  ──►  Site protégé (:5000)
                 │
                 ├──► waf.log (événements JSON, rotation automatique)
                 └──► Tableau de bord temps réel : /__waf/
```

## Fonctionnalités

**Détection** (24 règles dans `rules.json`)

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

**Fonctionnement**

- **Score d'anomalie** (comme l'OWASP Core Rule Set) : chaque règle a un score. La requête est bloquée seulement si le total atteint le seuil (5 par défaut). Les règles faibles seules sont simplement journalisées comme « suspectes », ce qui réduit les faux positifs.
- **Normalisation anti-contournement** : décodage URL multiple (`%253C` → `<`), entités HTML (`&lt;` → `<`), suppression des commentaires SQL (`UNION/**/SELECT`) et des octets nuls.
- **Zones inspectées** : URL, corps de la requête, cookies et autres en-têtes.
- **Rechargement à chaud** : modifier `rules.json` suffit, pas besoin de redémarrer.

**Protections supplémentaires**

- Rate limiting par IP (HTTP 429 avec `Retry-After`)
- Bannissement temporaire après plusieurs attaques
- Anti request smuggling : `Transfer-Encoding` et `Content-Length` invalide refusés
- Taille maximale du corps (HTTP 413)
- Masquage des erreurs 500 du backend (pas de fuite de traces ni de chemins)
- Suppression des en-têtes qui révèlent la technologie (`Server`, `X-Powered-By`)
- Ajout d'en-têtes de sécurité (`X-Frame-Options`, `X-Content-Type-Options`…)
- `X-Forwarded-For` accepté uniquement depuis un proxy de confiance (sinon un attaquant peut le falsifier pour contourner le ban)
- Liste blanche d'IP et de chemins
- Mode `monitor` : détecte sans bloquer, pour régler les règles sans casser le site

**Tableau de bord** sur `/__waf/`, réservé à localhost et protégé par un token (comparaison en temps constant). Il affiche les compteurs, les catégories d'attaques, le top des attaquants, les IP bannies et les derniers événements. Les données sont insérées avec `textContent` et une CSP stricte, pour que les payloads des attaquants ne déclenchent pas de XSS dans le tableau de bord lui-même.

## Installation et utilisation

Prérequis : Python 3.8+ (bibliothèque standard uniquement), et `curl` pour le script de test.

```bash
# Terminal 1 : le site de démo vulnérable
python3 demo_site.py

# Terminal 2 : le WAF
python3 waf.py
# -> affiche l'URL du tableau de bord avec son token

# Terminal 3 : les tests
./test_attacks.sh                          # 17 vérifications en conditions réelles
python3 -m unittest discover -s tests -v   # tests unitaires et d'intégration
```

Options : `--config`, `--rules`, `--port`, `--backend`, `--monitor`.

Démo rapide : ouvre `http://127.0.0.1:5000/search?q=<script>alert(1)</script>` (sans WAF, la popup s'affiche), puis la même URL sur le port `8080` (le WAF bloque).

## Configuration (`config.json`)

| Clé | Rôle |
|---|---|
| `mode` | `block` ou `monitor` |
| `anomaly_threshold` | Score à partir duquel une requête est bloquée |
| `rate_limit` | Nombre de requêtes autorisées par fenêtre de temps |
| `ban` | Nombre d'attaques avant le ban, et sa durée |
| `whitelist_ips` / `whitelist_paths` | Ce qui n'est jamais inspecté |
| `trusted_proxies` | Proxys dont on accepte le `X-Forwarded-For` |
| `hide_backend_errors` | Remplace les pages d'erreur 5xx du backend |
| `dashboard_token` | Vide = token aléatoire généré au démarrage |

## Exemple de log

```json
{"ip": "127.0.0.1", "score": 10, "categories": ["XSS"], "method": "GET", "path": "/search?q=%253Cscript%253Ealert(1)", "rules": ["2001 Balise script (url)", "2006 Fonctions de popup (url)"], "action": "blocked", "incident": "a3f9c2e1", "time": "2026-11-19 09:07:48"}
```

## Structure

```
miniwaf/
├── waf.py            # le WAF
├── rules.json        # règles de détection (modifiables à chaud)
├── config.json       # configuration
├── demo_site.py      # site volontairement vulnérable pour la démo
├── test_attacks.sh   # tests en conditions réelles avec curl
└── tests/test_waf.py # tests unitaires et d'intégration
```

## Limites connues

Les règles reposent sur des expressions régulières : un attaquant motivé peut les contourner, et certains textes légitimes peuvent déclencher des faux positifs (« Union Select Furniture » par exemple). Le WAF ne gère pas le HTTPS lui-même : en production, on le placerait derrière nginx. Les corps compressés ou chunked ne sont pas analysés (ils sont refusés). Un WAF ne remplace jamais la correction des failles dans le code.

## Avertissement

`demo_site.py` est volontairement vulnérable : ne l'expose jamais sur Internet. Projet pédagogique réalisé dans le cadre de ma formation à Guardia Cyber School.
