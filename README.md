# MiniWAF 🛡️

Un **Web Application Firewall** écrit en Python, sans aucune dépendance. Il se place en reverse proxy devant un site web, inspecte chaque requête HTTP et bloque les attaques avant qu'elles n'atteignent l'application.

```
Client  ──►  MiniWAF (:8080)  ──►  Site protégé (:5000)
                 │
                 └──► waf.log (événements JSON)
```

## Fonctionnalités

| Protection | Détail |
|---|---|
| Injections SQL | `UNION SELECT`, `OR 1=1`, `sleep()`, `information_schema`, commentaires `--` |
| XSS | `<script>`, `javascript:`, handlers `onerror=`/`onload=`, `document.cookie` |
| Path traversal | `../`, `/etc/passwd`, `C:\Windows` |
| Injection de commandes | `; cat`, `\| whoami`, `$(...)` |
| LFI / RFI | `php://`, `file://`, inclusion d'URL distante |
| Scanners | Détection de sqlmap, nikto, nmap, gobuster, wpscan, hydra… via le User-Agent |
| Anti-contournement | Décodage URL multiple (le double encodage `%253C` est détecté) |
| Rate limiting | 30 requêtes / 10 s par IP, sinon HTTP 429 |
| Bannissement | IP bannie 5 min après 5 attaques |
| Taille max | Corps > 1 Mo refusé (HTTP 413) |
| En-têtes de sécurité | Ajout de `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, et masquage du header `Server` du backend |
| Mode détection | `--monitor` : journalise sans bloquer (utile pour régler les règles sans casser le site) |

Zones inspectées : URL, corps de la requête (POST), cookies, Referer, User-Agent.

## Utilisation

Prérequis : Python 3.8+ (bibliothèque standard uniquement).

```bash
# Terminal 1 : le site de démo (volontairement vulnérable à la XSS)
python3 demo_site.py

# Terminal 2 : le WAF devant le site
python3 waf.py --port 8080 --backend http://127.0.0.1:5000

# Terminal 3 : lancer les attaques de test
./test_attacks.sh
```

Résultat attendu :

```
=== Requetes legitimes (attendu 200) ===
Page d'accueil           -> 200
Recherche normale        -> 200
=== Attaques (attendu 403) ===
SQLi UNION               -> 403
SQLi OR 1=1              -> 403
XSS script               -> 403
XSS double encodage      -> 403
Path traversal           -> 403
...
```

Pour voir l'intérêt du WAF : ouvre `http://127.0.0.1:5000/?q=<script>alert(1)</script>` (sans WAF, la popup s'affiche), puis la même URL sur le port `8080` (avec WAF, la requête est bloquée).

Exemple d'événement dans `waf.log` :

```json
{"ip": "127.0.0.1", "action": "blocked", "category": "XSS", "rule": "(?i)<\\s*script", "method": "GET", "path": "/?q=%253Cscript%253Ealert(1)", "user_agent": "curl/8.5.0", "incident": "1049bb86", "time": "2026-11-18 15:35:40"}
```

## Options

```
--listen    adresse d'écoute (défaut 127.0.0.1)
--port      port du WAF (défaut 8080)
--backend   URL du site à protéger (défaut http://127.0.0.1:5000)
--monitor   mode détection seule
```

## Limites connues

Les règles reposent sur des expressions régulières : elles peuvent produire des faux positifs et être contournées par un attaquant motivé. Un vrai WAF (ModSecurity + OWASP CRS, Cloudflare…) analyse aussi le contexte et attribue un score à chaque requête. Le WAF ne gère pas non plus le HTTPS lui-même : en production, on le mettrait derrière un terminateur TLS (nginx).

## Pistes d'amélioration

- Scoring d'anomalie à la place du blocage immédiat
- Règles chargées depuis un fichier YAML
- Tableau de bord web des attaques en temps réel
- Liste blanche d'IP et d'URL
- Export des logs vers un SIEM

## Avertissement

`demo_site.py` est volontairement vulnérable : ne l'expose jamais sur Internet. Projet réalisé dans un cadre pédagogique (Guardia Cyber School).
