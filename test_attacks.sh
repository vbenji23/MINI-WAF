#!/bin/sh
# Envoie des requetes legitimes et malveillantes au WAF et affiche le code HTTP recu
WAF="http://127.0.0.1:8080"

t() { name="$1"; shift; printf "%-24s -> %s\n" "$name" "$(curl -s --path-as-is -o /dev/null -w '%{http_code}' "$@")"; }

echo "=== Requetes legitimes (attendu 200) ==="
t "Page d'accueil"        "$WAF/"
t "Recherche normale"     "$WAF/?q=switch+cisco"

echo "=== Attaques (attendu 403) ==="
t "SQLi UNION"            "$WAF/?q=1%20UNION%20SELECT%20password%20FROM%20users"
t "SQLi OR 1=1"           "$WAF/?q=admin'%20OR%201=1--"
t "XSS script"            "$WAF/?q=<script>alert(1)</script>"
t "XSS double encodage"   "$WAF/?q=%253Cscript%253Ealert(1)"
t "Path traversal"        "$WAF/../../etc/passwd"
t "Injection commande"    "$WAF/?host=127.0.0.1;cat%20/etc/passwd"
t "SQLi dans un POST"     "$WAF/login" -d "user=admin'--&pass=x"
t "Scanner sqlmap"        "$WAF/" -A "sqlmap/1.7"

echo "=== IP bannie apres 5 attaques (attendu 403 meme sur une requete propre) ==="
t "Requete propre"        "$WAF/"
