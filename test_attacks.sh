#!/bin/sh
# Lance une serie de requetes contre MiniWAF et verifie le code HTTP obtenu.
# Prerequis : demo_site.py et waf.py lances (ports 5000 et 8080).
WAF="${WAF:-http://127.0.0.1:8080}"
PASS=0; FAIL=0
GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); RESET=$(printf '\033[0m')

# check <code attendu> <nom> <arguments curl...>
check() {
  expected="$1"; name="$2"; shift 2
  code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$expected" ]; then
    PASS=$((PASS+1)); printf "  ${GREEN}OK${RESET}    %-34s %s\n" "$name" "$code"
  else
    FAIL=$((FAIL+1)); printf "  ${RED}ECHEC${RESET} %-34s %s (attendu %s)\n" "$name" "$code" "$expected"
  fi
}

echo "== Trafic legitime (200) =="
check 200 "Accueil"                    "$WAF/"
check 200 "Recherche simple"           "$WAF/search?q=switch+cisco"
check 200 "Nom avec apostrophe"        "$WAF/search?q=O'Neil"
check 200 "Plusieurs parametres"       "$WAF/search?q=routeur&id=3&tri=prix"
check 200 "Texte avec 'select'"        "$WAF/search?q=select+a+product"
check 200 "Login normal"               "$WAF/login" -d "user=benjamin&pass=MonMotDePasse"

echo "== Fuites d'information =="
check 500 "Erreur backend masquee"     "$WAF/error"
if curl -s "$WAF/error" | grep -q "Traceback"; then
  FAIL=$((FAIL+1)); echo "  ${RED}ECHEC${RESET} la trace d'erreur est visible"
else
  PASS=$((PASS+1)); echo "  ${GREEN}OK${RESET}    trace d'erreur cachee"
fi
if curl -sI "$WAF/" | grep -qi "x-powered-by\|apache"; then
  FAIL=$((FAIL+1)); echo "  ${RED}ECHEC${RESET} la banniere du backend est visible"
else
  PASS=$((PASS+1)); echo "  ${GREEN}OK${RESET}    banniere du backend masquee"
fi

echo "== Protocole =="
check 400 "Request smuggling (TE)"     "$WAF/login" -H "Transfer-Encoding: chunked" -d "x"
check 403 "Dashboard sans token"       "$WAF/__waf/"

echo "== Attaques (403) =="
check 403 "SQLi UNION SELECT"          "$WAF/search?q=1%20UNION%20SELECT%20password%20FROM%20users"
check 403 "SQLi contournement /**/"    "$WAF/search?q=1/**/UNION/**/SELECT/**/1"
check 403 "SQLi bypass login (POST)"   "$WAF/login" -d "user=admin'--&pass=x"
check 403 "XSS <script>"               "$WAF/search?q=<script>alert(1)</script>"
check 403 "XSS double encodage"        "$WAF/search?q=%253Cscript%253Ealert(1)"

echo "== Bannissement apres 5 attaques (403 meme sur une page propre) =="
check 403 "Accueil (IP bannie)"        "$WAF/"

echo
echo "Resultat : ${GREEN}${PASS} OK${RESET}, ${RED}${FAIL} echec(s)${RESET}"
echo "Les autres attaques (traversal, commandes, Log4Shell...) sont testees dans tests/test_waf.py"
[ "$FAIL" -eq 0 ]
