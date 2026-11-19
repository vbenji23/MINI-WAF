#!/bin/sh
# Lance une serie de requetes contre MiniWAF et verifie le code HTTP obtenu.
# Prerequis : demo_site.py et waf.py lances (ports 5000 et 8080).
#
# Usage : WAF_TOKEN=<token du tableau de bord> ./test_attacks.sh
# Le token sert a debannir ton IP entre les tests (sinon le 2e lancement serait bloque).
# En HTTPS : WAF=https://localhost:8080 WAF_TOKEN=<token> ./test_attacks.sh
WAF="${WAF:-http://127.0.0.1:8080}"
TOKEN="${WAF_TOKEN:-}"
CURL_OPTS=""
case "$WAF" in https://*) CURL_OPTS="--cacert certs/waf.crt" ;; esac
c() { curl $CURL_OPTS "$@"; }
PASS=0; FAIL=0
GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')

ok()   { PASS=$((PASS+1)); printf "  ${GREEN}OK${RESET}    %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  ${RED}ECHEC${RESET} %s\n" "$1"; }

# check <code attendu> <nom> <arguments curl...>
check() {
  expected="$1"; name="$2"; shift 2
  code=$(c -s --path-as-is -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$expected" ]; then ok "$(printf '%-34s %s' "$name" "$code")"
  else fail "$(printf '%-34s %s (attendu %s)' "$name" "$code" "$expected")"; fi
}

# body_has <texte> <nom> <url> : verifie que la reponse contient le texte
body_has()  { if c -s "$3" | grep -q -- "$1"; then ok "$2"; else fail "$2"; fi; }
body_hasnt() { if c -s "$3" | grep -q -- "$1"; then fail "$2"; else ok "$2"; fi; }

unban() {
  [ -n "$TOKEN" ] && c -s -o /dev/null -X POST -H "X-WAF-Token: $TOKEN" "$WAF/__waf/unban?ip=127.0.0.1"
}

if [ -z "$TOKEN" ]; then
  echo "${YELLOW}Astuce : lance avec WAF_TOKEN=<token> pour tester aussi les pieges et relancer le script sans etre bloque.${RESET}"
fi
unban

echo "== Trafic legitime (200) =="
check 200 "Accueil"                    "$WAF/"
check 200 "Recherche simple"           "$WAF/search?q=switch+cisco"
check 200 "Nom avec apostrophe"        "$WAF/search?q=O'Neil"
check 200 "Plusieurs parametres"       "$WAF/search?q=routeur&id=3&tri=prix"
check 200 "Texte avec 'select'"        "$WAF/search?q=select+a+product"
check 200 "Login normal"               "$WAF/login" -d "user=benjamin&pass=MonMotDePasse"
check 200 "Produit existant"           "$WAF/product?id=3"

echo "== Fuites d'information (reponses du site) =="
check 500 "Erreur backend masquee"     "$WAF/error"
body_hasnt "Traceback"                 "Trace d'erreur cachee"                  "$WAF/error"
check 500 "Erreur SQL bloquee"         "$WAF/product?id=abc"
body_hasnt "SQL syntax"                "Message SQL invisible"                  "$WAF/product?id=abc"
body_hasnt "4111 1111 1111 1111"       "Carte bancaire masquee"                 "$WAF/orders"
body_has   "\*\*\*\* \*\*\*\* \*\*\*\* 1111" "4 derniers chiffres conserves"    "$WAF/orders"
if c -sI "$WAF/" | grep -qi "x-powered-by\|apache"; then fail "Banniere du backend masquee"
else ok "Banniere du backend masquee"; fi
if c -sI "$WAF/" | grep -qi "x-request-id"; then ok "En-tete X-Request-ID present"
else fail "En-tete X-Request-ID present"; fi

if [ -n "$CURL_OPTS" ]; then
  if c -sI "$WAF/" | grep -qi "strict-transport-security"; then ok "HSTS actif en HTTPS"
  else fail "HSTS actif en HTTPS"; fi
fi

echo "== Protocole =="
check 400 "Request smuggling (TE)"     "$WAF/login" -H "Transfer-Encoding: chunked" -d "x"
check 405 "Methode TRACE"              "$WAF/" -X TRACE
check 414 "URL de 3000 caracteres"     "$WAF/search?q=$(printf 'a%.0s' $(seq 3000))"
check 403 "Dashboard sans token"       "$WAF/__waf/"

echo "== Attaques (403) =="
check 403 "SQLi UNION SELECT"          "$WAF/search?q=1%20UNION%20SELECT%20password%20FROM%20users"
check 403 "SQLi contournement /**/"    "$WAF/search?q=1/**/UNION/**/SELECT/**/1"
check 403 "SQLi bypass login (POST)"   "$WAF/login" -d "user=admin'--&pass=x"
check 403 "XSS <script>"               "$WAF/search?q=<script>alert(1)</script>"
check 403 "XSS double encodage"        "$WAF/search?q=%253Cscript%253Ealert(1)"

echo "== Bannissement apres 5 attaques =="
check 403 "Accueil (IP bannie)"        "$WAF/"

if [ -n "$TOKEN" ]; then
  unban
  echo "== Pieges (deception) =="
  check 200 "Accueil (apres debannissement)" "$WAF/"
  check 404 "Acces a /.env"              "$WAF/.env"
  check 403 "Accueil (banni par le piege)" "$WAF/"
  unban
fi

echo
echo "Resultat : ${GREEN}${PASS} OK${RESET}, ${RED}${FAIL} echec(s)${RESET}"
[ "$FAIL" -eq 0 ]
