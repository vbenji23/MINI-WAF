#!/bin/sh
# Genere un certificat TLS auto-signe pour tester MiniWAF en HTTPS en local.
# Ensuite, dans config.json : "tls": {"cert": "certs/waf.crt", "key": "certs/waf.key"}
set -e
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -keyout certs/waf.key -out certs/waf.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 certs/waf.key   # la cle privee n'est lisible que par toi
echo "Certificat cree : certs/waf.crt et certs/waf.key (valable 365 jours)"
echo "Test : curl --cacert certs/waf.crt https://localhost:8080/"
