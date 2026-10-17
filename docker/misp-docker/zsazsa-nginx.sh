#!/bin/bash
# Proxies /zsazsa to zsazsa in misp-core's nginx, so the browser sends MISP's
# session cookie to zsazsa too. misp-docker runs it on every start, through
# customize_misp.sh; running it twice changes nothing.
set -euo pipefail

INCLUDE=/etc/nginx/includes/misp

if ! grep -q "location ^~ /zsazsa/" "$INCLUDE"; then
    cat >> "$INCLUDE" <<'EOF'

# zsazsa CTI application
location = /zsazsa { return 301 /zsazsa/; }
location ^~ /zsazsa/ {
    # Looked up per request, so MISP still starts while zsazsa is down.
    resolver 127.0.0.11 valid=30s;
    set $zsazsa http://zsazsa:5000;
    rewrite ^/zsazsa/(.*)$ /$1 break;
    proxy_pass $zsazsa;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Prefix /zsazsa;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 300s;
}
EOF
fi

nginx -t -q && nginx -s reload
