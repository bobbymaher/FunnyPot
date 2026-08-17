#!/bin/sh
# Run php-fpm (background) + nginx (foreground) in one container, serving HTTP on the
# common web ports and HTTPS (self-signed) on the common TLS ports.
set -e

CRT=/etc/nginx/funnypot.crt
KEY=/etc/nginx/funnypot.key

# Generate a self-signed cert on first boot (persisted if /etc/nginx is a volume).
if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$KEY" -out "$CRT" \
        -subj "/CN=${FUNNYPOT_CN:-localhost}" >/dev/null 2>&1
fi

# Real HTTPS for the admin hostname once Let's Encrypt has issued a cert (mounted from the
# host at /etc/letsencrypt). Named vhost wins by SNI; every other host/IP keeps self-signed.
# Absent a cert (first boot, before scripts/letsencrypt.sh runs), the block is skipped and
# the hostname is served by the default self-signed 443 vhost.
ADMIN_CONF=/etc/nginx/http.d/10-admin-ssl.conf
LE_LIVE="/etc/letsencrypt/live/${FUNNYPOT_LE_DOMAIN:-__none__}"
if [ -n "${FUNNYPOT_LE_DOMAIN:-}" ] && [ -f "$LE_LIVE/fullchain.pem" ]; then
    cat > "$ADMIN_CONF" <<EOF
server {
    listen 443 ssl;
    server_name ${FUNNYPOT_LE_DOMAIN};
    server_tokens off;
    access_log off;
    ssl_certificate ${LE_LIVE}/fullchain.pem;
    ssl_certificate_key ${LE_LIVE}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    set \$funnypot_https on;
    include /etc/nginx/funnypot-location.conf;
}
EOF
else
    rm -f "$ADMIN_CONF"
fi

php-fpm --daemonize

# Protocol honeypots: one background listener per plaintext protocol (each is a bounded
# select loop). They log connections + every command into the same store the dashboard reads.
# Disable with FUNNYPOT_PROTOCOLS=0.
if [ "${FUNNYPOT_PROTOCOLS:-1}" != "0" ]; then
    php /app/demo/listen.php redis     0.0.0.0:6379  &
    php /app/demo/listen.php ftp       0.0.0.0:21    &
    php /app/demo/listen.php smtp      0.0.0.0:25    &
    php /app/demo/listen.php telnet    0.0.0.0:23    &
    php /app/demo/listen.php memcached 0.0.0.0:11211 &
    php /app/demo/listen.php ssh       0.0.0.0:2222  &
fi

exec nginx -g 'daemon off;'
