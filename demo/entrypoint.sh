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

php-fpm --daemonize
exec nginx -g 'daemon off;'
