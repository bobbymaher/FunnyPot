# funnypot standalone honeypot — all-in-one nginx + php-fpm, HTTP + HTTPS across the
# common web ports (handles a scanner's concurrent request flood; php -S could not).
#   docker build -f demo/Dockerfile -t funnypot .
#   docker run --rm -p 80:80 -p 443:443 -p 8080:8080 -p 8443:8443 funnypot
FROM php:8.3-fpm-alpine

RUN apk add --no-cache nginx openssl

# opcache on (the index is compiled once, not re-parsed per request) + a worker pool
# sized for concurrency + the shared routing snippet.
COPY demo/opcache.ini           /usr/local/etc/php/conf.d/zz-funnypot.ini
COPY demo/fpm-pool.conf         /usr/local/etc/php-fpm.d/zz-funnypot.conf
COPY demo/nginx.conf            /etc/nginx/http.d/default.conf
COPY demo/funnypot-location.conf /etc/nginx/funnypot-location.conf
COPY demo/entrypoint.sh         /entrypoint.sh

WORKDIR /app
# Runtime pieces only: library source, prebuilt index, the demo. No composer/vendor.
COPY src ./src
COPY resources ./resources
COPY demo ./demo

RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/demo/storage \
    && chmod 0777 /app/demo/storage

ENV FUNNYPOT_STYLE=realistic \
    FUNNYPOT_LOG=/app/demo/storage/hits.log

# Common HTTP + alt-HTTP ports, and HTTPS on the common TLS ports.
EXPOSE 80 3000 5000 8000 8008 8080 8081 8088 8090 8161 8888 8983 9000 9090
EXPOSE 443 4443 8443 9443 10443

CMD ["/entrypoint.sh"]
