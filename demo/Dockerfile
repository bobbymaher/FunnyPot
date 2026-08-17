# funnypot standalone honeypot — all-in-one nginx + php-fpm, HTTP + HTTPS across the
# common web ports (handles a scanner's concurrent request flood; php -S could not).
#   docker build -f demo/Dockerfile -t funnypot .
#   docker run --rm -p 80:80 -p 443:443 -p 8080:8080 -p 8443:8443 funnypot
FROM php:8.3-fpm-alpine

# nginx + openssl; pdo_sqlite for the dashboard store (needs sqlite-dev to build, sqlite-libs
# at runtime — build deps installed virtual and removed after).
RUN apk add --no-cache nginx openssl sqlite-libs \
    && apk add --no-cache --virtual .build-deps sqlite-dev \
    && docker-php-ext-install pdo_sqlite \
    && apk del .build-deps

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

# Common HTTP + alt-HTTP + app/panel ports, and HTTPS on the common TLS ports.
# (Documentation only; docker publishes ports via -p in scripts/deploy.sh. Keep in sync.)
EXPOSE 80 81 88 591 2082 2086 2095 3000 3128 5000 5601 7001 7070 7080 8000 8001 8008 8009 8080 8081 8082 8083 8088 8090 8161 8180 8500 8880 8888 8983 9000 9080 9090 9200 10000
EXPOSE 443 2083 2087 2096 4433 4443 8443 8834 8843 9443 10443
# TCP protocol honeypots (redis/ftp/smtp/telnet/memcached/ssh).
EXPOSE 21 23 25 2222 6379 11211

CMD ["/entrypoint.sh"]
