# funnypot standalone honeypot — minimal image, no composer needed (uses demo/autoload.php).
# Build from the repo root:
#   docker build -f demo/Dockerfile -t funnypot .
#   docker run --rm -p 8080:8080 funnypot
FROM php:8.3-cli-alpine

WORKDIR /app

# Only the runtime pieces: the library source, the prebuilt index, and the demo.
# No vendor/, no dev deps — the runtime is pure PHP.
COPY src ./src
COPY resources ./resources
COPY demo ./demo

ENV FUNNYPOT_STYLE=realistic \
    FUNNYPOT_LOG=/app/demo/storage/hits.log

EXPOSE 8080

# php's built-in server with the demo front controller as the router.
CMD ["php", "-S", "0.0.0.0:8080", "-t", "demo", "demo/index.php"]
