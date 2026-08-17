# funnypot — standalone honeypot demo

Runs funnypot as a **self-contained honeypot server**. Drop it on a box, point traffic at it,
and every scanner that probes it gets served a plausible fake while you watch the hits land on a
live dashboard. Same codebase as the composer library — this just wires it into a front controller.

- `GET /` → a **"Welcome to funnypot"** homepage + a live dashboard of recent hits (auto-refresh 5s)
- anything else → funnypot detects the scanner probe, serves a fake if it matches, and **logs every
  request** — detections *and* non-detections — as JSON lines (to the log file and to stderr, so
  `docker logs` shows them live)

## Run it

**Docker (compose):**

```bash
cd demo
docker compose up --build
```

**Docker (plain run):**

```bash
docker build -f demo/Dockerfile -t funnypot .
docker run --rm -p 8080:8080 funnypot
```

**No Docker (local PHP — dev/poke only):**

```bash
php -S 0.0.0.0:8080 -t demo demo/index.php
```

Then open <http://localhost:8080> for the dashboard.

> Use Docker (nginx + php-fpm) for anything a scanner will actually hit. `php -S` is
> **single-process** — it serves one request at a time, so a scanner's concurrent flood
> queues up and times out (nuclei then marks the host unresponsive and quits, matching
> almost nothing). The Docker image runs php-fpm with a worker pool + opcache and caches
> the compiled index per worker, so it stays responsive under load.

## Try it

From another shell, act like a scanner:

```bash
curl http://localhost:8080/.git/config          # served a believable fake git config
curl http://localhost:8080/.env                 # served a believable fake .env
curl http://localhost:8080/nope                 # a normal 404 (logged as a non-detection)
curl -O http://localhost:8080/backup.zip        # a nested decoy archive — unzip it, find another zip…
nuclei -u http://localhost:8080 -t http/exposures/   # watch dozens light up on the dashboard
```

A `.zip` / `.tar.gz` probe on a path with no template gets a **nested decoy archive** instead of a
404: peel a layer, find another archive, repeat down to fabricated secrets. It wastes an attacker's
time re-extracting — bounded (a few KB, extracts to a few KB), never a decompression bomb. Rebuild
the assets with `scripts/build-decoys.sh`; disable with `FUNNYPOT_DECOY_ARCHIVE=0`.

Watch them appear on the homepage, and stream the raw log with `docker logs -f <container>`.

## Config (env)

| Env | Default | Meaning |
|---|---|---|
| `FUNNYPOT_STYLE` | `realistic` | `minimal` \| `realistic` \| `taunt` |
| `FUNNYPOT_LOG` | `demo/storage/hits.log` | where hit JSON lines are written |
| `FUNNYPOT_DECOY_ARCHIVE` | on | serve a nested decoy archive for `.zip`/`.tar.gz` 404s; `0` to disable |

> The demo serves a fake to **every** matched probe (`gate` is always open) and reveals itself on
> the homepage — that's the point of a *demo*. For real deployment, gate on your own suspicion
> signal and drop the give-away homepage.
