# Demo dashboard v2: spec + implementation plan

Upgrades the standalone demo dashboard (`demo/index.php`) from "tail -200 with a 3s
full-refresh poll" to a T-Pot-inspired live console: history paging, delta AJAX, an
optional SQLite store for real stats, GeoIP enrichment, an attacker map, and a set of
aggregate widgets. The demo must stay a one-command `docker compose up` and must keep
working with zero new services and zero DB (file-only fallback everywhere).

## Invariants every phase MUST respect

- Emulate output only. NEVER execute attacker input. No eval/shell/real-fs writes from
  request data or outbound fetches triggered by a hit. GeoIP is a local mmdb read; all
  "reputation" links are user-clicked `<a href>`s, never server-side fetches.
- Reflect, never harm: no decompression bombs, no retaliation, no active scanning of
  sources (no rDNS even, it's an outbound probe).
- The dashboard renders attacker-controlled strings (path, UA, body, referer). Every
  render goes through the existing `esc()`; JSON feeds stay `Cache-Control: no-store`.
- The dashboard must not make the host a real vulnerable service: new endpoints are
  GET-only and read-only, all SQL is prepared statements, cursors/limits/filters are
  regex-validated and clamped, the DB file lives in `demo/storage/` (all requests route
  through `index.php`, so it is never directly servable).
- Fakes stay inert: example.com, RFC-5737 IPs, seeded dummy secrets. RFC-1918/5737 and
  loopback sources are skipped by GeoIP (no fake geo for lab traffic, show "local").
- Runtime is PHP >= 8.0 (promoted ctors ok; no enums/readonly), matching SPEC.md.
- No JS build step. Vanilla JS as today; the only vendored asset is Leaflet (Phase 4).

## Current state (what we build on)

- `demo_log()` appends one JSON object per hit to `FUNNYPOT_LOG`
  (default `demo/storage/hits.log`) + echoes to stderr.
- Hit schema today: `ts, ip, method, path, ua, matched, severity, templates[], served,
  style, body, referer, log4shell, honeytoken`. There are also decoy events
  (`event: "decoy-archive", decoy`) with a shorter field set. The plan treats the JSON
  line as the canonical record; the DB is a queryable copy.
- `GET /?feed=1` re-sends the last 200 rows + stats every poll; the client re-renders the
  whole table and uses a `ts|ip|path` Set to detect "new" for the flash animation.
- Docker: baked image, nginx+php-fpm, ~19 published ports, no volume (log dies with
  the container; Phase 2 fixes that too).

## File layout after the work

```
demo/
  index.php              # front controller: routing + honeypot path only (thin)
  lib/
    store.php            # demo_store_*: FileStore/SqliteStore behind one function set
    feed.php             # demo_feed_*: snapshot / delta / pager / map / aggregate JSON
    geoip.php            # demo_geoip(): mmdb lookup + per-process cache
    dashboard.php        # demo_render_shell() (HTML shell moved out of index.php)
  assets/                # exact-match whitelist, served via /__fp/<name>
    app.js  app.css      # dashboard JS/CSS (moved out of heredocs)
    leaflet.js  leaflet.css   # vendored Leaflet 1.9.x (BSD-2), Phase 4
    world.geo.json       # Natural Earth 110m countries (public domain), Phase 4
  bin/
    import-log.php       # backfill hits.log -> hits.db (idempotent)
  storage/               # hits.log, hits.db, GeoLite2/DB-IP .mmdb files (volume-mounted)
```

Asset routing: in `index.php`, before the honeypot path, serve `GET /__fp/{name}` from
`demo/assets/` only for an exact hardcoded map of filenames to content-types; any
other `/__fp/...` falls through to the honeypot like any probe. (Homepage already
reveals the demo is a honeypot, so the prefix isn't a leak; real deployments drop the
dashboard anyway, per demo/README.md.)

---

## 1. View older logs / pagination

**Design.** One paged endpoint, newest-first pages walking backwards:

```
GET /?feed=page&before=<cursor>&limit=100
      [&from=2026-08-01&to=2026-08-17&ip=203.0.113.9&matched=1&severity=critical&q=wp-]
->  { "v":2, "rows":[ ...oldest page slice, newest first... ],
      "next_before":"d:8213" | null,     // null = beginning of history reached
      "mode":"db"|"file" }
```

- **Cursor is opaque, mode-prefixed:** `d:<id>` (DB rowid) or `f:<byteoffset>` (file).
  Validated with `/^[df]:\d{1,15}$/`; anything else returns a 400 JSON error.
- **DB mode:** `WHERE id < :before [AND filters] ORDER BY id DESC LIMIT :n`. Indexed,
  O(page). All filters supported (`q` is `LIKE` on path/ua/body, prepared).
- **File mode:** read the file backwards in 64KB blocks from the byte offset, split
  lines, JSON-decode, take `limit` rows; `next_before` = byte offset of the oldest row
  returned. Supports `before/limit` only; date/ip filters are applied post-decode within
  the scanned window (documented as best-effort). A rotated or truncated file (offset >
  filesize) returns `{"reset":true}` and the client restarts from the top.
- **UI:** the live table stays as-is (live window). Below it a "Load older" button
  appends the next page into a separate "history" tbody; a date-range pair + ip/severity
  selects re-query from scratch. History rows never flash and are excluded from the
  live `seen` set.

**Effort:** ~half a day file-mode + UI, +2-3h for the DB-mode filters (Phase 2 lands
them). Pure PHP, no deps.

## 2. Efficient AJAX: delta feed with a cursor

**Design.** Replace "resend all 200 rows" with snapshot-then-delta:

```
GET /?feed=1                       # initial (no cursor)
->  { "v":2, "mode":"db", "cursor":"d:8412",
      "stats":{ "total":n,"detections":n,"served":n,"ips":n,"harvested":n },
      "rows":[ last 200, newest first ] }

GET /?feed=1&after=d:8412          # poll
->  { "v":2, "cursor":"d:8419", "stats":{...}, "rows":[ only rows after 8412 ] }
      # nothing new -> "rows":[], same cursor (tiny constant-size response)

any stale/invalid cursor (rotation, db reset, downgrade)
->  { "v":2, "reset":true, ...full snapshot payload... }
```

- **DB mode cursor** = last rowid: exact, monotonic, immune to same-second collisions
  (fixes the current `ts|ip|path` dedupe key, which drops identical repeated probes).
  Delta query: `WHERE id > :after ORDER BY id ASC LIMIT 500` (cap; if 500 hit, client
  polls again immediately).
- **File mode cursor** = byte offset of EOF at read time. Delta = `fopen`+`fseek(offset)`
  and read only appended bytes. This is O(new data), no full-file scan. A torn final line
  (writer mid-append; writes are `LOCK_EX` single-`fwrite` so rare) is left for the next
  poll by only advancing the cursor past the last `\n`.
- **Client:** prepends `rows` to the table top, trims the live table at 200 DOM rows,
  flashes each prepended row (no `seen` Set needed anymore).
- **Stats:** DB mode recomputes exact stats per poll with indexed `COUNT`s (fine at
  demo scale; see §3 note). File mode keeps stats exact by scanning only on snapshot,
  then incrementing client-side from delta rows (`total/detections/served/harvested`
  are pure increments; unique-`ips` uses a client Set seeded lazily. It stays
  drift-free after a `reset`, and any drift heals on next full snapshot/reload).

**Effort:** ~half a day (both modes + client rewrite), shared plumbing with §1.

## 3. Optional database, engine choice: SQLite

**Weigh-up for this workload** (append-heavy writes from N php-fpm workers, tail reads
every 3s, aggregate GROUP BYs, geo fields on the row):

| Engine | Verdict |
|---|---|
| **SQLite (chosen)** | In-process via `pdo_sqlite` (already in the PHP image). WAL mode handles many fpm writers at honeypot rates (hundreds/s) with `busy_timeout`. Aggregates over millions of rows are fast with the indexes below. Zero extra containers: the "docker" part is a named volume, which the demo needs anyway for log persistence. Keeps `docker compose up` one service. |
| Postgres | Fine engine, but adds a second container, credentials, healthcheck/wait-for ordering, and a PHP driver requirement, all cost with no payoff at demo scale. Documented as the swap-in if someone runs funnypot as a long-lived multi-host collector (schema below is portable). |
| ClickHouse | Built for exactly this shape at *billions* of rows; at demo scale it's a 1GB+ container and merge-tree ops burden. No. |
| DuckDB | Great analytics, but PHP bindings are immature and concurrent appenders from fpm workers are not its model. No. |

**Schema (SQLite DDL; portable to Postgres with `SERIAL`/`JSONB` swaps):**

```sql
PRAGMA journal_mode=WAL;          -- set once at create
-- per-connection: PRAGMA busy_timeout=2000; PRAGMA synchronous=NORMAL;

CREATE TABLE hits (
  id        INTEGER PRIMARY KEY,          -- rowid alias; the delta/pager cursor
  ts        TEXT NOT NULL,                -- ISO-8601 UTC, as logged
  ip        TEXT NOT NULL,
  method    TEXT,
  path      TEXT,
  ua        TEXT,
  matched   INTEGER NOT NULL DEFAULT 0,
  severity  TEXT,
  templates TEXT,                         -- JSON array, as logged
  served    INTEGER NOT NULL DEFAULT 0,
  style     TEXT,
  body      TEXT,
  referer   TEXT,
  log4shell TEXT,
  honeytoken TEXT,
  event     TEXT,                         -- 'decoy-archive' etc; NULL for normal hits
  -- GeoIP enrichment (Phase 3; NULL when disabled/private-source)
  country   TEXT,                         -- ISO alpha-2
  city      TEXT,
  asn       INTEGER,
  as_org    TEXT,
  lat       REAL,
  lon       REAL,
  raw       TEXT NOT NULL                 -- the exact JSON line (source of truth copy)
);
CREATE INDEX idx_hits_ts         ON hits(ts);
CREATE INDEX idx_hits_ip         ON hits(ip);
CREATE INDEX idx_hits_matched_id ON hits(matched, id);
CREATE INDEX idx_hits_country    ON hits(country) WHERE country IS NOT NULL;
```

**Ingest path.** `demo_log()` becomes: build the entry, append the JSON line and stderr
(unchanged, canonical), then call `demo_store_insert($entry)` in a try/catch that can
never fail the request (if the DB is missing or locked, the line still landed in the log). No tailer process:
the front controller writes both sinks in-request, so file and DB agree per hit.
`FUNNYPOT_DB` env (default `demo/storage/hits.db`; set `0` to disable). First write
creates the schema (`CREATE TABLE IF NOT EXISTS`).

**Backfill / repair:** `php demo/bin/import-log.php [hits.log] [hits.db]` streams the
log, inserts rows not already present (match on `raw` line hash), applies GeoIP if
configured. Run once when upgrading an existing deployment; also the recovery story if
the DB is ever deleted.

**No-DB fallback:** `demo_store_*` functions dispatch on whether PDO opened; every feed
endpoint has the file-mode branch from §1/§2. `php -S` with no docker still works.

**docker-compose change** (the whole of it, persistence for log + db + mmdb):

```yaml
services:
  funnypot:
    # ...existing build/ports/env...
    environment:
      FUNNYPOT_STYLE: realistic
      FUNNYPOT_DB: /app/demo/storage/hits.db
      FUNNYPOT_GEOIP_DIR: /app/demo/storage/geoip
    volumes:
      - funnypot-data:/app/demo/storage
volumes:
  funnypot-data:
```

(Appendix in the doc footer: optional `postgres:16-alpine` service + `FUNNYPOT_DB_DSN`
override for collector-scale installs, not part of the build.)

**Effort:** ~1 day: store module + insert + importer + compose/volume + docs, plus the
§1/§2 DB branches.

## 4. GeoIP enrichment

**Design.** Offline MMDB lookup at write time in `demo_log()` (never at render
time; enrich once, query forever). `demo/lib/geoip.php`:

- Reader: **`maxmind-db/reader`** (official, pure-PHP, Apache-2.0) as a demo-only
  composer dev/suggest dependency. The package's "runtime require = PHP only" invariant
  is about `src/`; the demo image may compose-install it. Optional `ext-maxminddb`
  speeds it up but is not required. (Writing our own MMDB parser is not worth it.)
- Databases in `FUNNYPOT_GEOIP_DIR`: `city.mmdb` (+ optional `asn.mmdb`). Two sources:
  - **DB-IP Lite** (ip-to-city-lite, ip-to-asn-lite): CC BY 4.0, direct download,
    no account or key, so this is the demo default. Attribution required: dashboard footer gets
    "IP geolocation by DB-IP".
  - **MaxMind GeoLite2** City/ASN: free but EULA-gated. It requires a MaxMind account and
    license key (post-2019 policy), and must not be committed to the repo or baked into a
    published image; users fetch with `geoipupdate` or the permalink+key. Footer
    attribution "Includes GeoLite2 data created by MaxMind" when used.
  - `scripts/fetch-geoip.sh` downloads DB-IP Lite by default, GeoLite2 when
    `MAXMIND_LICENSE_KEY` is set. Run on host into the volume; never at image build
    (keeps the image redistributable and the repo mmdb-free; add `*.mmdb` to
    `.gitignore`).
- Lookup: per-process static cache `ip → geo` (scanners hammer from few IPs); skip
  private/loopback/RFC-5737 sources (`geo = null`, UI shows "local"). If the mmdb or
  reader is missing, enrichment is silently off; nothing else breaks.
- Fields onto the hit (log line *and* DB row): `country, city, asn, as_org, lat, lon`.
  Feed rows carry `country` (flag emoji derived client-side from alpha-2) and lat/lon
  for the map.

**Effort:** ~half a day incl. fetch script + attribution footer.

## 5. OpenStreetMap attacker map

**Design.** Leaflet, vendored (`demo/assets/leaflet.{js,css}`, BSD-2, ~180KB total,
served via `/__fp/`, no CDN). Two tile strategies, env-switched:

- **Default: fully self-contained.** No raster tiles at all. A dark-styled
  `L.geoJSON` world layer from vendored Natural Earth 110m countries
  (`world.geo.json`, public domain, ~250KB). Zero external requests: CSP-clean,
  works air-gapped, and the viewer's browser never leaks the dashboard to a tile CDN.
- **Optional: `FUNNYPOT_MAP_TILES=osm`** switches to `tile.openstreetmap.org` raster
  tiles (prettier; fine for a demo under the OSM tile usage policy, with the required
  attribution control). Off by default because it breaks self-containment.

Data + behavior:

```
GET /?feed=map
->  { "v":2,
      "points":[ {"ip":"203.0.113.9","lat":53.3,"lon":-6.2,"country":"IE",
                  "count":412,"matched":390,"last_ts":"..."} , ... top 500 by count ],
      "countries": {"IE":412,"CN":230,...} }
```

- DB mode: `GROUP BY ip` with lat/lon (indexed); file mode: aggregate the last 5,000
  lines only (documented cap). Polled every 10s.
- Rendering (T-Pot-attack-map inspired, but no websockets; polling is enough):
  circle markers per source, radius ~ log(count), colored by top severity; on each new
  hit from the live delta feed (§2) an animated arc (SVG polyline, ~1.2s) from
  source to the honeypot marker (`FUNNYPOT_MAP_HOME="53.35,-6.26"` env, default 0,0
  "unknown" hides the home marker) plus a marker pulse. Click a marker for a popup with
  ip, country/city/ASN, counts, and a "session view" link (§6).
- Map sits in a collapsible panel above the table; hidden entirely (no Leaflet loaded)
  when GeoIP is off. The dashboard must not show an empty map in the zero-config path.

**Effort:** ~1 day (vendor assets, map panel, arcs, aggregate endpoint).

## 6. T-Pot-inspired extras (chosen subset)

Stolen from T-Pot's Kibana set (attack histogram, top attacker IPs/countries/ASNs, CVE
tags, credential tag clouds, per-IP drill-down, 1m/1h/1d counters, reputation
link-outs), sized for one PHP file + vanilla JS:

| Widget | Design | Effort |
|---|---|---|
| **Events 1m / 1h / 24h** | three stat tiles from indexed `COUNT ... WHERE ts >` (file mode: counted from tail scan); T-Pot attack-map's headline stat | 1h |
| **Attack histogram** | 48 half-hour buckets, last 24h, stacked matched/unmatched, pure CSS bars (no chart lib), `GET /?feed=agg` | 3h |
| **Top talkers** | top 10 IPs: flag, count, top severity, last-seen, user-clicked link-outs to Talos/AbuseIPDB (`<a href>` only, never fetched server-side) | 2h |
| **Top templates / CVE board** | top 15 template ids from `templates[]`; ids matching `/^CVE-/i` styled as CVE chips, "what the internet is scanning for today" | 2h |
| **Harvested credentials cloud** | tag cloud of user/pass strings parsed from captured `body` on login-fake paths (fakes are inert, so the creds are attacker-chosen strings; esc() rendered) | 2h |
| **Session view** | click any IP to filter the live+history table to that IP via §1's `ip=` filter, plus header strip: first/last seen, hit count, geo/ASN, persona seed, honeytoken verdicts | 3h |
| **Live ticker** | one-line marquee of the latest hit ("203.0.113.9 → GET /.env — SCAN high — fake served"), driven by the §2 delta, no extra endpoint | 1h |

Skipped deliberately: websocket streaming (polling delta is enough at demo scale; keeps
nginx/fpm config untouched), Suricata-style protocol breakdown (single HTTP service),
Elasticsearch/Kibana anything (violates "simple to run").

`GET /?feed=agg` returns all widget data in one payload
(`{buckets:[], top_ips:[], top_templates:[], creds:[], counters:{m1,h1,d1}}`), polled
every 10s; file mode computes it from a bounded tail (last 5,000 lines) and labels the
UI "recent window" instead of "all time".

---

## Phased build order

1. **Phase 1: refactor + delta feed + paging (no deps, no schema change).**
   Split `index.php` into `lib/` + `assets/` with the `/__fp/` whitelist; ship §2
   delta cursor (file mode) and §1 "Load older" (file mode). Demo behaves identically
   with a fraction of the AJAX traffic. *~1.5 days.*
2. **Phase 2: SQLite store.** §3: store module, dual-write in `demo_log()`, importer,
   compose volume + `FUNNYPOT_DB`; switch feed/pager/stats to DB branches with
   file fallback intact. *~1 day.*
3. **Phase 3: GeoIP.** §4: fetch script (DB-IP default / GeoLite2 keyed), write-time
   enrichment, country flags in the table, attribution footer. *~0.5 day.*
4. **Phase 4: Map.** §5: vendored Leaflet + GeoJSON world, `feed=map`, arcs/pulses
   wired to the delta feed. *~1 day.*
5. **Phase 5: Widgets.** §6 in the order listed (counters, histogram, top talkers,
   CVE board, creds cloud, session view, ticker). Each is independently shippable.
   *~1.5 days.*

Total ≈ 5.5 focused days. Each phase leaves the demo releasable; nothing after Phase 1
is required for the demo to keep its "clone, `docker compose up`, done" story.

## Appendix: optional Postgres overlay (collector-scale only)

```yaml
# demo/docker-compose.pg.yml  (docker compose -f docker-compose.yml -f docker-compose.pg.yml up)
services:
  funnypot:
    environment:
      FUNNYPOT_DB_DSN: "pgsql:host=db;dbname=funnypot"
      FUNNYPOT_DB_USER: funnypot
      FUNNYPOT_DB_PASS: funnypot        # demo-only credential
    depends_on: [db]
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: funnypot
      POSTGRES_USER: funnypot
      POSTGRES_PASSWORD: funnypot
    volumes:
      - funnypot-pg:/var/lib/postgresql/data
volumes:
  funnypot-pg:
```

Same schema with `id BIGSERIAL PRIMARY KEY`, `templates JSONB`; requires `pdo_pgsql`
added to the demo image. Not built until someone actually runs funnypot as a
multi-sensor collector.
