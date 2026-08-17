# funnypot 🍯

**A reverse firewall / honeypot that is the _inverse_ of a [nuclei](https://github.com/projectdiscovery/nuclei) scanner.**

A nuclei scanner sends crafted requests and matches the *response* to decide "this target
is vulnerable to CVE-X". funnypot does the reverse: it takes an incoming (suspicious) request,
works out which nuclei template(s) it is probing for, and either

- **detects** it — a signal that the request is a known scanner probe (template ids, severity, tags), or
- **responds** — synthesizes a response that *satisfies those templates' matchers*, so the scanner
  reports the host "vulnerable" and the attacker wastes time triaging a decoy.

It ships a prebuilt index compiled from ~11k nuclei HTTP templates (**5,000+** invertible). The
**runtime needs PHP only** — no YAML, no extensions, no network. Framework-agnostic core with
PSR-15 and Laravel adapters.

> Defensive deception for your own infrastructure. Every fake is inert (example.com hosts,
> RFC-5737 IPs, dummy secrets) and never a real or working credential.

---

## Install

```bash
composer require bobbymaher/funnypot
```

## Quick start

Detect mode is always safe — it never writes to the wire:

```php
use Funnypot\NucleiInverter;
use Funnypot\RequestContext;

$funnypot = NucleiInverter::default();

$detection = $funnypot->detect(RequestContext::fromGlobals());
if ($detection->matched) {
    // feed your abuse scoring / rate limiter / ban list
    logScannerProbe($detection->templateIds(), $detection->highestSeverity, $detection->tags());
}
```

Respond mode (the honeypot) is opt-in and gated by your app:

```php
use Funnypot\Config;
use Funnypot\NucleiInverter;
use Funnypot\RequestContext;
use Funnypot\Http\ResponseEmitter;

$funnypot = NucleiInverter::default(new Config(
    mode: 'respond',
    gate: fn (RequestContext $r) => isSuspicious($r),   // your suspicion predicate
    responseStyle: 'realistic',                          // minimal | realistic | taunt
));

$response = $funnypot->respond(RequestContext::fromGlobals());
if ($response !== null) {
    ResponseEmitter::emit($response);
    exit;
}
// else: serve your normal 404
```

## Response styles

Set at init with `responseStyle`:

| Style | What the attacker gets |
|---|---|
| `minimal` | Just the tokens the matcher needs. Smallest, the default. |
| `realistic` | A believable fake — a full `.git/config`, a plausible `.env`, a real XML-RPC `methodResponse`. All values inert. |
| `taunt` | Still satisfies the scanner (time still wasted) **and** carries a visible `nice try — honeypot — your scan was logged` marker. |

Rich content is produced by **endpoint emulators** (git, env, xmlrpc, wp-config, wp-login, phpinfo,
htpasswd, server-status, package.json, ssh-key, sql-dump) and is *validated against the matcher*
before use — if it wouldn't satisfy the scanner, it silently falls back to minimal. Richness can
never break the guarantee.

## Laravel: send 404s to funnypot

The service provider auto-registers. Publish the config and wire your exception handler's 404 path.
See [`examples/laravel-exception-handler.php`](examples/laravel-exception-handler.php) for the full
drop-in; the essence:

```php
// app/Exceptions/Handler.php  (render(), on a 404)
use Funnypot\Inverter;
use Funnypot\RequestContext;
use Funnypot\Http\ResponseEmitter;

if ($e instanceof \Symfony\Component\HttpKernel\Exception\NotFoundHttpException) {
    $response = app(Inverter::class)->respond(RequestContext::fromGlobals());
    if ($response !== null) {
        ResponseEmitter::emit($response);
        exit;
    }
    // else fall through to your normal 404 view
}
```

Config (`config/funnypot.php`, published): defaults to `mode = detect` (inert). Turn on the honeypot
by setting `mode = respond` and supplying a `gate`. Start detect-only, watch the logs, then flip
respond on.

Or use the PSR-15 / Laravel middleware — see `src/Http/InverterMiddleware.php` and
`src/Laravel/InverterMiddleware.php`.

## Run as a standalone honeypot (Docker)

funnypot is also a drop-on-a-server honeypot on its own — no host app required. The
[`demo/`](demo/) directory is a full front controller: a **"Welcome to funnypot" homepage with a
live dashboard**, and every other request is run through the honeypot and **logged (detections and
non-detections alike)** to stderr and a file.

```bash
# compose
cd demo && docker compose up --build

# or plain docker
docker build -f demo/Dockerfile -t funnypot . && docker run --rm -p 8080:8080 funnypot

# or no docker
php -S 0.0.0.0:8080 -t demo demo/index.php
```

Open <http://localhost:8080>, then point a scanner at it (`nuclei -u http://localhost:8080 -t http/exposures/`)
and watch the hits land. See [`demo/README.md`](demo/README.md).

## How it works (compile once, serve forever)

```
        BUILD-TIME (CI, needs symfony/yaml)          RUNTIME (your app, PHP only)
  nuclei-templates/*.yaml                          incoming request
        |  parse + invert matchers                        |  one hash probe
        |  group by (method, path)                        v
        |  merge into coherent personas            route -> persona bundle
        v                                                 |
  resources/compiled/nuclei-index.full.php  --------------+  detect() or respond()
        (a plain PHP array, opcache-friendly)
```

The app never parses templates. It loads the frozen array and does an O(1) lookup. See
[`SPEC.md`](SPEC.md) and [`docs/PERSONA-CAP.md`](docs/PERSONA-CAP.md).

## Keeping up with nuclei

funnypot ships a prebuilt index, so `composer update` is all a consumer needs. To refresh the index
from the latest templates:

```bash
php bin/funnypot compile /path/to/nuclei-templates/http \
  --out=resources/compiled/nuclei-index.full.php
```

This repo's [`.github/workflows/update-templates.yml`](.github/workflows/update-templates.yml) does
it automatically: weekly (and on demand) it pulls the latest nuclei-templates release, recompiles,
runs the **real-nuclei golden test**, and opens a PR with the refreshed artifact only if it passes.

## Safety

- **Inert by default** — a fresh install is detect-only, gate closed; zero bytes on the wire.
- **Gate chain** — kill switch -> mode -> trusted-bypass (your own scanners see the *real* posture) ->
  suspicion gate -> severity ceiling -> coherent persona -> root-path guard -> body-size cap.
- **Never reflects attacker input**; never deserializes a request body; all synthesized headers are
  CRLF/NUL-safe.
- **Coherent personas** — one believable host per scanner (deterministic, spoof-proof seed), not an
  impossible "vulnerable to everything" fingerprint.

## Testing

```bash
composer install
vendor/bin/phpunit                 # 146 unit + compiler tests
bash tests/acceptance/run.sh       # real nuclei (Docker) vs a php -S server
```

## Licence

MIT — see [LICENSE](LICENSE). Derived in part from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT, © 2025 ProjectDiscovery, Inc.); the upstream notice is retained at
[resources/UPSTREAM-LICENSE.md](resources/UPSTREAM-LICENSE.md).
