# Runtime rules updates — immutable registry artifact

How to let a deployed funnypot install pull a fresh, verified rule set (nuclei-derived
routing corpus + CRS-derived attack templates + product-decoy routes) **without** a new
`funnypot-core` composer release and without a fleet-wide `composer update`. Champions one
architecture — a signed, versioned artifact fetched over plain HTTPS and swapped in
atomically — and rejects the OCI+cosign sibling design after pricing out what it would
actually cost this specific, dependency-free PHP codebase to operate.

**Verdict up front:** build **funnypot-rules** as a GitHub-Releases-distributed tarball,
Composer-shaped but not Composer-fetched, integrity-checked by sha256 and authenticity-checked
by an ed25519 signature verified with `sodium_crypto_sign_verify_detached()` — the same
primitive this codebase already trusts for the SSH honeypot's host key
(`funnypot/src/Protocol/Ssh/HostKey.php:28-48`, `sodium_crypto_sign_keypair()` /
`sodium_crypto_sign_detached()`). Not OCI+cosign. The reasoning is in
[§8](#8-why-not-oci--cosign-the-honest-comparison).

---

## 1. Grounding: today's load path (file:line)

Every compiled artifact is loaded the same way — a hardcoded, package-relative path, read
once per worker and cached in a static array:

- `PhpArrayStore::fromPackage()` → `dirname(__DIR__, 2) . '/resources/compiled/nuclei-index.full.php'`
  (`funnypot-core/src/Store/PhpArrayStore.php:79-82`), materialized via `require` and cached
  in `PhpArrayStore::$fileCache` keyed by path (`PhpArrayStore.php:46,56-69`) — "restart the
  worker to pick up a recompiled index" is already a documented invariant
  (`PhpArrayStore.php:51-55`).
- `TemplateAttackEmulator::fromPackage()` → `.../resources/compiled/funnypot-attack.php`
  (`funnypot-core/src/Template/TemplateAttackEmulator.php:47-49`).
- `RouteTemplateSet::fromPackage()` → `.../resources/compiled/funnypot-routes.php`
  (`funnypot-core/src/Response/RouteTemplateSet.php:31-34`).
- `ProtocolTemplateSet::fromPackage()` → `.../resources/compiled/funnypot-protocols.php`
  (`funnypot/src/Protocol/ProtocolTemplateSet.php:24-27`, app repo).
- `EmulationCatalog::fromPackage()` → `.../resources/compiled/funnypot-catalog.php`
  (`funnypot-core/src/Policy/EmulationCatalog.php:32-35`).

`Honeypot::__construct()` takes a `CompiledStore` by DI, so the routing index is already
swappable by a caller that builds its own `PhpArrayStore::fromFile($path)`. But
`Honeypot::default()` calls `TemplateAttackEmulator::fromPackage()` directly inside the
constructor (`Honeypot.php:56-57`), and `EmulatorRegistry::default()` calls
`RouteTemplateSet::fromPackage()` directly (`EmulatorRegistry.php:26`) — **two of the five
compiled artifacts have no injection seam at all today.** Any runtime-update design has to
add one, or it only half-works.

Today's actual "update": `.github/workflows/update-templates.yml` and `update-crs.yml` in
`funnypot-core` recompile on a schedule, run `phpunit` + real-nuclei golden acceptance
(`tests/acceptance/run.sh`), run `scripts/ci/check-license.sh` and
`scripts/ci/check-fingerprint-safety.php` (both already implemented and already wired into
both workflows — confirmed by reading the files directly, not just SPEC.md), and open a PR
against `funnypot-core` itself. A human merges it. Every consumer then needs
`composer update bobbymaher/funnypot-core` (or a version bump + redeploy) to see it. That
composer round-trip, multiplied across every app/server that embeds the package, is the
"too heavy" problem this doc solves.

---

## 2. Architecture at a glance

```
 funnypot-core (unchanged)               funnypot-rules (new repo)            consumer host
 ─────────────────────────               ──────────────────────────           ──────────────
 templates/ + Compiler/ +                 releases/vYYYY.WW.N/                RulesLocator
 CrsCompiler/  ──(CI, human-              ├─ resources/compiled/*.php         resolves the
 reviewed PR, unchanged)──►               ├─ manifest.json + crs-manifest     active path:
 resources/compiled/*.php                 ├─ upstream-licenses/*.LICENSE.md    env/config
 (the OFFLINE FLOOR, shipped              └─ SHA256SUMS                        override, else
 in every composer release)                                                    vendor-bundled
      │                                   release.json (signed)                floor
      │ publish job, human-triggered,     {version, sha256, built_at,               │
      │ GitHub Environment approval  ───► channel, key_id}                          │
      ▼                                   + release.json.sig (ed25519)              ▼
 (bytes identical to what already         published as GitHub Release        RulesUpdater
  passed phpunit + golden +               assets — plain HTTPS, Fastly       fetch → verify
  fingerprint-safety + license)           CDN, no auth for public repo       (sha256 + sig)
                                                                              → atomic swap
                                                                              → prune old
```

Two repos keep their existing jobs. `funnypot-core` still compiles and still ships a
bundled floor — nothing about today's composer-release path changes. `funnypot-rules` is a
**pure distribution surface**: it takes bytes that already passed every gate and republishes
them on a much faster, composer-independent cadence, signed so a consumer can trust them
without re-deriving them.

---

## 3. `funnypot-rules` layout

A GitHub repo, `bobbymaher/funnypot-rules`, deliberately shaped like a Composer package
(real `composer.json`, real SemVer git tags: `vYYYY.WW.N` — year.ISO-week.sequence, so a
version sorts by recency and two releases in the same week are still ordered) **so a team
that wants a normal `composer require bobbymaher/funnypot-rules` can still have one** — but
the primary distribution channel is GitHub Release assets, fetched directly, not through a
running `composer` process. See [§8](#8-why-not-oci--cosign-the-honest-comparison) for why
that split.

```
funnypot-rules/
├── composer.json                 # type: funnypot-rules-artifact; no autoload needed —
│                                  # this package is data, not code
├── README.md                     # trust model, public key, how to verify by hand
├── keys/
│   └── ed25519-2026.pub          # the CURRENT signing public key (also mirrored into
│                                  # funnypot-core, see §5 — two independent copies so a
│                                  # compromised funnypot-rules repo alone can't rewrite trust)
└── .github/workflows/
    └── publish.yml               # builds + signs + tags + uploads release assets
```

Per-release payload (what `git tag vYYYY.WW.N` + the publish workflow produces, not
committed to the repo's default branch — releases are append-only, the branch stays empty
of generated bytes):

```
funnypot-rules-v2026.34.0.tar.gz
├── resources/compiled/
│   ├── nuclei-index.full.php
│   ├── funnypot-attack.php
│   ├── funnypot-routes.php
│   ├── funnypot-routes-index.php
│   ├── funnypot-protocols.php
│   └── funnypot-catalog.php
├── manifest.json                 # unchanged shape — ArtifactWriter::write()'s own manifest
├── crs-manifest.json
├── skipped.json
└── upstream-licenses/
    ├── nuclei-templates.LICENSE.md
    └── coreruleset.LICENSE.md

release.json                      # signed metadata, NOT inside the tarball (see §5)
release.json.sig                  # detached ed25519 signature over release.json
SHA256SUMS                        # sha256 of the tarball, human-inspectable, informational
                                   # only — release.json.sha256 is the value actually checked
```

`release.json`:

```json
{
    "schema": 1,
    "version": "v2026.34.0",
    "channel": "stable",
    "built_at": "2026-08-19T06:14:02+00:00",
    "artifact": "funnypot-rules-v2026.34.0.tar.gz",
    "sha256": "b0e2b6c9…",
    "size_bytes": 6304920,
    "sources": {
        "nuclei_templates": { "tag": "v10.2.1", "sha": "2ec9141…" },
        "coreruleset":      { "tag": "v4.19.0", "sha": "9a41c0e…" }
    },
    "engine_schema": 1,
    "min_funnypot_core": "1.4.0",
    "key_id": "ed25519-2026"
}
```

`engine_schema`/`min_funnypot_core` matter because the compiled index's shape
(`PhpArrayStore`'s docblock schema-1 contract, `PhpArrayStore.php:15-22`) is a contract with
the *engine* code that reads it — an old `funnypot-core` must never load a rules release
built for a schema it doesn't understand. `RulesUpdater` refuses the swap if
`engine_schema` doesn't match `CompiledStore`'s own known schema constant, and the CLI
prints a clear "upgrade funnypot-core first" error rather than loading data the engine
can't interpret.

---

## 4. Transport

Plain HTTPS `GET` against `github.com/bobbymaher/funnypot-rules/releases/download/<tag>/<asset>`.
GitHub redirects release-asset downloads to `objects.githubusercontent.com`, which is
Fastly-fronted — the same CDN tier `ghcr.io` itself rides on, so choosing Releases over an
OCI registry costs nothing in cache hit rate or global distribution. Public repo, no
credential of any kind required for `stable`/`edge` fetches — the single biggest practical
win over any registry-based transport for the cron/headless case this doc is explicitly
asked to be honest about (constraint 5/7): there is no token to refresh, no `docker login`,
no credential helper.

Private/enterprise variant (a team forking funnypot-rules internally, or wanting a fork with
extra proprietary templates folded in): same code path, one extra header — a fine-grained
GitHub PAT or GitHub App installation token read from an env var
(`FUNNYPOT_RULES_TOKEN`), refreshed the same way any other CI secret is. This is strictly
simpler than an OCI registry's credential-helper chain (`docker-credential-*`, refresh
tokens, per-registry config files) because it is one bearer token against one well-known
API, not a pluggable credential-resolution protocol.

Client: PHP's `curl` extension (present on effectively every PHP install; funnypot-core
does not currently depend on it anywhere, so this is the one genuinely new baseline
assumption) with a `streams`-context fallback for the rare curl-less build. No SDK, no
Guzzle, no OCI client library. `grep`-confirmed: nothing in `funnypot-core`'s `composer.json`
or `src/` touches an HTTP client today — this is new either way, and a ~150-line
GET-with-retry wrapper is the smallest version of "new" available.

---

## 5. Trust model: signing and keys

**Why ed25519/libsodium and not cosign:** `sodium_crypto_sign_*` is already a proven,
shipped code path in this exact codebase family — `funnypot/src/Protocol/Ssh/HostKey.php`
generates an ed25519 keypair with `sodium_crypto_sign_keypair()` (line 28) and signs the SSH
exchange hash with `sodium_crypto_sign_detached()` (line 48) to answer real SSH clients'
host-key verification. `ext-sodium` is already an optional `suggest` in
`funnypot-core/composer.json`. Verifying a rules release's signature is the mirror-image
call, `sodium_crypto_sign_verify_detached()`, on infrastructure this codebase has already
exercised in production-shaped code — not a new cryptographic surface, not a new dependency
class, just the other half of a primitive already in the tree.

**Key model:**
- One maintainer-held ed25519 keypair per active key id (`ed25519-2026`). Private key lives
  only as an encrypted GitHub Actions secret (`FUNNYPOT_RULES_SIGNING_KEY`) scoped to a
  GitHub **Environment** (`rules-publish`) with a required-reviewer rule — publishing a
  release requires both (a) the workflow run and (b) a human clicking approve on that
  environment, on top of the human-reviewed-PR-merge gate `funnypot-core` already enforces.
  Compromising the release channel this way requires compromising two separate approval
  gates, not just repo write access.
- The public key ships in **two** independent places so a compromised `funnypot-rules` repo
  alone can't rewrite what's trusted: `funnypot-rules/keys/ed25519-2026.pub` (documentation
  / manual-verify convenience) and, authoritatively, baked into `funnypot-core` itself —
  `resources/rules-trust-keys.php` (new), a small `key_id => base64 public key` map shipped
  in the composer package and loaded the same inert way `resources/fingerprint-denylist.php`
  already is (`FingerprintGuard::fromPackage()`, `Crs/FingerprintGuard.php:36-38`). A
  consumer only trusts a rules release if its `release.json.key_id` is present in the
  `funnypot-core` version they run — bumping the trust set requires a new `funnypot-core`
  release, the same deliberate friction a TLS root-store update has.
- **Rotation:** add the new key id to `resources/rules-trust-keys.php` in a `funnypot-core`
  release *before* any release is signed with it, keep the old key id valid for an overlap
  window (both accepted), retire the old id in a later `funnypot-core` release once no
  supported version still needs it. Never a hard cutover that could brick an
  un-upgraded-but-still-fetching consumer.
- No transparency log, no independent auditability of "who signed this and when" beyond
  trusting the maintainer's own claim and CI logs. That is the real capability gap versus
  Sigstore/cosign — accepted deliberately; see §8.

---

## 6. Engine-side design

Three new pieces, `Funnypot\Rules\*` in `funnypot-core`, none of which the existing
`Honeypot`/`CompiledStore`/`TemplateAttackEmulator` call sites need to know exist unless a
consumer opts in.

### `RulesLocator` — the missing path-resolution seam

```php
final class RulesLocator
{
    /**
     * Directory holding the active compiled artifacts. Order: an explicit override
     * (env FUNNYPOT_RULES_PATH / Laravel config funnypot.rules_path) pointing at a
     * RulesUpdater-managed `current` symlink; else the path every fromPackage() call
     * already hardcodes today. A host that never calls rules:update gets byte-identical
     * behavior to today — this is additive, never a new requirement.
     */
    public static function resolve(string $packageDefault): string;
}
```

Every existing `fromPackage()` (`PhpArrayStore`, `TemplateAttackEmulator`, `RouteTemplateSet`,
`ProtocolTemplateSet`, `EmulationCatalog`) changes its one hardcoded path expression to
`RulesLocator::resolve($theSamePathItComputesToday)`. That is the entire blast radius in the
five existing classes — one line each, no behavior change for anyone not using the new
mechanism. It also closes the DI gap noted in §1: `TemplateAttackEmulator::fromPackage()`
and `EmulatorRegistry::default()`'s call to `RouteTemplateSet::fromPackage()` now honor the
override without needing new constructor parameters threaded through `Honeypot`.

### `RulesProvider` — read side

```php
interface RulesProvider
{
    public function currentVersion(): ?string;   // from the active manifest.json, null if never updated
    public function currentPath(): string;       // same value RulesLocator::resolve() would give
    public function manifest(): array;           // merged manifest.json + crs-manifest.json
}
```

Pure introspection, no network, no write access — safe to inject into a dashboard widget
(the app's `DashboardController` already surfaces `EmulationCatalog::fromPackage()` data at
`funnypot/src/App/Http/DashboardController.php:138`; a "rules freshness" panel is a one-line
addition reading `RulesProvider::manifest()['built_at']`/`['sources']`).

### `RulesUpdater` — write side: fetch → verify → atomic swap

```php
final class RulesUpdater
{
    public function __construct(
        private RulesFetcher $fetcher,     // HTTPS GET, curl-backed
        private SignatureVerifier $verifier, // sodium_crypto_sign_verify_detached against resources/rules-trust-keys.php
        private string $dataPath,          // e.g. storage_path('funnypot/rules') or --data-path
        private string $channel = 'stable',
    ) {}

    /** @throws RulesUpdateException on any failure — current release is never touched. */
    public function update(?string $pinVersion = null): RulesUpdateResult;

    public function rollback(string $toVersion): RulesUpdateResult; // point `current` at an already-downloaded release
}
```

Sequence, mirroring the tmp-write + `rename()` atomicity `ArtifactWriter::atomicWrite()`
already uses for a single file (`funnypot-core/src/Compiler/ArtifactWriter.php:79-88`), one
level up at the directory-pointer level:

1. Resolve target version: explicit `$pinVersion`, or the latest release on `$channel` via
   GitHub's Releases API (a plain unauthenticated JSON GET for the public repo).
2. Download `release.json` + `release.json.sig` + the tarball into
   `{dataPath}/tmp/<version>.<pid>/`.
3. Verify `sodium_crypto_sign_verify_detached($releaseJsonBytes, $sig, $trustedPublicKey)`
   using the key named by `release.json.key_id`, looked up in
   `resources/rules-trust-keys.php`. Unknown key id ⇒ fail closed.
4. Verify `hash('sha256', $tarballBytes) === release.json.sha256`. Mismatch ⇒ fail closed —
   this is the step that makes a re-pointed/tampered release asset harmless: the signature
   covers `release.json`, and `release.json` pins the exact tarball hash, so an attacker
   with write access to *just* the release asset (not the signing key) cannot substitute
   content silently.
5. Check `engine_schema` against the running `funnypot-core`'s known schema. Mismatch ⇒
   fail closed with an actionable message.
6. **Defense-in-depth, cheap because it needs no source checkout:** re-run
   `FingerprintGuard::fromPackage()->scan()` (already a plain-PHP class,
   `Crs/FingerprintGuard.php`) against the extracted `funnypot-attack.php` before it goes
   live — belt-and-suspenders against a compromised *publish* pipeline producing a leaky
   artifact that still carries a valid signature. See §7 for why this is fetch-side but
   the license check is not.
7. Extract the verified tarball to `{dataPath}/releases/<version>/`.
8. Atomic swap: `symlink({dataPath}/releases/<version>, {dataPath}/current.tmp.<pid>)` then
   `rename({dataPath}/current.tmp.<pid>, {dataPath}/current)` — a `rename()` over an
   existing symlink is atomic on the same filesystem (POSIX), so a request mid-flight
   always sees either the fully-old or fully-new target, never a half-swapped directory.
9. Prune: keep the last `N` (default 3) release directories under `{dataPath}/releases/`
   for instant, re-fetch-free rollback; delete older ones only after the new `current` is
   live.

Any failure at steps 2-6 leaves `{dataPath}/current` untouched and deletes the `tmp/`
scratch dir — the engine keeps serving whatever it was already serving. If `update()` has
never succeeded, `RulesLocator::resolve()` falls through to the vendor-bundled path and the
engine runs on the composer-shipped floor, fully functional, just as stale as the last
`funnypot-core` release — this is the whole of constraint 3 (fail-safe) and half of
constraint 5 (offline floor).

---

## 7. Where the safety gates run — publish vs. fetch, and why

**Fingerprint-safety** (`scripts/ci/check-fingerprint-safety.php`) and **license
compatibility** (`scripts/ci/check-license.sh`) already exist and are already wired into
`update-templates.yml` and `update-crs.yml` today — confirmed by reading both workflow
files directly, they are not aspirational. Nothing about this design changes where the
*primary* run happens: **publish time, in `funnypot-core`'s existing CI, unchanged.**

That placement is correct, not incidental, for a structural reason: the license check needs
the *raw upstream source tree* (`/tmp/nuclei-templates`, `/tmp/coreruleset`) to locate a
`LICENSE`/`COPYING` file and resolve an SPDX id (`check-license.sh` takes `<source-dir>` as
its first argument) — that tree exists only during the compile job, never again afterward. A
consumer fetching a rules release has no source checkout at all, only the compiled bytes;
there is nothing for the license gate to *do* at fetch time except trust that publish-time
already did it. So license compatibility is publish-only, full stop, and the fetch-time
integrity check (§6 step 3-4) is what lets a consumer trust that trust transitively: the
signature is only ever placed on an artifact that already passed the license gate, because
publishing is gated on the same CI run being green.

Fingerprint-safety is different: `check-fingerprint-safety.php` only needs the *compiled*
artifact (`FingerprintGuard::fromPackage()->scan()` against response bodies/headers in
`resources/compiled/funnypot-attack.php`) — no source tree required. That makes it cheap
enough to re-run at fetch time too, and worth it: it costs nothing (pure PHP, no network, no
external process) and buys real defense-in-depth against a compromised or buggy publish
pipeline that still manages to produce a validly-signed-but-leaky artifact (signing proves
*who* published it, not that what they published is safe — those are different guarantees).
So: fingerprint-safety runs **twice** — authoritatively at publish (as today, blocking the
PR/release), and again cheaply at fetch (blocking the swap) — while license compatibility
runs **once**, at publish, because fetch time structurally cannot do anything useful with
it.

---

## 8. Why not OCI + cosign — the honest comparison

The brief asks for OCI/cosign as sub-variant (a) and a Composer-shaped fetch as sub-variant
(b), and to champion the stronger one honestly. Priced out against this specific codebase,
(a) loses on the exact axes the brief asks to be explicit about: minimal deps, offline/cron
auth pain, and how much *new* infrastructure the choice drags in.

**What OCI+cosign would actually require here.** The OCI Distribution API itself (manifest
GET, blob GET, bearer-token auth) is plain HTTPS+JSON — a pure-PHP puller for it is
realistically buildable in a few hundred lines, no external binary needed for the *fetch*
half. Signature *verification* is the expensive half. `cosign`'s default keyless mode needs
a Fulcio-issued ephemeral certificate chain plus a Rekor transparency-log inclusion proof
verified at check time — reimplementing that trust chain in pure PHP means hand-rolling
X.509 chain validation against Sigstore's root plus Merkle inclusion-proof verification, a
substantially larger and more security-sensitive undertaking than the entire rest of this
design combined, and not something to DIY without a mature, audited PHP Sigstore client to
lean on. `cosign` key-pair mode (skip Fulcio/Rekor, verify a plain ECDSA-P256 signature with
a pinned public key) is closer to tractable — `openssl_verify()` is already an implicit
`ext-openssl` capability this package already suggests for the SSH cipher — but at that
point it is *doing the same job* as the ed25519/sodium scheme above, just with cosign's
OCI-annotation signature format layered on top for no added guarantee, and it still requires
either the `cosign` binary to actually verify against Rekor for its default offline-bundle
mode, or more hand-rolled format-parsing than the flat, self-describing `release.json` this
doc proposes.

**The dependency-injection problem.** Whichever verification mode, *pulling by digest* from
a registry needs an OCI client — `skopeo`/`oras`/`crane`, or a Docker daemon, or a from-
scratch PHP client. None of that exists anywhere in this codebase's dependency graph today:
`grep`-confirmed, `funnypot-core/composer.json` has zero registry/container tooling, and
every existing CI workflow (`update-templates.yml`, `update-crs.yml`) does nothing but
`git clone` + PHP. An OCI-first design would be the *first* piece of container/registry
tooling to touch this project, purely to move ~6 MB of PHP arrays around — a mismatched
amount of new operational surface for the actual problem. Concretely, on a bare EC2 box
running php-fpm with no Docker installed (a real, common funnypot deployment shape — this
is a honeypot meant to sit on ordinary web hosts, not inside a container platform), an
OCI-native design needs a new binary installed and kept patched on every host, or a bespoke
PHP OCI client maintained forever. The HTTPS-tarball design needs `curl`, which is already
there.

**Registry auth in cron — the constraint the brief explicitly wants addressed.** A private
OCI registry (ghcr.io included) needs a credential-helper-shaped token refresh cycle for
unattended cron pulls — the same class of operational pain Kubernetes `imagePullSecrets`
exists to paper over, awkward to reproduce for a bare cron/systemd-timer context with no
orchestrator underneath it. A bearer PAT read from one env var, refreshed by hand or by
whatever secret manager the host already uses, is strictly simpler, and for the public/OSS
case there is no credential at all.

**What OCI genuinely wins on, honestly.** Digest addressing is immutability *at the
protocol layer* — the address literally is the content hash, so a registry operator cannot
silently re-point `sha256:abcd…` to different bytes without every puller's own hash check
catching it anyway, but the *namespace itself* can't lie in the first place. GitHub Release
assets can technically be re-uploaded under an existing tag by someone with repo write
access; this design's immutability is enforced by *our own* signature+hash check at fetch
time (§6 steps 3-4), not by the transport being structurally incapable of misdirection.
In practice the two converge on the same outcome — a re-pointed asset fails verification and
the swap is refused — but OCI gets there by protocol guarantee and this design gets there by
verification code. And Sigstore's transparency log gives independent, third-party-auditable
proof of *who* signed *when*, which a single maintainer ed25519 key checked into
`funnypot-core` does not — that is a real, acknowledged gap (§5), acceptable for a
single-maintainer project, and the first thing to revisit if `funnypot-rules` ever grows
multiple independent trusted publishers.

Given all of that, for *this* codebase — pure-PHP by design, zero registry/container
tooling today, deployed on plain web hosts as often as containers, and already carrying a
proven pure-PHP signing primitive — the HTTPS-tarball-plus-ed25519 design delivers
equivalent practical guarantees (fail-safe, verified, atomic, rollback-capable) for
meaningfully less new operational surface. OCI+cosign is the more "industry-standard"-
looking answer; it is not the stronger one *here*.

---

## 9. CLI + PHP API

Extends `bin/funnypot` (`funnypot-core/bin/funnypot`, alongside the existing `compile` /
`compile-emulators` / `compile-routes` / `merge-routes` / `compile-crs` subcommands) rather
than inventing a second entrypoint:

```
funnypot rules:update [--channel=stable|edge] [--version=vYYYY.WW.N] [--data-path=PATH]
funnypot rules:rollback --version=vYYYY.WW.N [--data-path=PATH]
funnypot rules:status [--data-path=PATH]        # prints RulesProvider::manifest()
```

Standalone (non-Laravel) consumers wire this to cron/systemd-timer directly, or call the PHP
API in-process:

```php
$result = (new RulesUpdater($fetcher, $verifier, dataPath: '/var/lib/funnypot/rules'))->update();
```

`--data-path` has no default guess into a system directory — it is required (CLI) or must
be set in config (Laravel), matching this package's existing "inert unless the app opts in"
posture (`config/funnypot.php`'s docblock: "Defaults are INERT… does nothing until an app
deliberately opts in", `funnypot-core/config/funnypot.php:7-9`).

---

## 10. Laravel integration

New config keys in `config/funnypot.php` (published the same way as today, via
`php artisan vendor:publish --tag=funnypot-config`):

```php
'rules' => [
    'enabled' => env('FUNNYPOT_RULES_AUTO_UPDATE', false),   // opt-in, mirrors the mode default
    'channel' => env('FUNNYPOT_RULES_CHANNEL', 'stable'),
    'data_path' => storage_path('funnypot/rules'),
    'token' => env('FUNNYPOT_RULES_TOKEN'),                  // only for a private funnypot-rules fork
],
```

New Artisan command, `funnypot:rules:update`, registered in
`FunnypotServiceProvider::boot()` alongside the existing
`Console\UpdateTemplatesCommand::class` registration (`FunnypotServiceProvider.php:43-45`) —
additive, `UpdateTemplatesCommand` (full recompile from a local nuclei-templates checkout,
maintainer/CI use) is unchanged and keeps its separate job. Scheduler wiring is the
consumer app's own `routes/console.php` (or `Kernel::schedule()` pre-Laravel-11), not
something the package should register unprompted:

```php
$schedule->command('funnypot:rules:update')->hourly();
```

**Multi-server note, stated honestly rather than hidden:** `RulesUpdater` writes to local
disk. On a fleet of app servers each with their own local `storage/`, `rules:update` should
run on *every* node (each node fetches and swaps independently — the operation is
idempotent and read-only from the engine's perspective, so there is no coordination
requirement), not `->onOneServer()`. If the fleet instead shares a mounted `storage/`
(NFS/EFS), `->onOneServer()` is correct and cheaper. This package has no multi-server
orchestration concept anywhere else in its design (it is an embedded library, not a
service) and this design deliberately doesn't invent one — it documents the choice instead
of picking one silently.

**Worker-reload caveat.** `PhpArrayStore`'s own docblock already states the invariant this
design inherits unchanged: a persistent worker (php-fpm opcache, RoadRunner) caches the
parsed index for its process lifetime (`PhpArrayStore.php:51-55`). A `rules:update` swap
changes what `current` points at, but an *already-running* worker keeps serving the index it
loaded at boot until it is recycled — this is "eventually applied on next worker recycle,"
not "instantly applied mid-request," and should be stated in the same breath as the
scheduler wiring so nobody expects sub-second propagation. A rolling deploy or a
`php artisan octane:reload`-equivalent picks it up on the next cycle; nothing more invasive
is needed and nothing more invasive is safe to automate silently (killing all workers
because a background job just fetched new rules would be its own outage risk).

---

## 11. Publishing CI

A new job, gated behind the `rules-publish` GitHub Environment (§5), triggered manually
(`workflow_dispatch`) by the maintainer after a `funnypot-core` recompile PR is merged —
**never automatically chained off the PR merge itself**, preserving the existing
never-auto-merge, always-human-in-the-loop posture `update-templates.yml`/`update-crs.yml`
already established:

```yaml
name: publish-rules
on:
  workflow_dispatch:
    inputs:
      channel:
        description: 'stable | edge'
        required: false
        default: 'stable'

permissions:
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: rules-publish   # requires a human reviewer approval, separate from repo write access
    steps:
      - uses: actions/checkout@v4
        with:
          repository: bobbymaher/funnypot-core
      - name: Verify HEAD already passed the compile workflow
        run: gh run list --workflow=update-templates.yml --branch=main --status=success --limit=1 --json headSha \
          | jq -e ".[0].headSha == \"$(git rev-parse HEAD)\""
        env:
          GH_TOKEN: ${{ github.token }}
      - name: Package release payload
        run: |
          mkdir -p /tmp/payload/resources/compiled /tmp/payload/upstream-licenses
          cp resources/compiled/{nuclei-index.full,funnypot-attack,funnypot-routes,funnypot-routes-index,funnypot-protocols,funnypot-catalog}.php /tmp/payload/resources/compiled/
          cp resources/compiled/{manifest,crs-manifest,skipped}.json /tmp/payload/ 2>/dev/null || true
          cp resources/upstream-licenses/*.LICENSE.md /tmp/payload/upstream-licenses/
          tar -C /tmp/payload -czf funnypot-rules-${TAG}.tar.gz .
      - name: Sign release.json (ed25519, libsodium)
        run: php scripts/ci/sign-rules-release.php --tarball=funnypot-rules-${TAG}.tar.gz --channel=${{ inputs.channel }}
        env:
          FUNNYPOT_RULES_SIGNING_KEY: ${{ secrets.FUNNYPOT_RULES_SIGNING_KEY }}
      - name: Tag + upload release assets to funnypot-rules
        uses: softprops/action-gh-release@v2
        with:
          repository: bobbymaher/funnypot-rules
          tag_name: ${{ env.TAG }}
          files: |
            funnypot-rules-${TAG}.tar.gz
            release.json
            release.json.sig
            SHA256SUMS
```

The "verify HEAD already passed the compile workflow" step is the load-bearing line: it
refuses to package anything that didn't already go through `phpunit` + real-nuclei golden
acceptance + fingerprint-safety + license checks on `main`, so publishing can never become a
side channel that skips those gates.

---

## 12. Versioning, channels, rollback

- **Version:** `vYYYY.WW.N` git tags on `funnypot-rules`, one per publish run.
- **Channel:** `stable` (the default `rules:update` target, human-triggered publishes only)
  vs. `edge` (optional, could auto-publish every green `update-templates.yml`/`update-crs.yml`
  run with no manual approval step, for consumers who explicitly want the fastest cadence
  and accept the weaker review guarantee — out of scope to build now, but the channel field
  in `release.json` already reserves the seam).
- **Pin:** `--version=vYYYY.WW.N` on `rules:update` fetches and verifies that exact release
  regardless of what `stable`/`edge` currently point at — releases are never deleted from
  GitHub, so a pin from months ago still resolves.
- **Rollback:** trivial and re-fetch-free for the last `N` releases (§6 step 9) — flip
  `current` back with no network call. Rolling back further than the local retention window
  re-fetches that specific pinned version+sha from GitHub Releases, verified exactly like a
  forward update.

---

## 13. Tradeoffs, summarized

| Axis | This design | What it gives up |
|---|---|---|
| Runtime deps | `curl` (new baseline) + optional `ext-sodium` (already an existing `suggest`) | An OCI client and/or `cosign` binary would be genuinely new dependency *classes* this codebase has never carried |
| Immutability | Signed sha256 pin over a GitHub Release asset; verification-enforced | Not protocol-enforced content addressing the way an OCI digest is — relies on our own check running correctly, not on the namespace being unable to lie |
| Signing | ed25519/libsodium, reusing `funnypot`'s own SSH host-key primitive | No transparency log, no independent third-party auditability of who-signed-when (Sigstore/Rekor would give this) |
| Cron/offline | Zero-credential public HTTPS fetch; private forks need one bearer token | No SSO/keyless identity binding; a leaked PAT is a real (if narrowly scoped) risk, same as any bearer-token scheme |
| Air-gapped floor | Vendor-bundled `resources/compiled/*` always works, `RulesLocator` falls back to it | An air-gapped host is permanently on whatever `funnypot-core` version it's pinned to — this design doesn't (and can't) solve offline *freshness*, only offline *availability* |
| Fail-safe | Verify-then-swap, current release never touched on any failure | A silently-stale rules directory is possible if nobody monitors `rules:status`/`manifest()['built_at']` — worth a dashboard surface, not built here |
| Multi-server | Left as a documented deployment choice (per-node vs. shared mount) | No built-in fleet coordination — consistent with the rest of the package's single-process design, but a team running many nodes has to decide this themselves |
| Composer compatibility | `funnypot-rules` is still a valid Composer package for teams that want `composer require` | The *primary* path (direct fetch) intentionally does not shell out to `composer`, so a team relying on that path alone doesn't get Composer's own dist-integrity plumbing — it gets this design's instead, which is stronger (signed) than what Composer provides by default anyway |
