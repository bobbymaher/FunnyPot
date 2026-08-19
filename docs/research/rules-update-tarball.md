# Rules update via signed release tarballs — design

How funnypot-core picks up fresh nuclei/CRS rules **without** a `composer update` on
every consumer, while never weakening the "never let unreviewed upstream content reach
a deception engine" invariant the existing compile pipeline already enforces
(`funnypot/docs/research/auto-updaters.md`).

**Chosen architecture: a separate `funnypot-rules` repo publishes signed GitHub Release
tarballs of the artifacts funnypot-core already compiles; funnypot-core gains a
`Funnypot\Rules\RulesUpdater` that fetches, verifies, and atomically swaps them into a
writable data dir it now knows how to prefer over its bundled copy.** No git, no
registry client, no compiler toolchain at runtime — plain HTTPS + `ext-sodium`.

---

## 1. What exists today (the gap)

Every runtime artifact is loaded by a `fromPackage()` static that resolves a path
**relative to the package's own installed location** and requires it:

- `PhpArrayStore::fromPackage()` → `resources/compiled/nuclei-index.full.php`
  (`funnypot-core/src/Store/PhpArrayStore.php:79-82`)
- `TemplateAttackEmulator::fromPackage()` → `resources/compiled/funnypot-attack.php`
  (`funnypot-core/src/Template/TemplateAttackEmulator.php:47-50`)
- `RouteTemplateSet::fromPackage()` → `resources/compiled/funnypot-routes.php`
  (`funnypot-core/src/Response/RouteTemplateSet.php:30-32`)
- `EmulationCatalog::fromPackage()` → `resources/compiled/funnypot-catalog.php`
  (`funnypot/src/Policy/EmulationCatalog.php:32-35`, app-level, same pattern)

`Honeypot::default()` wires the first two together at construction
(`funnypot-core/src/Honeypot.php:57`, `:65-68`), and `EmulatorRegistry::default()`
wires the third (`funnypot-core/src/Response/EmulatorRegistry.php:24-26`). All four
resolve **inside `vendor/bobbymaher/funnypot-core/...`** (or the app's own `resources/`
for the catalog) — there is no writable-directory concept anywhere in this resolution
chain today. `PhpArrayStore::fromFile()` also keeps a static, per-path, per-process
`$fileCache` (`PhpArrayStore.php:47,56-71`) — the compiled index is 6MB, so a
long-lived php-fpm/RoadRunner worker parses it once and holds it in memory; its own
docblock already says "restart the worker to pick up a recompiled index."

There *is* an update command today: `php artisan funnypot:update` / `bin/funnypot
update` (`funnypot-core/src/Laravel/Console/UpdateTemplatesCommand.php`,
SPEC.md:200-202 "Updateability"). It is **not** what the task wants — it shells out to
`bin/funnypot compile <local-checkout>`, i.e. it still needs `symfony/yaml`, the
`Funnypot\Compiler\*` toolchain, and a full local `nuclei-templates` clone already
present on the runtime host, and it only ever refreshes `nuclei-index.full.php` (not
`funnypot-attack.php`/`funnypot-routes.php`). It's a fine power-user path for an
operator maintaining a **private** template corpus; it is not a fetch mechanism, and
this design doesn't replace it — see §9.

The pipeline that *does* already fetch + validate + gate upstream content is
`update-templates.yml` / `update-crs.yml`
(`funnypot-core/.github/workflows/update-templates.yml`,
`.../update-crs.yml`, both documented in detail in `auto-updaters.md`): pinned-tag
clone → `bin/funnypot compile*` → `phpunit` → real-nuclei golden acceptance →
`scripts/ci/check-fingerprint-safety.php` → `scripts/ci/check-license.sh` → PR to
`funnypot-core`, **never auto-merged**. This is the pipeline this design reuses — it
doesn't get rebuilt.

---

## 2. `funnypot-rules`: a thin distribution repo, not a second compiler

`funnypot-rules` holds **no PHP compiler code**. Compiling still only ever happens
inside `funnypot-core`'s own CI, by its own `bin/funnypot`, gated by the checks that
already exist. `funnypot-rules` is: a README documenting the trust model, a
`CHANGELOG.md`, and its GitHub Releases. Repo layout:

```
funnypot-rules/
  README.md          # trust model, public key fingerprint (out-of-band verification)
  CHANGELOG.md        # human-readable release notes, generated from manifest diffs
  .github/workflows/
    verify-release.yml   # sanity job: re-download the latest release, verify it
                          # against the public key, on a schedule — a canary that
                          # catches "signing broke" / "CDN served something odd"
                          # independent of any consumer ever polling
```

No `keys/` directory — the private key never touches this repo either (§5).

### What a release contains

Every GitHub Release is tagged (see §6 for the version scheme) and carries exactly
three assets:

```
funnypot-rules-<version>.tar.gz        # the payload
funnypot-rules-<version>.tar.gz.sig    # detached Ed25519 signature over the .tar.gz bytes
funnypot-rules-<version>.manifest.json # per-file sha256 + provenance (also inside the tarball)
```

The tarball root:

```
manifest.json                 # schema, version, channel, key_id, upstream provenance, per-file sha256
engine/
  nuclei-index.full.php
  funnypot-attack.php
  funnypot-routes.php
  manifest.json                # funnypot-core's own compile manifest (upstream tag/sha/counts)
  crs-manifest.json
app/                            # optional — present only when the triggering build also
  funnypot-catalog.php          # refreshed the funnypot app's catalog/protocol artifacts
  funnypot-protocols.php
```

`engine/` vs `app/` matters because the two live in different repos with different
release cadences today (funnypot-core's compiled index vs. the funnypot app's catalog).
A consumer that only requires `bobbymaher/funnypot-core` only ever reads `engine/`; the
funnypot app reads both. One tarball, one signature, one verify — not two channels to
separately trust.

`manifest.json` (inside the tarball, and duplicated as a release asset for
tooling/humans who don't want to fetch+extract the whole tarball just to inspect it):

```json
{
  "schema": 1,
  "version": "v2026.08.19-nuclei.2ec9141",
  "channel": ["latest"],
  "built_from_commit": "funnypot-core@a1b2c3d",
  "key_id": "2026-01",
  "sources": {
    "nuclei-templates": {"tag": "v10.2.3", "sha": "2ec9141..."},
    "coreruleset":       {"tag": "v4.19.0", "sha": "..."}
  },
  "files": {
    "engine/nuclei-index.full.php": "sha256:adb34e4e...",
    "engine/funnypot-attack.php":   "sha256:...",
    "engine/funnypot-routes.php":   "sha256:..."
  },
  "tarball_sha256": "..."
}
```

This is a direct extension of the `sha256`/`manifest.json` convention
`ArtifactWriter::write()` already stamps per compile
(`funnypot-core/src/Compiler/ArtifactWriter.php:37-41`, visible today in
`resources/compiled/manifest.json`'s `sha256` field) — nothing new is invented, it's
folded into one release-level manifest.

---

## 3. Publishing: where the gates run, and why publish only fires post-merge

**Decision: the publish step is triggered by push-to-`main` on `funnypot-core`
touching `resources/compiled/**` — i.e. only after a human has merged the PR that
`update-templates.yml`/`update-crs.yml` already open.** Not from the schedule-triggered
compile run itself.

This is the one place I deliberately traded speed for keeping an existing invariant
intact. The tempting shortcut is to publish straight from the same CI run that opens
the PR — it's already green (unit tests, real-nuclei golden acceptance,
fingerprint-safety, license check all passed) and it would shave days off freshness.
But `auto-updaters.md` is explicit that the whole point of the PR-not-auto-merge design
is "never auto-merge unreviewed upstream content into a deception engine" — the
automated gates catch *known* classes of leak (fingerprint strings, license
incompatibility, template-format regressions) but a human diff-review is still the only
check against a well-formed-but-malicious or subtly-wrong upstream template sailing
through all of them. Publishing pre-merge would make the **fast, no-composer-update
channel** — the one every honeypot in the fleet actually drinks from daily — bypass
that review entirely, while the slow channel (the composer package) kept it. That's a
silent downgrade of the project's own stated security posture for its most-used path.
So: every release, on every channel, is cut from a commit that already has a merged,
reviewed PR behind it. `stable` vs. `latest` (§6) is purely a *time-since-merge*
distinction, not a review-strength one.

New workflow `funnypot-core/.github/workflows/publish-rules.yml`:

```yaml
on:
  push:
    branches: [main]
    paths: ['resources/compiled/**']

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with: { php-version: '8.3', extensions: 'sodium', coverage: none }

      # Cheap re-gate on the EXACT commit being packaged. Not redundant with the
      # pre-merge run: it closes the gap between "what the PR run validated" and
      # "what actually landed on main" (squash-merge edits, a maintainer touching a
      # file during review, or a branch-protection misconfiguration letting a direct
      # push through). Only the two SECURITY gates re-run here — pure PHP/bash,
      # seconds, no Docker/real-nuclei acceptance needed a second time.
      - run: php scripts/ci/check-fingerprint-safety.php
      - run: bash scripts/ci/check-license.sh /dev/null resources/upstream-licenses/nuclei-templates.LICENSE.md --verify-only

      - name: Package + sign + publish
        env:
          FUNNYPOT_RULES_SIGNING_KEY: ${{ secrets.FUNNYPOT_RULES_SIGNING_KEY }}
          FUNNYPOT_RULES_RELEASE_TOKEN: ${{ secrets.FUNNYPOT_RULES_RELEASE_TOKEN }}
        run: php scripts/ci/publish-rules-release.php
```

`publish-rules-release.php` (new, funnypot-core): builds `manifest.json`, tars
`resources/compiled/{nuclei-index.full.php,funnypot-attack.php,funnypot-routes.php,
manifest.json,crs-manifest.json}` into `engine/`, `sodium_crypto_sign_detached()`s the
tarball with the key from `FUNNYPOT_RULES_SIGNING_KEY`, and calls the GitHub Releases
API (via `FUNNYPOT_RULES_RELEASE_TOKEN`, a fine-grained PAT scoped to
`contents:write` on **only** `bobbymaher/funnypot-rules`, nothing else) to create the
release and upload the three assets, then updates and re-signs `channels.json` (§6).

---

## 4. Signing and key model

**Ed25519 via `ext-sodium`** (`sodium_crypto_sign_detached` /
`sodium_crypto_sign_verify_detached`), not X.509/openssl PKI. Reasons: `ext-sodium` is
already a documented `suggest` dependency of funnypot-core for the pure-PHP SSH
honeypot's host key (`funnypot-core/composer.json` `suggest.ext-sodium`), it ships
compiled-in on almost every PHP 8 build, and a detached signature over one 32-byte
public key is the entire verification surface — no cert chains, no CA, no expiry
parsing, matching the "minimal deps" constraint far better than openssl X.509 would.

- **Who signs:** the `publish-rules.yml` workflow in `funnypot-core`, using a private
  key held **only** as a `funnypot-core` repo secret (`FUNNYPOT_RULES_SIGNING_KEY`).
  v1 is a plain GitHub Actions secret — see §8 for why that's the right call at this
  project's scale and what the honest blast radius is.
- **Where the public key lives:** committed into funnypot-core's own source tree,
  `resources/rules-signing-keys.php`, in the same "hand-curated, tracked, PHP-array"
  shape as `resources/fingerprint-denylist.php`:
  ```php
  return [
      ['key_id' => '2026-01', 'public_key' => 'base64...', 'valid_from' => '2026-01-01', 'valid_until' => null],
  ];
  ```
  It ships inside the composer package like every other `resources/*.php` file, so the
  trust root only ever changes via a normal, reviewed funnypot-core PR — **the same
  channel a compromised key would need to bypass to remove itself**, which is exactly
  the property you want from a root of trust.
- **Rotation:** add the new `key_id` (with a `valid_from` in the future) well ahead of
  first use; `RulesUpdater` accepts a signature from *any* key in the ring whose
  validity window covers `now()`, so old and new keys overlap safely. Retire the old
  key by giving it a `valid_until` once nothing still depends on it, in a later PR.
- **Compromise:** revoke by cutting a funnypot-core patch release that drops the
  `key_id` from the ring. This is intentionally decoupled from the rules channel's own
  cadence — a compromised signing key is a `composer update` event, not a `rules:update`
  event, so it can't be "fixed" by the same channel that's compromised.

---

## 5. Engine-side: packaged vs. data-dir resolution

New resolver, `Funnypot\Rules\RulesPaths::resolve(string $artifact, ?string $dataDir):
string`:

1. If `$dataDir !== null` and `is_file("$dataDir/current/$artifact")` → return that
   path.
2. Else return the existing packaged path (`dirname(__DIR__, 2) .
   "/resources/compiled/$artifact"`).

That's the whole mechanism for constraint (5) — **the packaged copy is the floor by
construction, not by policy**: nothing about step 2 changes, so a consumer that never
configures a data dir (the entire installed base today) sees byte-identical behaviour
to before this feature existed. `fromPackage()` becomes `fromPackage(?string $dataDir =
null)` on the four classes in §1, defaulting to `null` (unchanged call sites keep
compiling and behaving exactly as today) and delegating to `RulesPaths::resolve()` then
the existing `fromFile()`. `Honeypot::default()` gains the same optional param threaded
through to `PhpArrayStore::fromPackage($dataDir)` / `TemplateAttackEmulator::fromPackage($dataDir)`.

Resolution re-runs on **every** call, not once at boot — so a data dir that gets
manually deleted, or a `current` symlink left dangling by an interrupted swap,
self-heals to the packaged floor on the very next resolution with no error path, not
just at process start. That's what makes constraint (3) ("fetch/verify failure keeps
the currently-installed rules") also cover "the currently-installed rules directory
became unreadable" — not just "the network request failed."

### Data dir layout (atomic swap)

Symlink-swap release layout — the same idiom Capistrano/PM2-style atomic deploys use,
not a new invention:

```
<dataDir>/
  releases/
    v2026.08.10-nuclei.abc123/{engine,app}/...
    v2026.08.19-nuclei.2ec9141/{engine,app}/...
  current -> releases/v2026.08.19-nuclei.2ec9141/     (symlink)
  channels-cache.json    # last-fetched, still-signature-valid channels.json (offline resolution)
  .lock                  # flock'd during fetch/verify/swap
```

`RulesUpdater::update()`:

1. `flock()` `<dataDir>/.lock`, non-blocking — a second concurrent invocation (cron +
   manual trigger racing) just exits `0` immediately rather than contending.
2. Resolve target version: explicit pin, or fetch `channels.json` and resolve the
   requested channel. If it equals the version already stamped in
   `current/manifest.json`, return a no-op result — **before any download** — so
   frequent polling (daily cron on every node of a fleet) is cheap by default.
3. Refuse to move to a version **older** than the installed one unless the caller is
   `rollback()`, not `update()` — a plain `update()` cannot be used to force a fleet
   backward even if fed a validly-signed-but-superseded old tarball (a freeze/downgrade
   attack otherwise has no mitigation once a single signature check passes).
4. Download the tarball + `.sig` over plain HTTPS from
   `github.com/bobbymaher/funnypot-rules/releases/download/<tag>/<asset>` — the CDN
   asset-download path, deliberately **not** `api.github.com`, so a large fleet isn't
   throttled by the REST API's per-IP rate limit (release assets aren't subject to it).
   Into a temp file inside `<dataDir>` itself (never `sys_get_temp_dir()` — it can be a
   different filesystem, which would silently turn the final `rename()` in step 8 into
   a non-atomic copy).
5. `sodium_crypto_sign_verify_detached($sig, $tarballBytes, $key)` against every
   currently-valid key in `resources/rules-signing-keys.php`. Any failure (bad
   signature, no valid key, `ext-sodium` missing) → delete the temp file, return a
   failure result, `current` untouched. This is the one hard gate — nothing past this
   point runs on unverified bytes.
6. Extract to `releases/<version>/` (sibling of `current`, same filesystem).
7. Cross-check every `manifest.json["files"]` sha256 against the extracted files —
   belt-and-braces against extraction/disk corruption, not a security boundary (the
   signature already covers the exact tarball bytes).
8. Sanity-load: `PhpArrayStore::fromFile()` etc. against the new release dir, confirm
   `schema === 1` and route/template counts are within a sane range of the previous
   release (catches "signed but structurally broken" — a bug, not an attack — before it
   goes live). Failure here behaves exactly like step 5's failure.
9. Atomic activation: `symlink(releases/<version>, current.tmp)` then
   `rename(current.tmp, current)`. POSIX `rename()` within one directory is atomic, so
   any concurrent reader sees either the fully-old or fully-new `current`, never a
   half-updated one — the same "tmp/fsync/rename" idea SPEC.md's Updateability section
   already names (SPEC.md:200-202), applied to a symlink instead of a single file.
10. Prune `releases/` beyond a retention count (default 3), keeping whatever a pinned
    rollback still points at. Release the lock.

### Picking it up in a running process

Swapping the symlink does **not** retroactively fix an already-running worker's
`PhpArrayStore::$fileCache` (`PhpArrayStore.php:47`) — same limitation that already
exists for a manual redeploy today, per that class's own docblock. Two honest,
separate mechanisms, not one:

- **Same-process, cheap:** resolve through the *stable* path `current/nuclei-index.full.php`
  (the symlink target, not the versioned dir) so PHP's `stat()`-based opcache
  invalidation (`opcache.validate_timestamps`, PHP's default) notices the underlying
  inode changed on the next `require` and recompiles it. `RulesUpdater::update()` also
  calls a new `PhpArrayStore::forget(string $path)` right after a successful swap to
  drop its own in-process array cache for that path — best-effort, current process
  only.
- **Fleet-wide:** still needs the operator's normal deploy/restart signal (worker
  recycling via `pm.max_requests`, a rolling restart, or the same
  `docker-compose restart queue`-style step this codebase already relies on elsewhere
  for queued-job code reloads). No PHP library can force that from inside a request —
  documenting it honestly here rather than pretending the symlink swap alone is
  sufficient for a live fleet.

---

## 6. Version, channel, pin, rollback

**Version tag:** `v<date>-<source>.<short-sha>`, e.g. `v2026.08.19-nuclei.2ec9141` or
`v2026.08.20-crs.9f1a2b`, cut off whichever workflow (`update-templates.yml` or
`update-crs.yml`) triggered the merge — but the tarball it produces always packages the
**full current** `resources/compiled/` tree, not a diff, because `bin/funnypot
compile-emulators` always folds `templates/attack/` + `templates/attack-crs/` together
(`bin/funnypot:51-55`); a nuclei-only refresh still needs the last-known-good CRS
templates folded in. One version = one complete, internally-consistent rule set, so the
runtime never has to reconcile two independently-updated artifact sets — atomic swap
covers the whole bundle by construction.

**Channels**, resolved via a small, itself-signed `channels.json` published/re-signed
on every release (its own asset on a rolling `channels` GitHub Release, plus a
`.sig`) — this keeps "which version is current" (tiny, changes every release) separate
from "the immutable, content-addressed release" (large, fetched once per version, never
mutated):

```json
{ "schema": 1, "latest": "v2026.08.19-nuclei.2ec9141", "stable": "v2026.08.10-nuclei.abc1234", "revoked": [] }
```

- `latest` = the newest post-merge release (§3 — already human-reviewed).
- `stable` = the newest release that has been `latest` for ≥7 days with no incident —
  promoted by a small scheduled job, nothing else re-runs.
- `revoked` — a cheap, natural extension once `channels.json` is already fetched and
  trusted on every check: version tags a maintainer wants a fleet to actively refuse
  even though their signature is still individually valid (e.g. a structurally-fine but
  behaviourally-wrong release found after the fact). Not built in v1, but the plumbing
  (`RulesUpdater` already parses this file) makes it a small follow-up rather than a
  redesign.

**Pin:** `FUNNYPOT_RULES_VERSION` env / `rules.pinned_version` config bypasses channel
resolution entirely and always fetches that exact tag — for reproducible fleets or
staged rollout.

**Rollback:** GitHub Releases are immutable and stay downloadable indefinitely, but
`rollback()` doesn't even need the network in the common case — the retained
`releases/<older-version>/` directories in the data dir (§5, kept 3 by default) let
`funnypot rules:rollback [--to=vX]` do a **local, instant, network-free** symlink swap
back to an already-verified directory. Only falls back to a fresh signed fetch if the
target version isn't in local retention.

---

## 7. CLI + PHP API

CLI, new `bin/funnypot` subcommands in the same argument-parsing style as the existing
`compile*` commands:

```
funnypot rules:update   [--channel=stable|latest] [--version=vX] [--data-dir=PATH]
funnypot rules:rollback [--to=vX] [--data-dir=PATH]
funnypot rules:status   [--data-dir=PATH]     # installed version, channel, checked_at, source
funnypot rules:verify   <tarball> <sig>       # standalone verify — air-gapped manual installs
```

PHP API (`Funnypot\Rules\RulesUpdater`, new namespace):

```php
final class RulesUpdater
{
    public function __construct(
        string $dataDir,
        ?string $channel = 'stable',
        ?string $pinnedVersion = null,
        ?HttpFetcher $fetcher = null,   // seam for tests / custom TLS config
        ?KeyRing $keyRing = null,       // defaults to resources/rules-signing-keys.php
    ) {}

    public function update(): UpdateResult;                    // no-op if already current
    public function rollback(?string $toVersion = null): UpdateResult;
    public function status(): RulesStatus;                     // version, channel, checked_at, source
}
```

**Laravel:** a new `Console\RulesUpdateCommand` beside the existing
`UpdateTemplatesCommand` in `funnypot-core/src/Laravel/Console/`, registered the same
way in `FunnypotServiceProvider::boot()` (`funnypot-core/src/Laravel/FunnypotServiceProvider.php:49-51`).
Unlike `UpdateTemplatesCommand`'s `passthru()`-to-subprocess pattern (which exists to
keep a huge in-process YAML compile off the request/worker process,
`UpdateTemplatesCommand.php:9-13`), this command calls `RulesUpdater` **in-process** —
there's no heavy compile step here, just an HTTPS fetch + one signature check + file
I/O, so isolating it into a subprocess buys nothing. Scheduler wiring:

```php
$schedule->command('funnypot:rules-update')->dailyAt('03:00');
```

Whether to add `->onOneServer()` depends on topology, and getting it wrong is a real
footgun worth calling out rather than picking a default silently:
- **Per-node local disk data dir** (the common case — an EC2/ECS fleet each running its
  own php-fpm): do **not** use `onOneServer()`. Each node must run its own update
  independently since nothing else would update its local disk. Redundant runs across
  nodes are safe and cheap — step 2's version-compare short-circuit means N nodes
  polling the same day cost N cheap "already current" checks, not N re-fetches.
- **Shared data dir** (EFS/NFS across the fleet): `onOneServer()` is correct — one fetch
  updates the shared `current` symlink for everyone — but every node still separately
  needs its own worker-recycle to pick it up in-process (§5's fleet-wide caveat still
  applies per node even though the disk write happened once).

---

## 8. Fail-safe and honest risk accounting

**Fail-safe is structural, not a try/catch convention.** Every failure mode in §5's
`update()` — network error, non-2xx, signature mismatch, missing `ext-sodium`,
checksum mismatch, failed sanity-load, lock contention — returns before step 9's
`rename()`, so `current` is untouched and every subsequent `RulesPaths::resolve()` call
keeps reading whatever it read before, all the way down to the packaged floor if the
data dir was never populated at all. There is no code path where a failed update
degrades to "serve nothing."

Constraint checklist:

| Constraint | How it's met |
|---|---|
| Supply-chain integrity | Ed25519 signature over the tarball, verified before any extracted byte is trusted; key ring lives in reviewed source, not the channel it verifies |
| Fingerprint/license gates | Full gates pre-merge (existing `update-templates.yml`/`update-crs.yml`); cheap re-gate of the two security-critical checks at publish time, on the exact commit shipped (§3) |
| Fail-safe | Structural — every failure path returns before the atomic swap (§5, §8) |
| Atomic swap | `rename()` of a symlink within one directory (§5 step 9) |
| Offline/air-gapped floor | `RulesPaths::resolve()` step 2 is the unmodified, always-present packaged path (§5) |
| Version pin + channel + rollback | `channels.json` (signed) + explicit pin + local, network-free rollback from retained releases (§6) |
| Standalone + Laravel | `RulesUpdater` PHP API is framework-free; `RulesUpdateCommand` is a thin Illuminate wrapper, same pattern as the existing bridge (§7) |
| Minimal deps | `ext-sodium` only, already a documented `suggest`; absent → refuse to update, never touch the fetch path, packaged floor still serves (§4, §8) |

**What signing does *not* protect against**, stated plainly because the task asked for
honesty here specifically: it defends the **transport** — a compromised CDN edge, a
MITM, a `funnypot-rules` repo admin editing an already-uploaded asset, a bug in
`RulesUpdater` accidentally pointed at the wrong URL. It does **not** defend against a
compromised `funnypot-core` CI/secrets environment (the signer itself going rogue —
only §4's "rotate via a reviewed funnypot-core PR, decoupled from the rules channel"
mitigates that, after the fact), and it does **not** defend against a well-formed but
malicious upstream nuclei-templates/coreruleset release sailing through every automated
gate — only the human PR review §3 insists on running *before every single release*
defends against that. Signing and review are answering different threats; neither
substitutes for the other, and this design keeps both rather than trading one for
speed.

**Other honest tradeoffs:**

- **Single-maintainer key, no threshold signing.** No TUF-style root/targets/snapshot
  role separation, no Sigstore transparency log. That's the right call at this
  project's actual scale (one maintainer, no PHP TUF client exists, and the constraint
  explicitly asked for minimal deps) — but it's a real ceiling: if funnypot ever gains
  multiple trusted maintainers, this is the first piece to revisit, and a CI-held raw
  secret (v1) should become a KMS-backed signer called over short-lived OIDC before
  that happens, not after.
- **No per-version revocation in v1** — only key-level revocation (a whole
  funnypot-core release). `channels.json.revoked` (§6) is designed-for but not built;
  cheap to add later since the file is already fetched and trusted on every check.
- **Bandwidth is the maintainer's, indefinitely.** `nuclei-index.full.php` alone is
  ~6MB uncompressed (`resources/compiled/nuclei-index.full.php`, 6,102,033 bytes
  today); a large fleet polling daily is real recurring egress on a GitHub-hosted
  account. GitHub doesn't meter public release-asset bandwidth today, but that's a
  platform policy, not a guarantee — mitigated, not eliminated, by the version-compare
  short-circuit and a daily (not hourly) default interval.
- **Downgrade/freeze attack** is explicitly handled (§5 step 3, monotonic version
  check on `update()`) rather than assumed away — worth calling out because it's the
  kind of gap that's easy to miss in a "just check the signature" design.

---

## 9. Relationship to the existing local-compile update path

`bin/funnypot update --tag=vX` / `php artisan funnypot:update`
(`UpdateTemplatesCommand.php`, SPEC.md:200-202) stays. It serves a different, real use
case this design doesn't: an operator maintaining a **private** template corpus (their
own detection rules, not meant for the public `funnypot-rules` feed) who wants to
recompile against their own checkout. Recommend amending SPEC.md's "Updateability"
section to name `funnypot rules:update` as the **primary**, default-recommended path
for tracking the public corpus, and re-describe the existing command as the "custom
corpus" path — both call into the same compiled-artifact shape and the same
`PhpArrayStore`/`TemplateAttackEmulator` readers, so neither is a dead end.

---

## Summary (≤400 words)

**Chosen architecture:** a new `funnypot-rules` repo holds no compiler — it's a thin
GitHub-Releases distribution surface. funnypot-core's existing, already-gated compile
pipeline (`update-templates.yml`/`update-crs.yml`: pinned-tag fetch → compile →
phpunit → real-nuclei golden acceptance → fingerprint-safety → license check → PR,
documented in `auto-updaters.md`) is unchanged. A new `publish-rules.yml`, triggered
only by **push to `main` after that PR is human-merged** (never from the pre-merge
run), cheaply re-runs just the two security gates on the exact merged commit, tars
`resources/compiled/*` into `engine/`, signs the tarball with Ed25519
(`sodium_crypto_sign_detached`) using a `funnypot-core`-held CI secret, and uploads
tarball + `.sig` + `manifest.json` to a GitHub Release.

Engine side: today's four `fromPackage()` loaders (`PhpArrayStore.php:79-82`,
`TemplateAttackEmulator.php:47-50`, `RouteTemplateSet.php:30-32`, and the app's
`EmulationCatalog.php:32-35`) resolve a hardcoded path inside the installed package.
They gain an optional `?string $dataDir` param and a new `RulesPaths::resolve()` that
prefers `<dataDir>/current/<artifact>` when it exists and falls back — on every call,
not just at boot — to the unmodified packaged path. That fallback *is* the
offline/air-gapped guarantee, mechanically, not by policy.

A new `Funnypot\Rules\RulesUpdater` does fetch → verify → atomic-swap: download over
plain HTTPS (CDN asset URLs, not the rate-limited API), verify the Ed25519 signature
against a key ring committed in `resources/rules-signing-keys.php` (supports rotation
via overlapping validity windows), cross-check per-file sha256, sanity-load the new
artifacts, then `rename()` a `current` symlink — atomic, and every failure path returns
before that rename, so a failed update always leaves the prior (or packaged) rules
serving. A `channels.json`, itself signed and re-fetched cheaply, maps `stable`/`latest`
to concrete version tags; explicit version pins bypass it; rollback is a local,
network-free symlink swap to a retained prior release. CLI (`bin/funnypot rules:*`) and
a Laravel scheduler command both call the same in-process PHP API.

Deliberate tradeoff, stated rather than hidden: publishing only after human merge means
the fast channel is slower than "publish straight off green CI," in exchange for never
letting the highest-traffic update path bypass the review invariant the slow (composer)
path already has. Also honest: signing defends transport, not a compromised signer or a
malicious-but-well-formed upstream release — only pre-publish human review defends the
latter, and this design keeps that gate rather than routing around it for speed.
