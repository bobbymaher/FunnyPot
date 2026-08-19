# Runtime rules updates via git-pinned pull — design

Design for a **funnypot-rules** repo plus a **RulesUpdater** in funnypot-core that fetches
compiled detection artifacts at runtime — cron/scheduler-driven, no `composer update`, no
recompile toolchain in the consumer. Champions one architecture (git-based pinned pull) end
to end and is honest about where it strains.

Companion doc: [auto-updaters.md](auto-updaters.md) designs the *publish-time* CI that keeps
funnypot-core's `resources/compiled/*.php` in lock-step with upstream nuclei-templates/CRS —
that pipeline is reused here almost unchanged, just re-aimed at a new target repo (§8). This
doc is entirely about what happens **after** that PR merges: how a consumer 6 months and zero
`composer update`s later still gets this week's rules.

---

## 0. Grounding — today's load path (why this is needed)

Compiled artifacts are literal PHP arrays, shipped *inside* the funnypot-core git repo,
installed wherever composer puts `vendor/metrictower/funnypot-core/`:

- `PhpArrayStore::fromPackage()` — `src/Store/PhpArrayStore.php:79-82` — hardcodes
  `dirname(__DIR__, 2) . '/resources/compiled/nuclei-index.full.php'`, i.e. a path computed
  **relative to this class's own location inside the installed package**. There is no seam to
  point it anywhere else.
- `EmulationCatalog::fromPackage()` — `/Users/bobmaher/myrepos/funnypot/src/Policy/EmulationCatalog.php:32-35`
  (app-owned, not core) — same pattern, same problem, one directory up.
- `PhpArrayStore::fromFile()` (`src/Store/PhpArrayStore.php:49-72`) already does the two things
  a good update mechanism needs downstream of fetch: validates `schema === 1`
  (`src/Store/PhpArrayStore.php:37-39`) and caches the parsed array once per worker process
  (`:51-55` — a restart, not a request, is what picks up a new file). Both behaviors carry
  over unchanged; RulesUpdater only has to get a *new file* onto disk safely.
- `ArtifactWriter::atomicWrite()` (`src/Compiler/ArtifactWriter.php:78-86`) already does
  tmp-file + `rename()` for every compiled artifact today. RulesUpdater reuses this exact
  primitive for the `current` pointer swap (§5) rather than inventing a second one.
- SPEC.md §4 already promises `bin/funnypot update [--tag=vX]` / `php artisan funnypot:update`,
  implemented today as `UpdateTemplatesCommand`
  (`src/Laravel/Console/UpdateTemplatesCommand.php`). That command shells out to
  `bin/funnypot compile` against a **local nuclei-templates checkout** — it recompiles in the
  consumer's own environment, which needs `symfony/yaml`, a multi-GB templates checkout, and
  minutes of CPU. That's the "too heavy" mechanism this doc replaces for the common case: a
  consumer should never compile, only fetch something already compiled, checked, and signed.
  §11 addresses the naming collision this creates.

The gap this doc closes: nothing today lets a *running* funnypot instance pick up week N+1's
rules without a `composer update` (which repoints the whole package, pulls in any code changes
too, and requires the consumer's CI/CD to notice and act).

---

## 1. Architecture at a glance

```
                       publish (§8, weekly/on-demand, funnypot-core CI)
                                        │
        nuclei-templates ──┐           ▼
                            ├─▶ compile ─▶ check ─▶ sign ─▶ push + tag ──▶ funnypot-rules (git)
        coreruleset ────────┘   (existing        (existing    (NEW)         stable ──▶ v2026.08.19
                                 funnypot-core     gates)                              v2026.08.12
                                 compiler)                                             v2026.08.05 …

                                        │  git fetch --depth=1 <pinned tag>  (§2)
                                        ▼
  consumer host                data-dir/releases/<sha>.partial/   (staging, unreferenced)
  (funnypot-core                       │  verify MANIFEST.json.sig (§3), sha256 per file
   RulesUpdater)                       ▼
                              data-dir/releases/<sha>/            (verified, still not live)
                                        │  atomic rename of `current` pointer (§5)
                                        ▼
                              data-dir/current  ──▶  PhpArrayStore::fromPath() / EmulationCatalog
                                        │
                              (on any failure at any step above: current is never touched —
                               engine keeps serving the last-good rules, or the bundled floor)
```

Three actors, three trust boundaries:

1. **funnypot-core CI** (existing, trusted — it's what you `composer require`) — compiles,
   gates, and now also **signs**.
2. **funnypot-rules** (new repo, untrusted transport) — a dumb, append-mostly git history of
   already-signed artifacts. Compromise of this repo's *hosting* (not its signing key) buys an
   attacker nothing: RulesUpdater verifies signatures against a key it never fetches from here.
3. **RulesUpdater** (new, ships inside funnypot-core) — fetch → verify → atomic swap, and
   nothing it does can degrade the currently-serving rules, only refuse to advance past them.

---

## 2. funnypot-rules repo layout

```
funnypot-rules/                          (github.com/metrictower/funnypot-rules, MIT)
  rules/
    nuclei-index.full.php                # from funnypot-core resources/compiled/
    funnypot-attack.php
    funnypot-routes.php
    funnypot-routes-index.php
    manifest.json
    crs-manifest.json
    skipped.json
    skipped-crs.json
  MANIFEST.json                          # top-level release manifest (§3)
  MANIFEST.json.sig                      # detached ed25519 signature over MANIFEST.json
  CHANGELOG.md                           # short human diff summary per release (counts only)
```

- **One artifact set per commit, one commit per release** (no incremental fixups on top —
  `git commit --amend`-free once pushed; a bad release is fixed by a new release + rollback,
  never by rewriting history other tooling may have already fetched).
- **Branches = channels.** `stable` is the only channel at launch; its tip only ever advances
  by fast-forward merge of a new release commit — never an ordinary commit lands directly on
  it. That means "what's newest on `stable`" is answerable with a single
  `git ls-remote <repo> refs/heads/stable`, no tag listing needed. A second channel (e.g.
  `edge`, tracking un-golden-tested compiles) is a plausible future add; not built now because
  nothing consumes it yet — see §11.
- **Tags are the trust unit, not the branch.** Every release gets an annotated tag
  `vYYYY.MM.DD` (`-2`, `-3` suffix on a same-day re-publish). `pinnedRef` (§6) always resolves
  to a tag or exact sha, never to a branch name — a branch tip is a mutable pointer an operator
  chooses to trust when they opt into a channel, but it is never the thing cryptographically
  verified (the signature in §3 is over content, and is checked identically whether you arrived
  via tag or branch).
- Nothing else lives here: no PHP source, no vendor/, no tests, no compiler. Consumers never
  run code that came from this repo — they only `require` its `rules/*.php` files through the
  same `PhpArrayStore`/`EmulationCatalog` schema-1 loader that already exists.

---

## 3. Signing & integrity — the key model

**What is signed:** not the git tag (see below for why), but `MANIFEST.json` — a flat list of
every file in `rules/` with its sha256 and byte size, plus provenance:

```json
{
  "schema": 1,
  "channel": "stable",
  "min_core_version": "1.4.0",
  "produced_by_funnypot_core": "2ec9141",
  "upstream": { "nuclei_tag": "v2.9.1", "nuclei_sha": "…", "coreruleset_tag": "v4.29.0" },
  "built_at": "2026-08-19T10:08:30+00:00",
  "files": {
    "rules/nuclei-index.full.php": { "sha256": "…", "bytes": 6304799 },
    "rules/funnypot-attack.php":   { "sha256": "…", "bytes": 77824 }
  }
}
```

`MANIFEST.json.sig` is a raw ed25519 signature (`sodium_crypto_sign_detached()`) over the exact
bytes of `MANIFEST.json`, published alongside it in the same commit.

**Why sign the manifest instead of relying on git's own signed-tag mechanism (`git tag -s` /
`git tag -v`):** GPG tag verification needs a GPG keyring configured on the consumer host and a
`git` binary invocation to check it — that ties integrity to the transport, and the tarball
fallback (§4) doesn't go through git's object model at all, so it would need a *second*,
different verification path. Ed25519-over-a-manifest is transport-agnostic: git clone, tarball
download, or an operator manually copying a directory over USB into an air-gapped host (§9) all
produce the same `MANIFEST.json` + `.sig` pair, verified the same way. `ext-sodium` is already a
`suggest`-tier dependency of funnypot-core (the SSH honeypot's curve25519/ed25519 handshake, per
`composer.json`), so this reuses an existing capability rather than adding a new PHP extension
requirement.

**Who signs, where the private key lives:** a single ed25519 keypair, "funnypot-rules release
key," generated once and held **only** as a GitHub Actions encrypted secret on the
funnypot-rules repo (the publish workflow, §8). It never touches a developer laptop after
generation, is never committed anywhere, and funnypot-core's CI does not have it — signing
happens in the *last* step of publish, after every gate has passed, as the final "I attest this
exact content" act.

**Where the public key lives:** vendored inside funnypot-core itself, at
`resources/keys/funnypot-rules.pub` (raw 32-byte ed25519 key, hex-encoded, committed to
funnypot-core's own git history). This is the load-bearing design choice: **the verifier is
distributed through a channel the operator already trusts** (it's the `composer require`d
package), not fetched at runtime from the same untrusted repo whose content it's about to
check. A poisoned funnypot-rules repo cannot supply its own trusted pubkey — that would be
asking the fox to hand over the keys to its own coop. This mirrors how apt trusts a keyring
shipped by the distro, not one downloaded from the repo being verified, and how Sigstore's TUF
root is bootstrapped out-of-band from the artifacts it verifies.

**Rotation:** ship a new `funnypot-rules-v2.pub` in a funnypot-core minor release. For an
overlap window (90 days), funnypot-rules CI publishes **two** signature files per release
(`MANIFEST.json.sig` with the old key, `MANIFEST.json.sig.v2` with the new one) so consumers on
either funnypot-core version keep verifying successfully. RulesUpdater tries every vendored
pubkey it has (`v1`, `v2`, …) against every `.sig*` file present and accepts on the first match
— no coordination needed beyond "ship the new pubkey a while before you stop dual-signing."

**Revocation:** there is no live "CRL" fetch — revoking a compromised key is itself a
funnypot-core patch release that removes it from the trusted set. Deliberately: a revocation
mechanism that lived in the same channel being revoked could be spoofed by whoever compromised
that channel. This makes key compromise response exactly as fast as a normal `composer update`
of funnypot-core, which is an acceptable bound for a project this size (see §11 for the
honest limits of a single-maintainer key).

**Verification order in `RulesUpdater::update()`**, all before the swap in §5, any failure
aborts with `current` untouched:

1. `ext-sodium` loaded? If not: refuse (fail-safe default) unless the operator explicitly set
   the documented `--insecure-skip-signature` break-glass flag (loud warning, logged, never
   the default — for a private mirror the operator already trusts by other means).
2. Fetch `MANIFEST.json` + `.sig` from the staged release. Verify signature against every
   vendored pubkey; reject if none match.
3. For every file the manifest lists, recompute sha256 from the fetched bytes; reject on any
   mismatch (also reject if the fetched tree has files the manifest doesn't list, or is
   missing one it does — an exact set match, not a subset check).
4. Check `schema === 1` and `min_core_version` against the running funnypot-core version
   (mirrors the existing `PhpArrayStore` schema guard at `src/Store/PhpArrayStore.php:37-39` —
   an old consumer must not load a manifest shape it doesn't understand).
5. Sanity-load: `require` each `rules/*.php` in the staged (not-yet-live) directory and confirm
   it returns an array with the expected top-level keys — catches a syntactically-valid-but-
   wrong file the hash check wouldn't (e.g. right hash, wrong schema version shipped by
   mistake — belt-and-braces, cheap to run once per release).

---

## 4. Transport

**Primary: the `git` binary, shallow, per-update.**

```
git clone --depth=1 --branch <tag> --single-branch <repo-url> <data-dir>/releases/<sha>.partial
```

Chosen over maintaining a persistent bare mirror + `git worktree add` for two reasons: (a) the
compiled artifacts are `var_export()` output (`src/Compiler/ArtifactWriter.php:59-75`) — key
ordering and formatting can shift between compiler runs even for a small upstream template
change, so git's delta compression is not reliably finding much overlap between consecutive
releases' blobs, weakening the bandwidth case for a mirror; (b) a fresh, disposable clone per
update has no persistent `.git` state that can itself get into a corrupt/interrupted state
needing separate recovery logic — every fetch starts from nothing and either fully succeeds
into a throwaway directory or fails and is deleted. Simpler is the safer default until a
measured bandwidth problem argues otherwise (weekly ~6 MB is not that problem).

**Fallback: HTTPS tarball, when `git` is unavailable or `exec()`/`proc_open()` is disabled**
(common on locked-down shared PHP hosting). RulesUpdater probes for a usable `git` binary once
at construction (`proc_open` a `git --version`); if that fails, or the operator forces it via
config, it falls back to a GitHub Releases **asset** (not the auto-generated
`archive/refs/tags/…tar.gz`, which isn't a stable published thing we control) — the publish
workflow (§8) attaches `rules.tar.gz` + `MANIFEST.json` + `MANIFEST.json.sig` as release assets
on the same tag. Fetched via `ext-curl` if present, else `file_get_contents()` with
`allow_url_fopen` (documented as the last-resort transport), then extracted with `PharData`
(bundled `ext-phar`, on by default almost everywhere) into the same `releases/<sha>.partial/`
staging directory. From that point on, verification (§3) and swap (§5) are **identical code** —
transport is fully decoupled from trust, which is the entire reason signing the manifest (not
relying on git's tag-signature machinery) was the right call in §3.

If neither transport is usable (`git` absent *and* neither `curl` nor `allow_url_fopen`
available), `update()` returns a failed result with a clear "no transport available" reason.
Current rules are untouched — this is a config problem for the operator to fix, not a runtime
fault.

**Air-gapped mirrors work for free:** git natively supports `file://` remotes, so
`--repo=file:///srv/funnypot-rules-mirror` goes through the exact same clone/verify/swap code
path as a normal `https://` remote — no special-casing needed (§9).

---

## 5. Engine-side design

### 5a. Data-dir layout

```
<data-dir>/                              # storage_path('funnypot-rules') in Laravel,
  current                                # or FUNNYPOT_RULES_DIR standalone
  releases/
    2ec9141/
      rules/nuclei-index.full.php ...
      MANIFEST.json
      MANIFEST.json.sig
    a91f0dd/
      ...
  .update.lock
```

`current` is a symlink to a `releases/<sha>` directory where the filesystem supports symlinks
cleanly; where it doesn't (documented fallback for oddball hosts), `current` is instead a small
pointer file (`current.json` — `{"release": "2ec9141"}`) written with the same tmp+rename
primitive already in `ArtifactWriter::atomicWrite()` (`src/Compiler/ArtifactWriter.php:78-86`)
— reused verbatim, not reinvented.

### 5b. Path resolution

`PhpArrayStore::fromPackage()` (`src/Store/PhpArrayStore.php:79-82`) and
`EmulationCatalog::fromPackage()` (`funnypot/src/Policy/EmulationCatalog.php:32-35`) are left
**unchanged** — they remain the bundled, offline floor (§9) and stay what the unit/acceptance
tests load. A new resolver sits in front, tried in order:

1. Explicit constructor argument (a specific `data-dir`, for tests/tooling).
2. `FUNNYPOT_RULES_DIR` env var (standalone convenience).
3. `<data-dir>/current` — used only if it resolves to a directory containing a `MANIFEST.json`
   that itself re-validates (schema + file-set match; a cheap re-check, not a signature
   re-verify on every request — see below) against the files actually present.
4. Otherwise, the bundled package copy — today's behavior, always present, never deleted or
   overwritten by RulesUpdater.

```php
final class PhpArrayStore implements CompiledStore
{
    // ...unchanged fromFile()/fromPackage()...

    /** Resolution order: $dataDir override -> FUNNYPOT_RULES_DIR -> current/ -> bundled. */
    public static function fromPath(?string $dataDir = null): self
    {
        $dir = $dataDir ?? getenv('FUNNYPOT_RULES_DIR') ?: null;
        $current = $dir !== null ? $dir . '/current' : null;

        if ($current !== null && is_file($current . '/rules/nuclei-index.full.php')) {
            return self::fromFile($current . '/rules/nuclei-index.full.php');
        }

        return self::fromPackage();
    }
}
```

Re-validating a full signature on every request-serving worker boot would reintroduce exactly
the cost this design exists to avoid; that already happened once, in `RulesUpdater::update()`,
before `current` was ever repointed. The resolver's job at read time is only "does this look
like the schema I expect," the same cheap check `fromFile()` already does today
(`src/Store/PhpArrayStore.php:37-39`).

### 5c. RulesUpdater (fetch → verify → swap)

```php
namespace Funnypot\Rules;

final class RulesUpdater
{
    public function __construct(
        private string $dataDir,
        private string $repoUrl = 'https://github.com/metrictower/funnypot-rules.git',
        private string $channel = 'stable',
        private ?string $pinnedRef = null,     // exact tag/sha; overrides channel resolution
        private int $keepReleases = 3,
        private bool $allowInsecureSkipSignature = false
    ) {
    }

    public function check(): UpdateCheckResult;   // resolve latest ref, no fetch, no write
    public function update(): UpdateResult;        // fetch -> verify -> swap -> prune (§5a/5d)
    public function rollback(?string $toRef = null): UpdateResult;  // §7
    public function status(): RulesStatus;          // current manifest + channel + on-disk releases
}
```

`update()` never lets an exception escape as fatal. Every failure mode — transport unavailable,
network timeout, signature mismatch, hash mismatch, schema mismatch, sanity-load failure, lock
contention — is caught internally and returned as `UpdateResult{success: false, reason: string,
...}`. The CLI/Artisan wrapper decides exit code and logging; the *library* contract is "this
call cannot make things worse than they already were," which is what makes it safe to wire into
cron unattended from day one.

**Concurrency:** `update()` takes a non-blocking `flock()` on `<data-dir>/.update.lock` first. A
second invocation (an overlapping cron tick, a manual run racing the scheduler) sees the lock
held and returns immediately as a no-op success (`reason: "update already in progress"`) rather
than racing the first one's staging directory or `current` repoint.

### 5d. Atomic swap, in order

1. Fetch into `releases/<new-sha>.partial/` — never a name `current` could ever point at.
2. Run all of §3's verification steps against the `.partial` tree.
3. `rename('releases/<new-sha>.partial', 'releases/<new-sha>')` — atomic on the same
   filesystem, and even after this the directory is still not referenced by `current`.
4. Repoint `current`: for the symlink case, `symlink('releases/<new-sha>', 'current.tmp')` then
   `rename('current.tmp', 'current')` (the rename, not the symlink creation, is the atomic
   commit point — a crash between the two leaves a harmless orphan `current.tmp`, never a
   half-updated `current`). For the pointer-file case, the same `ArtifactWriter::atomicWrite()`
   pattern.
5. Prune `releases/*` older than `keepReleases` (default 3), skipping whichever one `current`
   still points at even if it would otherwise be prunable (defends against a `rollback()` racing
   a prune, however unlikely under the lock in §5c).

At no point is `git checkout`/tarball-extract ever pointed directly at a live, served directory.
The new tree is fully built and fully verified in an unreferenced location before `current`
moves — this *is* "checkout into a temp worktree, then swap" from the brief, using plain
directories rather than literal `git worktree` state because the fresh-clone-per-update decision
in §4 means there's no persistent working tree to add a worktree to.

---

## 6. Fail-safe behavior — summary

Every constraint in the brief maps onto a concrete guarantee already implied above; stated
explicitly because it's the one property everything else exists to protect:

| Failure | What happens |
|---|---|
| Network down / host unreachable | `.partial` never completes; `update()` returns failed; `current` untouched |
| Signature missing/invalid | Rejected in §3 step 2; `current` untouched |
| Hash mismatch (tampered/corrupt transfer) | Rejected in §3 step 3; `current` untouched |
| Schema/version incompatible | Rejected in §3 step 4; `current` untouched |
| Sanity-load throws | Rejected in §3 step 5; `current` untouched |
| Crash mid-swap | `rename()` is atomic; `current` is either the old target or the new one, never a partial write |
| Two updates race | Second sees `.update.lock` held, no-ops |
| `data-dir` missing/unwritable entirely | `update()` fails fast with a clear reason; `PhpArrayStore::fromPath()` (§5b) falls through to the bundled package copy, which is never touched by any of this |
| Everything above, simultaneously, on a box that has never run `update()` once | Resolver's step 4 (bundled) — the engine has *never* not had rules to serve |

The honeypot degrades to "running last week's (or the day-one bundled) rules," never to "not
running" or "running a half-applied rule set."

---

## 7. CLI + PHP API surface

```
bin/funnypot rules:update   [--channel=stable] [--pin=<tag|sha>] [--data-dir=PATH]
                             [--repo=URL] [--dry-run] [--insecure-skip-signature]
bin/funnypot rules:status   [--data-dir=PATH]
bin/funnypot rules:rollback [--to=<tag|sha>] [--data-dir=PATH]
```

Exit codes: `0` — current rules are good, whether just updated or already current (this is the
code cron should treat as "fine," including the no-op case); `1` — an update was attempted and
failed, rules unchanged (worth alerting on, not worth paging on — the honeypot is still up);
`2` — usage/configuration error (bad flags, unwritable data-dir).

Deliberately namespaced `rules:*`, not reusing `update`/`funnypot:update` — see §11 for why
that name is already spoken for by the existing recompile-from-checkout command and why the two
need to stay visibly distinct rather than merged.

PHP API is exactly the `RulesUpdater` class in §5c; the CLI commands above and the Artisan
command in §8 are both thin wrappers around it — no logic lives in either wrapper that isn't
also reachable programmatically (a consumer embedding funnypot in something other than a
Laravel app can call `RulesUpdater::update()` directly from its own scheduler).

---

## 8. Laravel integration

New Artisan command, `funnypot:rules-update`, registered alongside the existing
`funnypot:update` in `FunnypotServiceProvider::boot()` (`src/Laravel/FunnypotServiceProvider.php:49-51`)
— additive, no change to the existing command:

```php
$this->commands([
    Console\UpdateTemplatesCommand::class,   // unchanged: recompile from a local checkout
    Console\RulesUpdateCommand::class,       // new: fetch a signed pre-compiled release
]);
```

New config keys in `config/funnypot.php`, following the file's existing pattern of env-backed,
inert-by-default knobs:

```php
'rules_channel'    => env('FUNNYPOT_RULES_CHANNEL', 'stable'),
'rules_pinned_ref' => env('FUNNYPOT_RULES_PIN', null),
'rules_repo'       => env('FUNNYPOT_RULES_REPO', 'https://github.com/metrictower/funnypot-rules.git'),
'rules_data_dir'   => env('FUNNYPOT_RULES_DIR', storage_path('funnypot-rules')),
```

`FunnypotServiceProvider::register()` binds `RulesUpdater::class` as a singleton built from
these keys, and the `Engine`/`Honeypot` construction (`src/Laravel/FunnypotServiceProvider.php:27-34`)
switches its store lookup from `PhpArrayStore::fromPackage()` to `PhpArrayStore::fromPath()`
(§5b) — a one-line change, backward compatible: an app that never runs `rules:update` has an
empty data dir, the resolver falls through to `fromPackage()`, and behavior is byte-identical
to today.

**What is *not* automatic:** a package cannot register an entry into the consuming app's
`App\Console\Kernel::schedule()` — Laravel has no package-schedule discovery hook. "Cron /
Laravel scheduler" support means funnypot-core ships the command; the operator adds one line
themselves:

```php
$schedule->command('funnypot:rules-update')->daily()->withoutOverlapping();
```

This is consistent with the project's existing "inert by default" philosophy (`config/funnypot.php`'s
own docblock: a bare `composer require` does nothing until the app opts in) — worth stating
plainly rather than implying a zero-config auto-updating honeypot that doesn't exist.

---

## 9. Offline / air-gapped

The bundled `resources/compiled/*.php` inside funnypot-core — today's only mechanism, entirely
unchanged by this design — remains the floor. `RulesUpdater` is opt-in at every layer: nothing
in `Engine`/`Honeypot` construction requires network access, ever, and an app that never
installs a scheduled `rules:update` call behaves exactly as it does today, forever.

For an air-gapped operator who *does* want fresher-than-bundled rules without a network path
out: two supported routes, both going through the identical verify+swap code, nothing
special-cased —

1. `--repo=file:///srv/funnypot-rules-mirror` — an internal git mirror kept current by whatever
   the org's own air-gap transfer process already is; git's native `file://` remote support
   means RulesUpdater needs zero awareness this isn't `https://`.
2. Fully manual: copy a `releases/<sha>/` directory (built and signed the same way, on the
   public internet, transferred by whatever media the org's policy allows) directly under
   `<data-dir>/releases/`, then run `rules:rollback --to=<sha>` (§7) — which, since that ref is
   already on disk, repoints `current` without any fetch at all. Signature verification still
   runs against the vendored pubkey (§3) even on this fully-offline path, so a tampered
   USB-transferred artifact is still caught.

---

## 10. Version pin / channel / rollback semantics

- **Pin** (`rules_pinned_ref` / `--pin=<tag|sha>`) is exact and reproducible: `update()`
  resolves to precisely that ref, every time, until the operator changes it. Right for
  CI/staging environments, or any deploy that wants funnypot-core-version-style predictability.
- **Channel** (`rules_channel` / `--channel=stable`) is "track whatever `stable`'s tip points at
  right now" — right for a low-traffic prod honeypot that wants hands-off freshness and accepts
  that "now" moves under it week to week.
- Setting both is not a conflict: an explicit `pinnedRef` always wins over channel resolution,
  full stop — channel is only consulted when no pin is set.
- **Rollback** to one of the `keepReleases` (default 3) releases still on disk is instant and
  fully offline — just a `current` repoint, no network, no re-verification needed (it was
  verified when it was first fetched and has sat untouched since). Rollback to an **older** ref
  no longer on disk transparently falls through to the normal `update()` path pinned to that
  ref — it is fetched, verified, and swapped exactly as any other update would be. Rollback is
  never a weaker or less-checked code path than a forward update; it's the same path with a
  different target ref.

---

## 11. Honest tradeoffs

**The `git`-binary dependency is real, even with a fallback.** The best-tested, best-supported
path assumes `git` on `PATH` — true of virtually every CI image and most Docker base images that
already run composer (composer itself frequently shells to git for VCS-type packages), but not
guaranteed on a minimal `php:8.3-fpm-alpine` unless `apk add git` is added to the image, and
categorically false on shared hosting that disables `exec()`/`proc_open()` outright (common on
budget shared PHP hosts). The tarball fallback (§4) covers that case — it never shells out — but
it is the less-exercised path in practice and can't do the (theoretical, currently declined —
see below) incremental-mirror-fetch optimization at all. Document this plainly rather than
imply universal git availability: "if your host disables `exec()`, you get tarball-only
transport — fully supported, slightly less bandwidth-efficient, no incremental mirroring."

**Repo-size growth is a real, currently-unsolved maintenance chore.** The dominant artifact,
`nuclei-index.full.php`, is ~5.8 MB of `var_export()` output today
(`resources/compiled/manifest.json`: `"artifact_bytes": 6304799`). Weekly releases over a year
is roughly 50 × ~6 MB ≈ 300 MB of blob churn in funnypot-rules' full history — fine for
consumers (a `--depth=1` shallow clone of one tag costs the same ~6 MB regardless of how much
history sits behind it) but not fine for anyone who ever needs the full history (a maintainer
debugging a regression, a mirror operator). This needs a periodic squash — e.g. re-root `stable`
as an orphan commit annually, archive prior history to a `history/<year>` branch nobody clones
by default — flagged here as a scheduled chore to build, not solved by this design.

**The persistent-mirror optimization was deliberately declined, and might stay declined.**
`var_export()`'s key ordering and formatting can shift meaningfully between compiler runs even
for a small upstream template diff, so git's delta compression is not reliably finding much to
save between consecutive releases' blobs — a persistent bare mirror + incremental
`git fetch --update-shallow` would add real operational complexity (a mirror that can itself get
into a broken state needing its own recovery path) for a bandwidth win that's unproven at best.
Fresh-shallow-clone-per-update (§4) is the honest "don't build the optimization until the
non-optimized version is a measured problem" choice — weekly ~6 MB per consumer is not that
problem today.

**Trust concentrates in one long-lived private key.** The ed25519 signing key (§3) is a single
point of failure for the entire rules supply chain: anyone who obtains it can sign arbitrary
regex/response bodies and every RulesUpdater in the world will install them as trusted. The
CI-secret-only custody plus rotation plan (§3) is a reasonable answer **at this project's
current scale** — a single-maintainer OSS repo — but it is not an enterprise answer. The natural
next hardening step, if funnypot ever gains more maintainers or a wider blast radius, is
**keyless signing** (Sigstore/cosign bound to the GitHub Actions OIDC identity) — that removes
the "long-lived private key sitting in a secret" risk entirely by having the identity provider
(GitHub) attest to *who* ran the workflow instead of a static key attesting to *what* they
signed. Worth a forward-looking mention; not built now because it adds a Sigstore-client
dependency (Cosign binary or a Go/Rust toolchain) to a PHP-only project for a threat model this
project doesn't face yet.

**Fingerprint-safety/license gates run once, at publish, not on every fetch — and that's a
deliberate bet, not a free lunch.** §8's reasoning (re-running a content linter can't add
anything a signature over already-checked content doesn't already guarantee) is sound *given
that the signing key itself is trustworthy* — but it means the checker never runs again on the
consumer side as a second opinion. If the funnypot-rules publish workflow itself were ever
compromised in a way that let it sign content that bypassed the gates (a broken CI runner, a
supply-chain hit on the check scripts themselves), no consumer-side check would catch it,
because none exists. The mitigation in §8 — reuse the exact same `check-fingerprint-safety.php`
/ `check-license.sh` scripts already battle-tested in funnypot-core, pinned by tag, rather than
a second reimplementation that could drift — reduces this risk but does not eliminate the
single-point-of-trust nature of "checked once, signed, trusted forever after."

**Two update mechanisms now coexist, and that needs its own follow-up.** SPEC.md §4 already
promises a *different*, heavier mechanism (`bin/funnypot update [--tag=vX]` /
`php artisan funnypot:update`, today's `UpdateTemplatesCommand`) that recompiles from a raw
local checkout. This design deliberately uses a different name (`rules:update` /
`funnypot:rules-update`, §7/§8) to avoid colliding with it, but an operator reading SPEC.md
today has no way to know two mechanisms exist or which one to reach for. SPEC.md §4 needs a
follow-up edit — out of scope for this design doc, flagged so it doesn't get lost.

**"Scheduler support" means "we ship the command," not "it runs itself."** As noted in §8, a
package cannot inject a line into the consumer's `Kernel::schedule()`. Every deployment of this
feature requires one explicit operator action (a scheduler line, or a crontab entry). That is
consistent with the project's inert-by-default stance elsewhere, but worth stating plainly so
nobody designs around an assumption of automatic, zero-touch freshness that this system does not
actually provide.

---

## 12. What this design deliberately does not solve

- A second channel (e.g. `edge`, pre-golden-test compiles) — no consumer need for it yet;
  the branch-per-channel model (§2) extends to it trivially when one appears.
- Cross-account/cross-team key custody (HSM, multi-party signing) — noted in §11 as the answer
  if the project's blast radius grows, not built for a single-maintainer repo today.
- funnypot-rules history squashing tooling — flagged as a scheduled maintenance chore (§11),
  not automated by this design.
- Reconciling SPEC.md §4's existing recompile-from-checkout command with this new
  fetch-a-signed-release command in the project's own documentation — flagged in §11, left for
  a follow-up edit to SPEC.md itself.
