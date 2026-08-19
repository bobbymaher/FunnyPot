# Runtime rules-update — security + ops cross-cut

Adversarial review of the proposed `funnypot-rules` runtime update capability: a separate
repo of versioned rule artifacts plus a CLI + PHP API that fetches and hot-swaps rules on a
running honeypot (on demand / cron / Laravel scheduler), with **no `composer update`**.

Scope: assess the *idea* and the three candidate transports — (A) signed GitHub-Release
tarballs, (B) git-pinned pull, (C) OCI/registry or Satis — then recommend. The three
transport design docs (`rules-update-{tarball,git,oci}.md`) do not exist yet; this reasons
from first principles, grounded in the real `funnypot-core` load/write code.

All `file:line` citations are `/Users/bobmaher/myrepos/funnypot-core` unless marked.

---

## 0. The one fact that reframes everything

**The rules artifact is executed, not parsed.** `PhpArrayStore::fromFile()` loads the
compiled index with a bare `$index = require $path` (`src/Store/PhpArrayStore.php:62`). The
file is a `<?php … return [ … ];` literal (`ArtifactWriter::render()`,
`src/Compiler/ArtifactWriter.php:56-78`). At **load** time nothing enforces that it is a
pure literal — the only checks are `is_array($index)` and `schema === 1`
(`PhpArrayStore.php:37,64`). So a fetched/hot-swapped `nuclei-index.full.php` (or
`funnypot-attack.php`) that contains *any* PHP — a `system()` call, a backdoored autoload
side effect — runs in the honeypot's web process the instant it is loaded.

Therefore **the rules-update channel is a remote-code-execution delivery path**, not a
data feed. Every control below is in service of that single fact. And there is currently
**no signature or verification anywhere** in the codebase (`grep -niE
'minisign|cosign|openssl_verify|sodium_|gpg|rekor'` over `src/ bin/ scripts/` → only
unrelated honeytoken-HMAC and probe-signature hits). The `sha256` in `manifest.json`
(`ArtifactWriter.php:37-39`) is computed by the writer over the very bytes it writes — a
checksum of the file against itself, worthless as a trust anchor against a poisoned release,
a compromised mirror, or a MITM.

**Design consequence, load-bearing:** the OTA channel must ship rules as **inert data**
(JSON/MessagePack), verify a detached signature, and let the *consumer's own trusted*
`ArtifactWriter` render the `require`-able PHP locally. The fetched bytes are then never
executed — only parsed. If PHP-array form is kept for opcache speed, the fetched file MUST
be tokenizer-validated as `<?php return <array-literal>;` (no `T_FUNCTION`, `T_NEW`,
`T_STRING` call, `::class`, backticks, `T_EVAL`…) *before* it can be `require`d. Severing
this channel is the highest-value control in this document.

---

## 1. Threat model

The feed hot-swaps content that is (i) executable PHP (above), (ii) PCRE patterns matched
against attacker input at runtime, and (iii) response bytes served back to attackers. Each
is an attack surface.

### T1 — Poisoned rules: RCE via the artifact
Covered in §0. Highest severity. A single poisoned artifact that passes (or bypasses) the
gate = code exec as the web user. Mitigation: data-form transport + signature + local
render, or pre-`require` tokenizer validation.

### T2 — Poisoned rules: ReDoS / CPU exhaustion on the honeypot itself
There **is** a live runtime regex engine on attacker-controlled input:
`TemplateAttackEmulator::match()` runs `preg_match('~' . $cond['regex'] . '~' . $flags,
$surface)` where `$cond['regex']` comes straight from the rules artifact and `$surface` is
the attacker's request (`src/Template/TemplateAttackEmulator.php:135`). Existing mitigations
are real but partial: the surface is capped at 32 KB (`MAX_SURFACE`, line 113/128-130) and a
`preg_last_error()` backtrack-limit hit fails the rule instead of matching (line 138). But:
- The engine is **PCRE**, not Go RE2. The SPEC's RE2 witness validation (`FindAllString≠∅`)
  runs at build time for *nuclei* witnesses only; the CRS/attack `regex` conditions are
  authored/broadened patterns that run under PCRE, where catastrophic backtracking that RE2
  cannot even express is possible.
- PHP's default `pcre.backtrack_limit` is 1,000,000. A pathological pattern on a 32 KB
  surface can burn that budget on **every matching request** before failing — a poisoned
  rule doesn't need to hang once, it needs to make each scanner probe cost 100 ms of CPU.
- The cap protects input length, not pattern pathology. `(a+)+$` against 32 KB of `a` is
  still catastrophic within the limit.

Mitigation: **fetch-time ReDoS validation of every incoming `regex` condition** under a
tight wall-clock + backtrack budget, using PCRE (the runtime engine), rejecting the whole
artifact on any pattern that blows the budget. RE2-only build validation does not cover this.

### T3 — Poisoned rules: blinding (disable detection)
An update is a whole-index replacement. A poisoned feed can ship an empty/near-empty
`routes` map, or silently drop tier-1 templates, and the honeypot stops detecting while
looking healthy. This is the quiet, high-value attack against a defender's telemetry.
Mitigation: an anti-blinding **sanity floor** — reject an update whose route/template counts
drop below a tolerance of the *current live* index (the SPEC already has a CI "coverage-rot
gate" concept, SPEC §6; extend the same idea to fetch time). Alert on rejection.

### T4 — Poisoned rules: fingerprint leak / working-exploit bodies
A rule whose synthesized response echoes a scanner/matcher signature verbatim lets an
attacker classify the reply as canned honeypot output (the exact failure the nuclei-inversion
design exists to prevent); a response body could also embed a genuinely working exploit
served onward. The fingerprint-safety gate (`scripts/ci/check-fingerprint-safety.php`,
`FingerprintGuard`) addresses this — see §2 for *where* it must run.

### T5 — Compromised signing key
Single-key signing = single catastrophic failure: poisoned rules that pass every gate
because they are validly signed. Mitigations: keep the key offline / CI-OIDC-scoped
(cosign keyless via Fulcio + Rekor binds the signature to a workflow identity and a public
transparency log); rotate; and — decisively — keep the fetch-time structural + ReDoS +
sanity-floor validators as defense-in-depth so a signature alone can never push
executable/blinding content. **A signature proves provenance, not safety.**

### T6 — Downgrade / rollback
An attacker who can serve an older, *validly signed* artifact rolls you back to a version
with a since-fixed fingerprint leak or a since-removed bad rule, or blinds you to newer
templates. `manifest.json` carries `built_at`, `upstream_tag`, `upstream_sha`
(`resources/compiled/manifest.json`) but nothing monotonic is enforced. Mitigation: the
consumer records the last-applied version/sequence and **refuses an artifact older than
current** unless an operator passes an explicit rollback flag. Rekor's transparency log
(transport C) gives independent downgrade detection.

### T7 — TOCTOU on the atomic swap
`ArtifactWriter::atomicWrite()` is tmp-then-`rename()` in the same dir — atomic on POSIX,
good (`ArtifactWriter.php:85-95`). Gaps: (a) the tmp name is `getmypid()`-predictable
(`ArtifactWriter.php:87`) — in a shared/world-writable rules dir that is a symlink/hijack
vector; (b) no `fsync` before rename; (c) the update flow must write the **verified bytes**
to tmp and rename *that* — never verify one file and rename a different one, and never fetch
to the live path then verify in place (an attacker or a racing request loads the unverified
file in the window). Verify → write verified bytes to tmp → `rename` → invalidate.

### T8 — Writable rules dir as a persistence foothold
Because the dir holds `require`-d PHP executed by the web user, if the rules dir is writable
by the web/runtime user (the natural way to let a web request hot-swap), then **any** code-exec
bug elsewhere in the host app lets an attacker drop a webshell as `nuclei-index.full.php`,
executed on next load. This directly conflicts with "web process hot-swaps on demand." The
updater (a separate, non-web user via cron) must own and write the dir; the web user gets
**read-only**. Note `bin/funnypot` creates output dirs `mkdir(…, 0777, true)` in four places
(`bin/funnypot:60,85,197,219`) — 0777 on a dir of executed PHP is a real smell; the rules
dir must be 0755 owned by `updater`, files 0644, outside the web root.

### T9 — SSRF / DNS-rebind on the fetch
If the fetch URL is operator-configurable or follows redirects, it can be pointed at an
internal address (cloud metadata endpoint, internal service), and DNS-rebind can swap the
resolved IP between the version-check and the download. Mitigation: pin an allow-listed
HTTPS host, disallow redirects to off-allowlist hosts, validate TLS, and — the real
defense — **verify content by the signed digest**, so *where* the bytes came from is
irrelevant to whether they are trusted.

### T10 — Cron running as a privileged user
If the scheduler runs the updater as root or the web user, a fetch/parse bug or a poisoned
artifact escalates accordingly. Run the updater as a dedicated low-privilege, no-shell user,
write-scoped to the rules dir only.

---

## 2. Controls — and where each MUST run

**Publish-time vs fetch-time is the central design question. The gates split by what data
they need.**

### Fingerprint-safety + license gates → PUBLISH time (mandatory), attested by signature
Both gates are **preconditions of publishing** a `funnypot-rules` artifact; a lightweight
cron fetch on a production box cannot reproduce them:
- **Fingerprint-safety** needs (a) the *source corpus* being compiled, to extract the
  fresh-from-corpus canonical matcher literals (the auto-fed list-(b) in the
  `auto-updaters.md` design), and (b) the acceptance harness / real-nuclei Docker to replay
  responses and grep them. Neither the source tree nor Docker exists on a honeypot host.
- **License-compatibility** needs the upstream `LICENSE` file from the source tree
  (`scripts/ci/check-license.sh`), also absent at fetch time.

So both run in the publishing pipeline, and **the artifact is signed only if they pass** —
the signature *is* the attestation that they did. Fetch time then verifies the signature and
trusts the attestation. This is the correct place: authoritative, has the inputs,
deterministic, one-time cost per release instead of per-host-per-fetch.

**But fetch time must still run the cheap, source-free subset as defense-in-depth** (because
the signing key can be compromised, T5):
1. **Structural validation** — the payload is a schema-1 literal array (data-form), or the
   PHP file tokenizes as a pure `return`-literal with no calls/objects (§0).
2. **ReDoS validation** — every incoming `regex` condition under a PCRE time/backtrack
   budget (T2). Source-free; must run at fetch.
3. **Sanity floor** — route/template counts within tolerance of the current live index (T3).
4. **Fingerprint denylist re-scan** — the shipped `resources/fingerprint-denylist.php`
   lists (a) internal markers and (c) published probe strings are source-free and cheap;
   re-run them at fetch time. Only list-(b), the fresh-from-corpus literals, genuinely needs
   the source and is covered by the signature.

### Integrity + provenance
- **Detached signature over artifact + manifest**, verified against a public key **baked
  into `funnypot-core`** (shipped in the package, pinned) — never fetched alongside the
  payload. Runtime require is PHP-only (`composer.json`: `"php": ">=8.0"`); `ext-sodium` /
  `ext-openssl` are *suggest*-only, so the verifier must degrade gracefully — prefer
  `sodium_crypto_sign_verify_detached` (ed25519, minisign-compatible) when `ext-sodium` is
  present, else a vendored pure-PHP ed25519 verifier. Do not hard-require an extension.
- **Digest pinning** — verify content by a sha256 you compute over the fetched bytes and
  compare to the signed manifest value; the self-attested `sha256` in today's manifest is
  not this.
- **Monotonic version pinning** — persist last-applied sequence; refuse older (T6).

### Rollback safety + fail-safe
- Verify-everything → write verified bytes to tmp → `rename` → opcache-invalidate the new
  path **and drop the in-process static cache** (`PhpArrayStore::$fileCache`,
  `PhpArrayStore.php:47`, whose own comment says "Restart the worker to pick up a recompiled
  index" — under php-fpm/RoadRunner with opcache `validate_timestamps=0`, a rename alone is
  *not* hot; the swap must `opcache_invalidate($path, true)` and reset the static, or signal
  a worker reload).
- **On ANY verify/validation failure: keep the currently-loaded artifact, log, alert, exit
  non-zero. Never blank the index — never serve nothing.** The engine already fails safe
  per-request (miss → null → app's own 404) and installs inert (`mode=detect`, `gate=null`),
  but the *update path* must never leave zero rules live.
- **Mutex** the swap (`->withoutOverlapping()` / a lockfile) so two runs can't race T7.

### Permissions (T8/T10)
Rules dir outside web root, `0755 updater:webgroup`, files `0644`, web user read-only,
updater is a dedicated non-root no-shell user. No long-lived fetch secret on the box if the
transport allows anonymous signed fetch.

---

## 3. Ops / ergonomics

### Laravel scheduling
- Artisan command (the SPEC's Laravel bridge already registers an update command, SPEC §4;
  `src/Laravel/Console/UpdateTemplatesCommand.php` is the shape to follow — note it already
  `passthru`s to a subprocess so "a bad/huge corpus can't take the web app down mid-request",
  the right instinct). New: `funnypot:rules-update` with `--check` (dry-run: fetch + verify,
  no swap), `--force-version=` (deliberate rollback, the only way past the monotonic guard).
- `Kernel::schedule()`:
  ```php
  $schedule->command('funnypot:rules-update')
      ->dailyAt('03:'.sprintf('%02d', crc32(gethostname()) % 60)) // per-host jitter
      ->withoutOverlapping()   // mutex the swap (T7)
      ->runInBackground()
      ->onOneServer()          // one node fetches; or let each verify independently
      ->onFailure(fn () => /* emit metric + alert */);
  ```
- **Jitter + fleet staggering are not cosmetic**: a whole fleet hitting GitHub/registry on
  the same minute is a thundering herd, and a single upstream outage otherwise lands in every
  honeypot's update window at once. Derive the minute from a host hash.

### Headless / cron auth per transport
- **(A) GitHub Release tarball** — public repo downloads need *no* auth; a token only lifts
  rate limits and is a stored secret with blast radius. Prefer anonymous + digest-pin, or a
  fine-grained read-only token. **Least secret on the box.**
- **(B) git pull** — public HTTPS = no auth; private needs a deploy key/token on disk (a
  secret to guard) and a `git` binary + writable checkout on every prod host.
- **(C) OCI / Satis** — registry pull usually needs a robot/pull credential
  (`~/.docker/config.json`); Satis behind basic auth = a stored credential. Rekor/cosign is
  best-in-class provenance but adds a client (`oras`/`cosign`) and, typically, a secret.

### Observability
Log every run as structured JSON: fetched version, prev→new, verify result per stage, swap
result, elapsed, source digest. **Alert (page-worthy) on:** signature-verify failure
(key/MITM/poisoning), ReDoS-validator rejection, sanity-floor rejection (possible blinding),
downgrade rejection, repeated fetch failure (upstream down or being censored), and — easy to
miss — a **staleness alarm**: last-successful-update older than `cadence × margin` means the
updater is silently wedged and you are no longer detecting new attacks. Track
last-successful-update timestamp explicitly.

### Cadence
Upstream moves roughly weekly (nuclei-templates tags, CRS releases). A **daily** run that
does a cheap version/etag check and downloads only on change keeps detection latency low at
near-zero cost; weekly is acceptable. Add ±jitter and fleet staggering. Never fetch on the
hot request path.

---

## 4. Recommendation

Ranked for **this** project — small, self-hosted, framework-free PHP 8.0 (runtime = PHP
only), must run unattended in cron *and* as a standalone CLI, no Docker on prod hosts.
Ranking axes: no long-lived secret on the honeypot · works headless + standalone · minimal
deps · native signing + digest + downgrade protection · simple atomic swap · fetched bytes
are data, not code.

**1st — (A) Signed GitHub-Release tarball. THE DEFAULT.**
Anonymous HTTPS pull of a versioned asset + a detached signature asset (minisign/ed25519
or a cosign blob) verified against a public key baked into `funnypot-core`. **No secret on
the box.** Pure-PHP fetch (`curl`/streams) + verify + extract + local re-render + atomic
swap — no external binary, no framework, works in cron and standalone. The payload is
**data** (json/msgpack), never executed. Cheap version check via release tag/etag. It reuses
the tag-pinning muscle the repo already has (`git ls-remote` tag resolution in
`update-templates.yml`) without needing `git` on prod. Fewest moving parts that still gets
signing + digest + version pinning.

**2nd — (C) OCI/registry + cosign. Deviate to this only if a registry already exists.**
Best-in-class provenance: content-addressed digests are immutable, cosign + Rekor give
signing *and* a transparency log (strong T6/downgrade story), ORAS pushes arbitrary
artifacts. But it adds a registry dependency, usually a pull credential (a secret on the
box, T10-adjacent), and a heavier client (no pure-PHP OCI client — shell to `oras`/`cosign`
or vendor one). Right for a fleet already running a registry + cosign in its deploy path;
overkill for one self-hosted box. **Satis is a trap here**: it is a Composer channel — i.e.
back to `composer update`, the very thing this feature exists to eliminate — and still can't
hot-swap without a composer run.

**3rd — (B) git-pinned pull.** Mentally simple, weakest for unattended prod: needs a `git`
binary + writable working tree on every honeypot (more attack surface + a persistence
foothold, T8), no native artifact signing (you'd GPG-verify signed *tags*, awkward and
rarely set up headless), pulling a branch invites moving-target/downgrade unless pinned to an
exact tag/sha, and a checkout drags source + history you never run. Fine for a human pulling
updates by hand; last for automation.

**Single best default:** (A) — a signed, digest-and-version-pinned, **data-form** rules
tarball, verified against a pinned public key, re-rendered locally to the PHP artifact.
Deviate to (C) only when the deployment already runs a registry and wants Rekor-grade
provenance across a fleet.

### Non-negotiable controls for any implementation
1. **Fetched rules are DATA, never executed on fetch.** The executed PHP artifact is
   rendered locally by the trusted `ArtifactWriter`; or a fetched PHP file is
   tokenizer-validated as a pure literal before `require`. (Severs the RCE channel — §0/T1.)
2. **Detached signature** over artifact + manifest, verified with a public key **baked into
   the package**, not fetched with the payload. Self-attested `manifest.sha256` is not a
   trust anchor.
3. **Digest + monotonic-version pinning**; refuse older-than-current (anti-downgrade, T6);
   fetch pinned to an allow-listed HTTPS host, no off-allowlist redirects (anti-SSRF/rebind,
   T9).
4. **Fetch-time ReDoS validation** of every incoming `regex` condition under a PCRE
   time/backtrack budget (the runtime engine, not RE2); reject the whole artifact on any
   blow-up (T2).
5. **Anti-blinding sanity floor** + fingerprint-denylist re-scan at fetch time (T3/T4).
6. **Fail-safe swap**: verify-all → write verified bytes to tmp → atomic `rename` →
   `opcache_invalidate` + drop the static cache (or signal reload); on ANY failure keep the
   current index, never serve empty; mutex concurrent updates (T7).
7. **Least privilege**: updater runs as a dedicated non-web non-root user via
   cron/scheduler; rules dir owned by updater, read-only to web, outside web root, 0644
   files (never 0777); no long-lived fetch secret on the box (T8/T10).
8. **Publish-time fingerprint-safety + license gates are mandatory and attested by the
   signature** — the artifact is signed only if they pass (§2).
9. **Observability + alerting** on verify-fail, ReDoS/sanity/downgrade rejection, repeated
   fetch failure, and staleness (§3).

### Verdict on the idea itself
Sound and worth building — decoupling rules from `composer update` is the right call, and
the SPEC already anticipates it (`bin/funnypot update`, atomic write, manifest provenance).
But it is only safe if it stops being an OTA channel for *executable PHP* and becomes an OTA
channel for *signed, validated data that the host renders locally*. Build control #1 first;
without it, every other control is decoration on a remote-code-execution path.
