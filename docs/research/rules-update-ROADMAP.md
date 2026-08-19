# Runtime rules-update mechanism — synthesis & recommendation

Consolidates four brainstorm notes ([tarball](rules-update-tarball.md), [git](rules-update-git.md),
[oci](rules-update-oci.md), [security](rules-update-security.md)) into one recommended design.

**Goal (from Bob):** stop shipping a new composer package for every daily/weekly rule change. A
separate **`funnypot-rules`** repo holds versioned rule artifacts; funnypot-core gains a **callable
update mechanism** (CLI + PHP API) that fetches + hot-swaps rules at runtime — on demand or from a
cron / Laravel scheduler — with **no `composer update`**.

## The load-bearing finding (read this first)

The compiled rule artifacts are **`require`d PHP** — `PhpArrayStore::fromFile()` does `$x = require
$path` with only an `is_array` check. So a naive "download new rules and load them" is a
**remote-code-execution delivery path**, and there is **no signature verification anywhere in the
codebase today**. Every other control is decoration until this is fixed. Two acceptable fixes:

1. **Ship rules as inert DATA** (JSON/msgpack), verify the signature, then let the consumer's own
   already-trusted `ArtifactWriter` render the `.php` locally — the fetched bytes are never executed.
   *(Preferred.)*
2. Or **tokenizer-gate** any fetched `.php` as a pure array literal (no calls/includes/side effects)
   before `require`.

Signature verification proves *provenance*, not *safety* — so the safety gates still matter (below).

## Recommended design

**Transport — signed tarball via GitHub Releases (HTTPS).** Ranked #1 by three of four agents. No
`git` binary and no writable checkout on prod (git ranked last); no registry/cosign tooling to
reimplement in PHP and no cron registry-auth pain (OCI rejected for this project's scale). Just an
HTTPS GET of a Release asset + a detached signature.

**Authenticity — ed25519 detached signature** (`sodium_crypto_sign_verify_detached`). The signing
**public key is vendored inside funnypot-core** (a small keyring for rotation via overlapping
validity windows) — trust is anchored in the already-trusted consumer package, never fetched
alongside the artifact it verifies. funnypot already uses ed25519 (`src/Protocol/Ssh/HostKey.php`),
so the primitive is in-house. Per-file sha256 manifest cross-check on top.

**`funnypot-rules` repo — a thin distribution surface, no compiler.** funnypot-core's existing gated
compile pipeline (`update-templates.yml` / `update-crs.yml`) is unchanged. A new `publish-rules.yml`,
triggered **only after the human-merged PR** (never the pre-merge run), re-runs the two safety gates
on the merged commit, tars `resources/compiled/*`, signs it, and uploads tarball + `.sig` +
`manifest.json` to a Release. (Publishing after human merge is deliberately slower than "straight off
green CI" so the fast path never bypasses the review the slow composer path already had.)

**Engine seam — `RulesLocator::resolve()`.** Each `fromPackage()` loader
(`PhpArrayStore`, `TemplateAttackEmulator`, `RouteTemplateSet`, `ProtocolTemplateSet`,
`EmulationCatalog`) calls it: **data-dir `current/<artifact>` if present, else today's bundled
package path** — checked on every load, not just boot. That fallback *is* the offline/air-gapped
guarantee, mechanically. Two loaders are built directly in `Honeypot`'s constructor with no DI seam —
that seam has to be added.

**Atomic, fail-safe swap.** Fetch + verify happen in an unreferenced `.partial/` dir; only after full
verification is a `current` symlink `rename()`d. Any failure returns before the rename — the engine
never loses its rules and never serves empty. After swap: `opcache_invalidate` + drop
`PhpArrayStore`'s static file cache (a rename alone isn't hot under a persistent worker). Mutex the
whole thing (`withoutOverlapping`).

**Gates — publish-time, re-checked cheaply at fetch.** `check-fingerprint-safety.php` +
`check-license.sh` run at publish (they need the source corpus + acceptance harness, gone by fetch),
attested by the signature. The source-free subset re-runs at fetch as defense-in-depth: a
fingerprint-denylist re-scan, **ReDoS validation of every incoming regex** under a PCRE backtrack
budget (there's a live `preg_match` on attacker input in `TemplateAttackEmulator`), and an
**anti-blinding sanity floor** (reject a fetched set that drops coverage vs current — a silent
detection-kill is an attack).

**Surfaces.** `RulesUpdater` PHP API (`update()/status()/rollback()`), `bin/funnypot
rules:update|status|rollback` CLI, and a Laravel `funnypot:rules-update` Artisan command wired into
`Kernel::schedule` (daily, per-host jitter, `withoutOverlapping`, a **staleness alarm** — a wedged
updater silently goes blind). Rollback is a local, network-free symlink swap to a retained release.

**Other non-negotiable controls:** monotonic-version pinning (anti-downgrade), an allow-listed HTTPS
host with no off-list redirects (anti-SSRF/rebind), and a least-privilege rules dir — **not** the
`mkdir 0777` `bin/funnypot` uses in four places; the updater should be a dedicated non-web user and
the dir read-only to the web user.

## What each transport gave up

| Transport | Verdict | Why |
|---|---|---|
| **Signed tarball** | **Chosen** | HTTPS-only, no runtime git/registry deps, pure-PHP verify, inert payload |
| Git-pinned pull | Rejected | needs `git` + writable checkout on every host; no native artifact signing; repo blob-churn |
| OCI + cosign | Rejected | zero registry tooling exists; cosign keyless = a Fulcio/Rekor reimpl in PHP; cron registry-auth pain |
| Satis "rules package" | Rejected | it *is* the composer channel this feature exists to kill |

## Phased build plan

1. **Engine seam + fail-safe resolver** (`RulesLocator`, the five `fromPackage()` call-sites, the
   `Honeypot`-ctor DI seam) — zero behavior change for anyone not opting in. Ship this first.
2. **Data-format + local render** (fix the RCE path): rules published as data, consumer renders PHP
   via the trusted `ArtifactWriter`; or the tokenizer gate. **Blocks everything downstream.**
3. **`RulesUpdater`** (fetch → ed25519 verify → sha256 → fetch-time safety subset → atomic swap →
   cache-bust), CLI, PHP API, retained-release rollback.
4. **`funnypot-rules` repo + `publish-rules.yml`** (post-merge, gates, sign, Release).
5. **Laravel command + scheduler** wiring + staleness alarm + docs/README.

Steps 1–2 are the core (and the security-critical part); 3–5 are mechanical once the seam + data
format exist.
