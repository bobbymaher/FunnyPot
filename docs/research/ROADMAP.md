# funnypot — research synthesis & roadmap (2026-08-19)

Consolidates seven parallel research notes into one prioritised plan. Each topic links to its
detail note. Two hard rails run through everything: **fingerprint-safety** (never emit or train the
model on canonical scanner/matcher signature strings — that unmasks the honeypot) and
**small/self-hosted** (CPU-runnable, ≤~1B, no third-party AI hosting).

## Verdict table

| Topic | Verdict | Tier | Detail note |
|---|---|---|---|
| Extension-aware responses (the `.js` bug) | **Build** — user-reported correctness bug | 1 | [extension-aware-responses.md](extension-aware-responses.md) |
| Galah data → SFT + **DPO** refresh of the 0.5B | **Build** — real model-quality lever | 2 | [training-datasets.md](training-datasets.md) |
| dd-honeypot 7 phpMyAdmin rows | **Adopt (trivial)** — cache seeds + smoke test | 2 | [training-datasets.md](training-datasets.md) |
| Vulhub + mitmdump ground-truth recorder | **Build** — the step-change data source | 3 | [dataset-indexes-and-vulhub.md](dataset-indexes-and-vulhub.md) |
| CRS → funnypot-core attack-template layer | **Build** — generic-attack coverage | 4 | [coreruleset-templates.md](coreruleset-templates.md) |
| Payload scorer (query/body/headers) → ProbeGate | **Build** — openappsec's real lesson | 4 | [openappsec-ml-classify.md](openappsec-ml-classify.md) |
| CI fingerprint-safety + license gates | **Build** — missing today, cheap | 5 (pull fwd) | [auto-updaters.md](auto-updaters.md) |
| Auto-updaters for CRS / datasets | **Build** — mirror existing nuclei updater | 5 | [auto-updaters.md](auto-updaters.md) |
| Woyoung21/qwen-honeypot-GGUF | **Reject** — 1.5B *shell* honeypot, no HTML signal | — | [models-candidates.md](models-candidates.md) |
| klukama llm-honeypot sft/dpo | **Reject** — SSH/shell data, no license | — | [training-datasets.md](training-datasets.md) |
| open-appsec (the product) | **Skip** — not reusable, enterprise footprint | — | [openappsec-ml-classify.md](openappsec-ml-classify.md) |
| awesome-* index repos | **Skip** — noise; already covered | — | [dataset-indexes-and-vulhub.md](dataset-indexes-and-vulhub.md) |
| honeyval | **Defer** — a harder *eval* harness for later | — | [training-datasets.md](training-datasets.md) |

Cross-cutting finding: HTTP-honeypot ML resources are scarce — the model and both "honeypot"
datasets the maintainer flagged all turned out to be **shell/Cowrie** work, not HTTP. Our 0.5B +
juicy-prompt path is the right one; the levers are better *data* and broader *detection*, not a
different off-the-shelf model.

## Tier 1 — Correctness, now: extension-aware responses

The honeypot serves `text/html` for every generated fake, so a `.js`/`.json`/`.env` probe gets an
HTML page at the wrong Content-Type — itself a fingerprint tell. Two defects, both in
`src/App/Llm/LlmFakeResponder.php`:
1. **Latent bug (quick):** `build()` (`:111`) and the cache write (`:101`) hardcode `text/html`, so
   even a correctly-typed cache entry is re-served as HTML — `$hit['content_type']` from
   `LlmFakeCache::get()` is discarded. Read it back.
2. **Feature:** derive Content-Type from the path extension and generate type-appropriate bodies.

Plan (phased by risk): **JSON first** (new `json.gbnf`, grammar-bounded, highest value/lowest risk)
→ **plaintext/CSS** (grammar-free + type-aware sanitizer + anti-refusal check) → **XML**
(`DOMDocument` well-formedness + XXE guard) → **JS last**. JS is the risk: Turing-complete, so
inertness is not decidable by blocklist — use a data-only exemplar + blocklist as defence-in-depth,
with a static non-model JS stub as the honest fallback. **Must-do regardless:** bump
`FUNNYPOT_LLM_PROMPT_VERSION` `v1→v2` (`AppConfig.php`) so existing wrong-typed cache entries miss.
Unknown/dangerous extensions and no-extension → keep current HTML behaviour.

## Tier 2 — Model quality: Galah SFT + DPO refresh

Galah's `data/` (Apache-2.0, no poison strings): 1,380 records over 62 **real** attacker paths, each
run through ~20 models. Two products from one source:
- **SFT enrichment** (~150–250 rows) for request-side realism (real scanner paths, not invented).
- **DPO pairs for free** — chosen = a strong model's plausible body, rejected = a weaker model's
  refusal/degenerate body on the *identical* request. DPO aligns the 0.5B toward juicy-over-boring
  at the weight level (the earlier "boring login page" complaint, fixed structurally not just by
  prompt). We already have the mlx-lm LoRA scaffold (`funnypot-llm/train/`).

Fold the 7 dd-honeypot phpMyAdmin rows into the cache as ground-truth seeds + a post-train smoke
test. Re-run the A/B eval; only swap the GGUF if servable-HTML rate / juiciness improve without a
latency regression.

## Tier 3 — Foundational data: Vulhub ground-truth recorder

The only route to *real* response data. Replay a request corpus (nuclei / SecLists / CSIC) against a
16-target Vulhub shortlist through `mitmdump` (plain HTTP — no TLS/WARC hassle) with a JSONL addon.
Two outputs: `ground-truth.jsonl` (status+headers+body — the eval oracle) and `messages.jsonl`
(drops straight into `mlx_lm.lora`, matches our prompt contract). No WordPress in Vulhub → stock
container. **License:** WebLogic/Confluence/GitLab use repackaged proprietary binaries — internal
training only, never redistribute captures. This is one build cycle and unlocks both better training
data and a reusable eval oracle (and later, honeyval).

## Tier 4 — Detection coverage: CRS + payload scorer (converged)

Two agents independently pointed at the same gap: funnypot only judges the URL **path**, never the
query/body/headers for attack payloads.
- **CRS** slots into funnypot-core's hand-authored attack-template layer (`templates/attack/*.yaml`
  → `TemplateAttackEmulator`), **not** the nuclei inversion pipeline — CRS rules carry no response
  to invert, only "looks like class X." Aggregate many CRS PL1 rules into one broadened regex per
  `attack-*` tag; its category tags already match funnypot's `CATEGORY_TAGS` verbatim, so it also
  feeds the LLM's prompt-category selection. Parser handles `@rx`/`@pmFromFile` only (skip the
  `@detectSQLi` libinjection ops). Apache-2.0 → own license notice. **Risk:** never copy CRS
  `msg:`/rule-ids into served bodies → build-time lint.
- **Payload scorer:** a small pure-PHP keyword/regex attack-scorer (no ML runtime), sourced from
  CRS/Galah/nuclei, feeding a third signal into `ProbeGate::decide()`. Skip open-appsec's stateful
  baselining (needs warm-up a first-contact honeypot never gets).

CRS is the corpus; the scorer is the consumer. Build the parser first.

## Tier 5 — Automation & safety

An updater already exists: `funnypot-core/.github/workflows/update-templates.yml` (cron → pinned
tag clone → `bin/funnypot compile*` → phpunit + real-nuclei golden test → PR via peter-evans, never
auto-merges, provenance in `manifest.json`). It is **missing two gates**, valuable immediately:
- `check-fingerprint-safety.php` — fails the build if compiled artifacts would leak canonical
  matcher/CRS signature strings.
- `check-license.sh` — SPDX allow-list, commits the fetched license text into the PR.

Then mirror the workflow for CRS (`update-crs.yml`) and add a cheap sha-poll `update-datasets.yml`
(HF dataset repos are plain git remotes) — pinned, PR-only, never auto-adopt.

## Suggested sequence

1. **Tier 1** extension fix (user-reported; start with the cache-hit Content-Type bug + `v2` bump,
   then JSON, then the rest).
2. **Tier 5 safety gates** in parallel (cheap, standalone, protect everything downstream).
3. **Tier 4** CRS parser + payload scorer (biggest strategic coverage gain).
4. **Tier 2** Galah SFT+DPO refresh (can run as a background training track).
5. **Tier 3** Vulhub recorder (foundational; feeds a stronger future train).
