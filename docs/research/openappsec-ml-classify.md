# open-appsec — ML request classification, and whether funnypot can borrow it

Research task: could funnypot use an open-appsec-style ML "this request is an attack" verdict to
*route* a request to a honeypot response, instead of blocking it? Investigated the upstream repo
(`github.com/openappsec/openappsec`, Apache-2.0, ~1.7k stars, C++, ~100MB checkout), its docs site
(`docs.openappsec.io`), and community reports. Companion doc: `honeypot-projects.md` (other
honeypot prior art, same KEEP/DROP format). No clone was needed — GitHub's contents API and raw
file fetches were enough to read the relevant source.

**One-line verdict:** open-appsec's "ML" is not reusable and not what it sounds like — it's a large,
tightly-coupled Hyperscan-accelerated keyword/regex indicator engine plus a per-asset online
statistical baseliner, shipped as ~100 interlocking C++ files with an undocumented binary model
format, and its real-world footprint (agent + attachment + per-asset state) is nowhere near
funnypot's "small, self-hosted, framework-free PHP" bar. **Don't integrate or embed it. Do steal
the *idea* of a payload-level attack-indicator score** — implemented as a tiny hand-weighted
keyword/regex scorer in PHP, no training pipeline, no new runtime dependency — as a new signal
feeding `ProbeGate` alongside the existing lexical `ProbeClassifier`.

---

## 1. What open-appsec's "ML" actually is

Marketing language is "Patented Contextual Machine Learning Engine." Reading
`components/security_apps/waap/waap_clib/` (the WAAP = Web App & API Protection engine, ~100 files,
`Waf2Engine.cc` alone is 105KB) shows three phases, matching the docs' own description but with the
mechanism now concrete:

**Phase 1 — parsing/decoding.** A stack of format-specific parsers
(`ParserJson`, `ParserXML`, `ParserMultipartForm`, `ParserPHPSerializedData`, `ParserGql`,
`ParserPercentEncode`, `ParserGzip`, `ParserPDF`, `ParserHTML`, `ParserBinary`…) normalize the
request body/headers/URL into decoded strings/tokens the indicator engine can scan. This part is
genuinely useful engineering (payload normalization) but is classic parsing, not ML.

**Phase 2 — attack indicators.** `WaapHyperscanEngine.cc` runs Intel Hyperscan (a high-performance
multi-regex matching library) against a large corpus of attack-signature regexes/keywords compiled
into the shipped data files (`components/security_apps/waap/resources/`: `waap.data` 1.6MB,
`1.data` 788KB, `2.data` 895KB, `8.data` 1.7KB — total ~3.4MB, custom binary format written by
`Serializator.cc`, no documented schema). `KeywordIndicatorFilter.cc`, `IndicatorsFiltersManager.cc`,
and `ScoreBuilder.cc` (21KB) combine per-pattern hit scores into a payload confidence score. This is
"supervised" in the sense that the regex-family weights were tuned offline against a labeled corpus
of malicious/benign payloads — but the runtime mechanism is signature scoring with pre-baked
weights, not a neural net or a model file you can point an inference runtime at. There is no
`.onnx`/`.pb`/`.h5`/`.pt` anywhere in the repo.

**Phase 3 — contextual confidence.** `ConfidenceCalculator.cc` (48KB) is a per-deployment, per-asset
online statistical baseliner: for each request parameter key, it tracks the *set* of values seen
across a configurable minimum number of distinct sources (`minSources`) and time windows
(`minIntervals`, `intervalDuration`), and only marks a value "confident" (i.e., normal for this app)
once the source-diversity/ratio threshold is met (`ratioThreshold`). This is frequency-based
anomaly detection / automatic allowlisting, not a trained classifier — it explicitly reserves
**40MB of memory per protected asset by default** (`defaultConfidenceMemUsage = 40 * 1024 * 1024`,
`ConfidenceCalculator.h`). `TrustedSourcesConfidence.cc` and `BehaviorAnalysis.cc` layer in
source-reputation and behavioral signals the same way.

So "contextual machine learning" = pattern/keyword scoring (statistically tuned offline) +
per-asset online frequency baselining + reputation weighting, combined in a weighted sum against a
threshold. It is real, useful attack-detection engineering — but it is not the kind of "ML model"
that ports to a small self-hosted PHP process; there's no discrete artifact to extract and run.

## 2. Training, shipping, license, standalone-ness

- **License:** confirmed Apache-2.0 for the whole repo (`LICENSE` file, GitHub API `license.spdx_id`)
  — core code AND the "basic" model data files. **But** the docs explicitly say the "advanced" model
  ("more accurate and recommended for Production") is a **separate download** from the open-appsec
  portal under a proprietary "Machine Learning Model license," not in the repo and not Apache-2.0.
  The thing that actually ships in the open repo is the non-production-grade model.
- **Reusable standalone?** No. The indicator engine is ~100 C++ files deeply coupled to: Hyperscan
  (a C library dependency), a custom `cereal`-based serialization format for its state/model files
  (undocumented), the `ConfidenceCalculator`'s per-asset persistent state, and the WAAP component's
  IPC contract with the "attachment" (an nginx/Kong/APISIX/Envoy module) and the "agent" (separate
  orchestration/attachment-registrator/http-transaction-handler daemons). There is no `pip install`
  / single `.so` / documented C API boundary that exposes "score this payload" in isolation — you'd
  be vendoring a meaningful slice of a WAF product, not linking a model file.
- **Where inference runs:** in-process inside the attachment's call into the WAAP component
  (C++, same host as the reverse proxy), with a separate long-running "agent" process handling
  policy sync, learning-state persistence, and orchestration. Not a lightweight sidecar call.

## 3. Footprint — the number that matters most for funnypot

The docs never publish minimum CPU/RAM/disk requirements — `docs.openappsec.io` prerequisites pages
only list root permissions, `wget`, and an existing NGINX/Kong/APISIX install. A maintainer-unanswered
GitHub issue asking for minimum specs has been open since the repo's early days
([issue #126](https://github.com/openappsec/openappsec/issues/126)). A community deployment report
([discussion #249](https://github.com/openappsec/openappsec/discussions/249)) for >100 protected
sites needed to scale a VM to **128GB RAM** after running out of memory in 12 hours, with the
reporter suspecting a memory leak. Even taken as an outlier, it's consistent with the architecture:
`ConfidenceCalculator` alone budgets 40MB *per protected asset*, on top of the Hyperscan pattern
database, the parser stack, and the separate agent daemons. This is enterprise-WAF-shaped resource
usage — miles from funnypot's single PHP process + one small CPU llama.cpp sidecar.

## 4. Feasibility for funnypot

**(a) Reuse the actual open-appsec component — no.** Nothing is cheaply extractable: no standalone
model artifact, no documented model-file format, a Hyperscan dependency, and the one model that
*is* Apache-2.0 is explicitly the non-production-grade one. Embedding the WAAP engine via PHP FFI
would mean vendoring ~100 C++ files plus Hyperscan plus a chunk of the agent's persistence layer —
the opposite of "framework-free small PHP."

**(b) Reuse the concept — yes, and cheaply, scoped way down.** The useful idea to steal is narrow:
*score the payload for attack-family indicators, not just judge the URL path string.* That's a real
gap in funnypot today — `ProbeClassifier` (`src/App/Llm/ProbeClassifier.php`) only judges the
request path (hard-allow bait list, probe-token/entropy checks on path segments, extension
allowlist, app-word/pronounceability check) via `ProbeGate::decide()`, which AND-combines it with
`VelocityTracker`'s per-IP bulk-scan signal. Neither layer looks at query params, POST body, or
headers for classic attack payloads (`' OR 1=1`, `<script>`, `../../../etc/passwd`,
`${jndi:ldap://`, `; cat /etc/passwd`, etc.) — a request that's 404 on a plausible-looking path with
an obvious SQLi payload in a query string gets the same treatment as a clean plausible request
today.

**Proposed minimal design — a hand-weighted indicator scorer, no ML runtime:**

- A new pure-PHP class, e.g. `PayloadIndicatorScorer`, sitting next to `ProbeClassifier` as a third
  signal into `ProbeGate::decide()`.
- Input: query string + POST body (when present) + a short list of commonly-abused headers
  (`User-Agent`, `X-Forwarded-For`, `Referer`).
- Mechanism: a handful of regex/keyword *families* (SQLi, XSS, path traversal, command injection,
  template/SSTI injection, log4j-style JNDI, PHP object injection markers), each with a small static
  confidence weight, summed and thresholded — i.e., reimplement WAAP Phase 2 in miniature, skip
  Phase 1's deep multi-format parsing and Phase 3's stateful per-asset baselining entirely. Source
  the keyword/regex families from data funnypot already has license-clear access to: Galah's ~62
  attack paths (Apache-2.0, already cited in `honeypot-projects.md`), nuclei-templates' public
  detection regexes (funnypot's nuclei-inversion engine already parses these), and OWASP
  CRS/PayloadsAllTheThings for canonical payload shapes. No training pipeline, no model file, no new
  dependency — this is a static PHP array of patterns + weights, unit-testable exactly like
  `ProbeClassifier` is today.
- Decision change: a request that's `probe` on the path (today: plain 404) but scores "malicious" on
  payload indicators becomes a **new** honeypot-worthy case — still not just a plain 404, but
  arguably not the same *plausible-app* fake either. Cheapest correct framing: feed the payload
  score as a second axis alongside `ProbeClassifier`'s plausible/probe verdict, and let `ProbeGate`
  return a richer reason (`plausible`, `malicious-payload`, `probe`) so the caller can pick a
  response flavor (rich LLM fake vs a canned "attack detected, here's your fake shell" static
  page) instead of a boolean.
- Explicitly **not** worth building: the Phase 3 online per-asset baselining. It requires persistent
  state, warm-up time, and per-endpoint memory — the opposite of what a honeypot wants (funnypot
  wants a *confident* verdict on the very first hit from a never-seen-before IP, not a model that
  gets better after weeks of legitimate traffic it will rarely see).

**Rough effort:** design the pattern/weight families + port/curate keyword lists from
Galah/nuclei-templates + write the PHP scorer + tests ≈ **1–2 days**, similar scope to
`ProbeClassifier` itself. Contrast with actually training and maintaining a statistical classifier
(data collection, labeling, retraining, drift monitoring) — weeks to months of ongoing work — for a
domain (opportunistic internet scanner payloads) that is overwhelmingly known-signature space
already, which is exactly what nuclei-inversion and a curated regex list are good at. There's no
evidence in open-appsec's own docs that the "ML" framing buys accuracy a good regex/keyword list
doesn't already get for this threat model; its real differentiator (Phase 3 contextual baselining)
is the one piece that doesn't fit a honeypot's first-contact use case anyway.

## 5. Recommendation

**Skip integrating/embedding open-appsec.** License is fine but the artifact isn't reusable and the
footprint is wrong by an order of magnitude or more for what funnypot needs.

**Build the scoped-down analog**: a static keyword/regex payload-indicator scorer
(`PayloadIndicatorScorer`) added as a new signal to `ProbeGate`, sourced from data funnypot can
already license-clear (Galah, nuclei-templates, OWASP CRS/PayloadsAllTheThings), with zero new
runtime dependencies. This closes the real gap open-appsec's architecture highlights — funnypot
currently only judges the path, not the payload — without adopting anything resembling open-appsec's
actual weight, dependency graph, or stateful-baselining design.
