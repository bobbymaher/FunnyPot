# Tiny-Model Evaluation + Test Plan — funnypot LLM honeypot layer

Status: model shortlist for the Phase 2 `llama-server` sidecar (see
`LLM-HONEYPOT-RESEARCH.md`). The job is narrow and unglamorous: on a cache-miss
for a path that already passed the deterministic gate, write one short plausible
fake HTML page, output nothing but the page, and never refuse. The model fires
rarely (once per unique plausible path, then cached forever), so raw speed
matters less than **format discipline and never refusing**. This doc picks what
to try first on a small box, what to A/B, and what to avoid.

The incumbent recommendation in the research doc is Qwen2.5-1.5B-Instruct. This
doc re-scopes that against four newer/smaller candidates so we can push the
footprint down toward a `t4g.small`-class box if a sub-1B model holds up.

---

## 1. Candidate comparison

| Model | Params | Q4 size (GGUF) | Resident RAM (proc + KV) | Smallest fitting instance | License | Commercial + public repo OK? | Refusal risk | Output-only-HTML reliability | In LM Studio? |
|---|---|---|---|---|---|---|---|---|---|
| **Qwen3-0.6B** | 0.6B | ~0.4 GB | ~1.0–1.3 GB | `t4g.small` (2 GB) | Apache 2.0 | Yes, clean | Low | Moderate — *thinking mode must be disabled* (`/no_think`), else it emits `<think>…</think>` reasoning before the page | Yes (lmstudio-community / unsloth GGUF) |
| **Qwen2.5-0.5B-Instruct** | 0.5B | ~0.4 GB | ~1.0–1.2 GB | `t4g.small` (2 GB) | Apache 2.0 | Yes, clean | Low | Moderate — thin output, needs tight prompt + grammar | Yes |
| **Gemma-3n-E2B** | ~2B effective (MatFormer, ~5B raw) | ~2.5–3.5 GB | ~3.5–5 GB | `t4g.large` (8 GB) | Gemma Terms of Use + **Prohibited Use Policy** | **Conditional — see §4 license flag** | Moderate–High (Google safety tuning) | Good but chatty (adds explanations/fences) | Yes |
| **Phi-4-mini(-instruct)** | 3.8B | ~2.3–2.5 GB | ~3–4 GB | `t4g.large` (8 GB) | MIT | Yes, clean | **Moderate–High** — Microsoft RLHF refuses "deception/honeypot" framing readily | Very good (strong instruction-following) once it agrees to answer | Yes |
| **Qwen2.5-1.5B-Instruct** (incumbent) | 1.5B | ~1.1 GB | ~1.5–2 GB | `t4g.medium` (4 GB) | Apache 2.0 | Yes, clean | Low | Good | Yes |

Notes on the columns:

- **Resident RAM** is the model process plus a modest KV cache, on top of
  funnypot's existing nginx + php-fpm + TCP listeners + SQLite. The research doc
  sizes instances from this, not from the weight file alone.
- **Smallest fitting instance** assumes funnypot's full stack shares the box. A
  sub-1B model brings the sidecar within reach of a `t4g.small`; the incumbent
  1.5B wants `t4g.medium`; Phi-4-mini and Gemma-3n-E2B push back up to
  `t4g.large`, erasing the cost win that motivated looking below 1.5B.
- **Params alone do not predict CPU latency.** The research doc's own finding:
  a reasoning model (DeepSeek-1.5B) measured ~13s in LLMHoney. Qwen3-0.6B is a
  hybrid-reasoning model — with thinking left on it behaves like a reasoning
  model and blows both the latency budget and the output-format contract. Treat
  it as a plain instruct model only (`/no_think`).

---

## 2. What each candidate is actually good/bad at for this job

- **Qwen3-0.6B** — smallest credible pick with clean licensing. Its one trap is
  the hybrid thinking mode: leave it on and every response is prefixed with a
  reasoning block, which is both a latency hit and a format-contract violation.
  Disabled, it is a competent tiny instruct model in the Qwen2.5-0.5B weight
  class with a newer training run. Cheap to host.
- **Qwen2.5-0.5B-Instruct** — the safe, boring floor. Non-reasoning, Apache 2.0,
  tiny. The research doc already flags sub-1B models as prone to "incorrect or
  out-of-character outputs" (LLMHoney), so expect thinner pages that lean on the
  prompt's generic-login fallback. Good enough for the common case (a bland
  login / "not authorized" page) which is most of what the gate lets through.
- **Gemma-3n-E2B** — no quality edge that justifies its cost here. It is
  multimodal and large-footprint for an "effective 2B," it is chatty (fights the
  output-only-HTML rule), Google's safety tuning raises refusal risk, and the
  license carries a Prohibited Use Policy (§4). Nothing about the fake-page task
  needs what Gemma-3n adds.
- **Phi-4-mini** — genuinely strong instruction-following and clean MIT
  licensing, but the wrong personality for a deception layer: Microsoft's RLHF
  is quick to refuse anything framed as a honeypot, fake page, or deception.
  With grammar + prefill + neutral framing it can be coerced into compliance,
  but you are fighting the model instead of leaning on it, and at 3.8B it wants
  a `t4g.large`. Keep as a last-resort "if everything smaller reads too thin."
- **Qwen2.5-1.5B-Instruct** — the incumbent for good reason: Apache 2.0,
  benchmarked in LLMHoney (arXiv 2509.01463) as among the most reliable models
  in exactly this 0.36B–3.8B fake-response comparison, low refusal risk, good
  structured-output discipline, fits `t4g.medium`. The one to beat.

---

## 3. Refusal + preamble: the structural fix

A weaker model has two failure modes that a plain prompt cannot reliably close:

1. **Refusal** — "I can't help create a fake login page / that could be used to
   deceive users." (Highest on Phi-4-mini and Gemma-3n; lowest on Qwen.)
2. **Preamble / markdown fences** — "Sure! Here's a plausible page:\n```html…"
   The leading prose or ` ``` ` fence makes the body invalid to serve verbatim.

Fix these in order of strength — do not rely on prompt wording alone:

### 3.1 GBNF grammar-constrained decoding (the structural fix — do this)

In production the sidecar is llama.cpp `llama-server`, which supports GBNF
grammars. Constrain generation to a grammar that **can only emit HTML**: the
first token must be `<`, `<script>/<iframe>/<link>` are unreachable, and length
is bounded by the grammar plus `n_predict`. This makes preamble and markdown
fences *structurally impossible* rather than merely discouraged — the model
cannot type "Sure! " because "S" is not a legal first token. It also blunts soft
refusals, since a refusal sentence is not valid under an HTML-only grammar. This
is the single highest-leverage control and is the reason the research doc picks
bare `llama-server` over Ollama/llamafile (they add nothing on top of it).

Caveat for evaluation: **LM Studio's OpenAI-compatible endpoint does not take a
raw GBNF grammar** (it exposes JSON-schema structured output instead). So the
eval harness in §6 measures each model's *unconstrained* behaviour — its native
tendency to refuse or add preamble. That is deliberate: it tells you how hard
grammar will have to work per model. A model that already starts with `<` on the
raw prompt (Qwen family) needs grammar only as a guardrail; one that refuses or
fences on the raw prompt (Phi-4-mini) is relying entirely on grammar to save it,
which is more fragile. Prefer models that behave well *before* the grammar.

### 3.2 Assistant prefill (second line of defence)

Seed the assistant turn with an opening `<` (or `<!doctype html>`) so the model
continues an HTML document already in progress rather than deciding whether to
answer. A model mid-tag does not open with an apology. Works on any endpoint,
including LM Studio, and stacks with grammar.

### 3.3 Prompt framing (necessary, not sufficient)

- Frame as **security-research / defensive** work, never "deceive users." Say
  "generate a placeholder page for a security-research honeypot, as if this
  software existed" (the research-doc prompt already does this).
- Put the output contract first and make it absolute: "Output ONLY raw HTML, no
  explanation, no markdown fences."
- Include the **one-shot exemplar turn** (a fake request → a bare-HTML answer)
  baked before the real request. Prior art (beelzebub) shows an exemplar
  stabilises output format far better than instructions alone.
- For Qwen3-0.6B, append `/no_think` to kill the reasoning block.

Order of reliability: **grammar > prefill > exemplar > wording.** Ship all four;
never trust wording alone on a tiny model.

---

## 4. License flags (public-repo blocker)

funnypot is a public repo, so the model's terms must permit commercial use,
redistribution, and — critically — a deception/honeypot use case.

- **Apache 2.0 (Qwen3-0.6B, Qwen2.5-0.5B, Qwen2.5-1.5B):** clean. No use policy,
  no attribution strings, no field-of-use carve-out. Deception/honeypot use is
  unrestricted. **Preferred.**
- **MIT (Phi-4-mini):** clean on redistribution and commercial use, no
  Prohibited Use Policy attached to the license itself. The refusal problem is a
  behaviour issue, not a license issue.
- **Gemma Terms of Use + Prohibited Use Policy (Gemma-3n-E2B): flag.** Google's
  Gemma license binds you to a separate Prohibited Use Policy that restricts,
  among other things, generating content "to deceive or mislead." A honeypot
  serving fabricated pages to attackers is a defensive/security use, but the
  deceive-or-mislead clause is a genuine gray area for a *public* repo that ships
  the model behind exactly that behaviour. The research doc already rejected
  Gemma-2-2B for the same "custom terms with a Prohibited-Use Policy" reason and
  found no quality edge to justify the risk. Same verdict here: **avoid Gemma-3n
  for this project on license grounds alone**, before quality even enters.

---

## 5. Recommendation

**Try first on a small box: Qwen2.5-0.5B-Instruct.** It is the lowest-risk way
to test whether the footprint can drop to a `t4g.small`: Apache 2.0, ~0.4 GB,
non-reasoning, low refusal risk, LM Studio-available. If its pages read
plausibly for the bland login / "not authorized" / "under construction" cases
that dominate what the gate admits, we get the incumbent's behaviour at a
fraction of the RAM. If they read too thin, we have a clean upgrade path.

**A/B against it: Qwen3-0.6B (thinking disabled) and the incumbent
Qwen2.5-1.5B.** Qwen3-0.6B is the same footprint class as the 0.5B with a newer
training run — a cheap upside bet, *provided* `/no_think` reliably suppresses the
reasoning block (verify in the eval; if it leaks `<think>`, drop it). Qwen2.5-1.5B
is the known-good ceiling to measure the small models against; if the 0.5B/0.6B
pages are visibly worse, fall back to it on a `t4g.medium` — that is the safe
default the research doc already endorses.

**Avoid: Gemma-3n-E2B** — license Prohibited-Use-Policy risk for a public
deception use case (§4), largest footprint, chattiest output, no quality edge.
**Avoid unless everything smaller reads thin: Phi-4-mini** — clean MIT license
but the most refusal-prone personality for a honeypot, and a 3.8B footprint that
pushes back to `t4g.large` and erases the reason we went sub-1.5B. Only reach for
it if the sub-1B Qwen pages are unusably generic, and even then plan on grammar +
prefill doing heavy lifting against its refusals.

Decision order: **Qwen2.5-0.5B → (if thin) Qwen3-0.6B / Qwen2.5-1.5B → (only if
still thin) Phi-4-mini. Gemma-3n excluded.**

---

## 6. How the guard rails make a weaker model safe

The point of the design in `LLM-HONEYPOT-RESEARCH.md` is that model *quality* is
not load-bearing for *safety* — the deterministic layers around it are. A weaker
model is acceptable because it can never do damage even when it misbehaves:

1. **The deterministic gate runs before the model.** A random dirbuster
   calibration probe (`/intentional_404_page.php`) never reaches the model at
   all — Gate A (per-IP bulk-scan behaviour) and Gate B (lexical plausibility)
   send it to the byte-identical plain 404. So the weak model only ever sees
   paths that already look like plausible app paths. It cannot unmask the
   honeypot on garbage because it never generates for garbage.
2. **GBNF grammar makes malformed/refusing output unreachable** (§3.1). The model
   physically cannot emit a `<script>`, an external URL, a markdown fence, or a
   leading apology, regardless of how weak it is.
3. **`LlmOutputSanitizer` treats all model output as hostile.** Byte cap,
   dangerous-tag strip, `on\w+=` strip, absolute-URL deny, exploit-shape
   deny-list, UTF-8 safety. Any violation returns `null`, which is identical to
   a generation failure. A weak model that produces junk simply falls through to
   the plain 404 — the same safe output as today.
4. **Status and Content-Type are app-chosen, never model-chosen** (allowlist
   200/401/403/404, no 3xx). A confused model cannot make the honeypot an open
   redirect or emit a broken status line.
5. **Uniform fallback.** Refusal, timeout, empty output, sanitizer rejection —
   every failure mode collapses to the exact same plain 404 the honeypot serves
   now. The feature is purely additive: worst case it degrades to current
   behaviour, it can never produce a worse tell than a plain 404.
6. **Deterministic caching.** One fake per path, served byte-identical forever,
   through the same latency envelope as a matched template. A weak model's
   occasional bad page is a one-time event that either gets sanitized to `null`
   (retry later) or, if it passed all guards, is at least *consistent* — and
   consistency is the property that actually matters against scan-scale
   fingerprinting.

So the model choice is a *quality* decision (do the pages read plausibly?), not a
*safety* decision (the guard rails hold regardless). That is exactly why it is
worth trying the smallest Qwen first: if a 0.5B model's pages read well enough,
nothing about the safety posture changes.

---

## 7. Running the eval

See `scripts/llm-eval/eval.php`. Load each candidate in LM Studio, start its
local server, then:

```
php scripts/llm-eval/eval.php <model-name>
```

It POSTs the honeypot prompt for a fixed set of URLs (a plausible rare app path,
an app dir, an api path, and a garbage control) and prints a per-URL table
scoring: refused? / had preamble or markdown fences? / valid-ish HTML? / byte
size. Use it to eyeball which model starts with `<`, never apologises, and stays
in a realistic byte range *before* grammar is applied — those are the ones
grammar then makes bulletproof.
