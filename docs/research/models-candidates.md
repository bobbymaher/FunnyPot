# Model candidates — evaluation notes

Scouting pass over Hugging Face for models that might replace or benchmark
against the incumbent sidecar model (`Qwen2.5-Coder-0.5B-Instruct`, Q4_K_M,
~400 MB, described in `../../../funnypot-llm/README.md`). Companion docs:
`../LLM-MODEL-EVAL.md` (the existing size/license/refusal comparison across
Qwen3-0.6B / Qwen2.5-0.5B / Gemma-3n-E2B / Phi-4-mini / Qwen2.5-1.5B) and
`../LLM-HONEYPOT-RESEARCH.md`.

**Bottom line up front:** the one purpose-built candidate found —
`Woyoung21/qwen-honeypot-GGUF` — is tuned for the wrong honeypot shape (SSH/
shell terminal output, not HTTP/HTML) and sits at 1.5B, over funnypot's
"ideally ≤0.5–1B" line and *at*, not under, the "<1.5B" hard ceiling. It is
wire-compatible with the sidecar (same Qwen2 arch, same ChatML tokens) so it
*can* be loaded and benchmarked cheaply, but there is no task-fit reason to
expect it beats the current 0.5B on HTML plausibility, and every reason to
expect its shell-flavored LoRA leaks odd artifacts into HTML output. Treat it
as a curiosity to A/B once, not an adoption candidate.

---

## 1. `Woyoung21/qwen-honeypot-GGUF`

Source: https://huggingface.co/Woyoung21/qwen-honeypot-GGUF (model card,
`README.md`, `Modelfile`, HF API metadata — all fetched directly, no download
of the GGUF weights).

| Fact | Value |
|---|---|
| Base model | `Qwen/Qwen2.5-Coder-1.5B-Instruct` (via `unsloth/Qwen2.5-Coder-1.5B-Instruct`) |
| Parameters | 1.5B (1.54B total, 1.31B non-embedding) |
| Architecture | `Qwen2ForCausalLM` — same family/arch as funnypot's current model |
| GGUF file | `qwen2.5-coder-1.5b-instruct.Q4_K_M.gguf`, **986 MB**, single quant only (no other quant sizes offered) |
| Context length | 32,768 tokens (inherited from base; sidecar caps this itself with `--ctx-size`, currently 2048) |
| Training method | **LoRA fine-tune via Unsloth**, not full SFT. 18.4M trainable LoRA params, 8 epochs, 472 steps, ~25 min on a Colab T4 |
| Training data | (1) ~100 hand-written honeypot examples — filesystem enumeration, log files, SSH keys, credentials, cloud metadata, persistence artifacts; **not published/linked**, so its contents can't be audited directly. (2) `mrheinen/linux-commands` (HF dataset, Apache 2.0, 481 rows, real Debian terminal command→output pairs, "cleaned to remove multi-command sequences") |
| Task the model was actually tuned for | **"You are a computer terminal and receive one or more command-line commands. Your task is to provide the example output of these commands."** — i.e. a Cowrie-style **SSH/shell** honeypot backend, not an HTTP/HTML one. Card's own framing: "forwards attacker-issued shell commands to an LLM, which responds with realistic terminal output." |
| Loss reported | train loss ~0.55–0.65, eval loss ~0.72. No other benchmarks. |
| License | **Not tagged on the repo itself** (HF API returns no `license` field). Base model (Qwen2.5-Coder-1.5B-Instruct) is Apache 2.0 and the named dataset is Apache 2.0, so a permissive license is *likely* the intent, but it is not stated — a real gap for a project (funnypot) that ships a public repo and needs the license question closed, not inferred. |
| Prompt/chat format | Standard Qwen2 ChatML (`<\|im_start\|>role\n...<\|im_end\|>`), confirmed via the repo's Ollama `Modelfile` template. **Default `SYSTEM` in that Modelfile is the generic "You are Qwen, created by Alibaba Cloud. You are a helpful assistant."** — i.e. the honeypot behavior is not baked into a default system prompt; it only shows up because of the LoRA weight deltas plus whatever system prompt the *caller* supplies. This matches funnypot's own pattern (funnypot supplies its own system prompt each call), so no format friction there. |
| Repo files | `.gitattributes`, `Modelfile`, `README.md`, `config.json`, the one `.gguf` — no other quant, no training script, no eval script in-repo |
| Popularity | 123 downloads, 1 like, created 2025-11-20, last modified 2025-11-26 — small, low-traffic community repo |

### Is it drop-in for funnypot's llama.cpp sidecar?

**Mechanically, yes; behaviorally, no.**

- Same `Qwen2ForCausalLM` arch, same GGUF format, same ChatML special tokens
  (`<\|im_start\|>`, `<\|im_end\|>`) that `LlmPromptBuilder`/`LlmClient` already
  emit. It would load under the existing `entrypoint.sh` (`--model`,
  `--ctx-size`, `--parallel`, `--threads`, `--cont-batching`) with zero code
  changes, and the sidecar's `/completion` + GBNF-grammar contract
  (`resources/llm/html.gbnf`) would apply just as it does to the 0.5B — the
  grammar forces `<!doctype html>`-first output regardless of what the model
  "wants" to say.
- **But the model was never shown HTML during fine-tuning.** Its ~100-example
  custom set and the 481-row `linux-commands` set are both plain-text terminal
  transcripts. The GBNF grammar can force it to *emit* well-formed HTML tokens,
  but there's no reason its LoRA-shifted priors help it write a *plausible*
  fake app page — if anything, the shell-output fine-tuning pulls token
  probabilities toward things like `total 24`, `-rw-r--r--`, `user@host:~$`,
  directory listings, `cat`/`ls` output shapes. Under grammar constraint that
  can't literally break out of HTML, but it can plausibly surface as stray
  shell-flavored text *inside* HTML (e.g. a listing-looking `<pre>` block on an
  unrelated login page) — which is a believability problem, and arguably a
  new-flavor fingerprint risk: an attacker who notices a web app spontaneously
  emitting `total 24` / `drwxr-xr-x` formatting has a much stronger "this is
  fake" signal than a generically bland page.
- Base Qwen2.5-Coder-1.5B-Instruct (untuned) is *already* the "known-good
  ceiling" fallback in `../LLM-MODEL-EVAL.md` §5 ("Qwen2.5-1.5B... the one to
  beat"). Woyoung21's fine-tune adds no HTML-relevant capability on top of that
  ceiling and costs the same RAM/latency footprint, so the honest comparison
  isn't "0.5B vs. Woyoung21" — it's "Woyoung21 vs. plain Qwen2.5-Coder-1.5B-Instruct-GGUF",
  and there's no a priori reason to expect the honeypot LoRA wins that one for
  *this* task.

### Fingerprint / training-data poison risk

- No evidence of literal scanner/matcher signature strings in the two
  documented training sources — `linux-commands` is real, benign Debian
  command output; the custom 100-example set's *categories* (filesystem, logs,
  SSH keys, credentials, cloud metadata, persistence) are generic honeypot
  content classes, not verbatim scanner fingerprints, as far as the card
  describes them. **Caveat: that 100-example set is not published**, so this
  can't be verified directly — only the card author's description is
  available.
- The more concrete risk is the *task-mismatch* one above: shell-transcript
  artifacts leaking into an HTML response body would read as "broken/weird"
  to a human attacker and as a stronger honeypot tell than a bland but
  internally-consistent fake page. This is a plausibility/fingerprint risk
  specific to reusing an off-topic fine-tune, not a data-poisoning risk in the
  classic sense.

### Verdict

**Do not adopt. Optional one-shot benchmark, low priority.** Fails the size
ceiling (1.5B, not <1.5B), offers no training signal relevant to HTML
generation (it was tuned for shell-command emulation, a different funnypot
subsystem — see `src/Protocol/Shell/FakeShell.php` for where a *shell*-tuned
model like this would actually be relevant), has an unstated license on a
project that must ship one, and its only realistic role is as a free data
point for "does a 1.5B fine-tune skew toward shell-flavored artifacts under
HTML grammar constraint" — worth one quick A/B run only because it's free to
try (mechanically drop-in, no code changes) and never worth deploying over the
plain Qwen2.5-Coder-1.5B-Instruct-GGUF baseline that `../LLM-MODEL-EVAL.md`
already treats as the size ceiling to avoid.

---

## 2. Secondary scan — other <1.5B / near-1.5B "honeypot"-adjacent HF models

Searched HF's model-search API for `honeypot`, `web attack`, `tarpit`, plus
general web search for phishing/fake-website generator models. Nothing else
purpose-built for **HTTP/HTML** honeypot generation turned up; the space is
almost entirely SSH/shell honeypots (Cowrie-style) or attack-traffic
*classifiers* (the opposite task — detecting attacks, not generating decoys).

| Model | One-line verdict |
|---|---|
| `vyykaaa/web-attack-llama3-v1` (+ `-f16`) | Llama-3 **8B**, 4-bit bitsandbytes. Way over budget; no honeypot framing found in its (thin) card beyond the repo name. Reject on size alone. |
| `JunyaoC/tarpit_cleaner_phi3_q4_k_m` | Phi-3-mini (~3.8B) LoRA, already GGUF/Q4_K_M. Interesting *direction* — "tarpit cleaner" implies generating filler content to waste a scraper's time, thematically close to funnypot's goal — but 3.8B blows the size ceiling the same way Phi-4-mini already does in `../LLM-MODEL-EVAL.md` (and Phi models there are flagged as the most refusal-prone personality for deception framing). Reject on size; not worth chasing further. |
| `stewy33/*-honeypot_ignore_comment-*` (Gemma-3-1B, Llama-3.2-1B, Qwen2.5-1.5B PEFT adapters) | **False positive.** "Honeypot" here is AI-safety/deceptive-alignment research jargon (a bait scenario used to test whether a model takes a forbidden action), unrelated to network security honeypots. Cards are placeholder-only ("[More Information Needed]"). Not applicable — do not confuse with a web-honeypot model despite the name match. |
| `Qwen/Qwen2.5-Coder-1.5B-Instruct` (untuned base, official GGUF quants exist from third parties) | Not honeypot-tuned, but this is the actual ceiling to benchmark against if the current 0.5B ever reads too thin — already the incumbent recommendation in `../LLM-MODEL-EVAL.md`. More useful to A/B than Woyoung21's fine-tune of the same base. |
| `HuggingFaceTB/SmolLM2-1.7B-Instruct` (and 360M) | General-purpose small model, no honeypot/coder tuning, Apache 2.0. 1.7B variant is over budget and untested for HTML-output discipline; 360M is small enough but a weaker instruction-follower than Qwen2.5-Coder at this size class per public benchmarks. Not worth prioritizing over the Qwen family already selected on `../LLM-MODEL-EVAL.md` licensing/behavior grounds. |

No candidate found beats or meaningfully complements the Qwen2.5-Coder-0.5B/1.5B
pair already shortlisted in `../LLM-MODEL-EVAL.md`. The HF "honeypot" tag is
dominated by (a) SSH/terminal honeypots, (b) attack-detection classifiers, and
(c) an unrelated AI-safety research naming collision.

---

## 3. Benchmark plan — A/B on the box

Goal: decide whether any candidate is worth swapping in for
`Qwen2.5-Coder-0.5B-Instruct`, using the machinery that already exists in this
repo rather than inventing new tooling.

### 3.1 What to compare

1. **Baseline (current):** `Qwen2.5-Coder-0.5B-Instruct` Q4_K_M (~400 MB) — the
   shipped default in `funnypot-llm/entrypoint.sh` / `Dockerfile`.
2. **Woyoung21/qwen-honeypot-GGUF** Q4_K_M (986 MB) — one-shot curiosity run
   per §1.
3. **Plain `Qwen2.5-Coder-1.5B-Instruct` Q4_K_M** (untuned base, ~1.1 GB per
   `../LLM-MODEL-EVAL.md`'s own table) — the real ceiling comparison; more
   informative than #2 since it isolates "does 1.5B help at all" from "does
   this particular shell-tuned LoRA help."

Load each one at a time into the sidecar (swap `MODEL_PATH` /
`--build-arg MODEL_URL` per `funnypot-llm/README.md`) — don't try to run three
models concurrently on the 3.8 GB box.

### 3.2 Step 1 — reuse the existing unconstrained-behavior harness

`scripts/llm-eval/eval.php` already does exactly the "refuses? / fences? /
starts with `<`?" check the research docs call for, against an
OpenAI-compatible `/v1/chat/completions` endpoint (llama.cpp's `llama-server`
exposes this alongside the native `/completion` used in production). Point it
at each candidate in turn:

```bash
LLM_EVAL_URL=http://<sidecar-host>:8080/v1/chat/completions \
LLM_EVAL_MODEL=- \
php scripts/llm-eval/eval.php
```

Read the table per `../LLM-MODEL-EVAL.md` §3.1's rule: `refused?` and
`preamble/fence?` must be "no" *before* grammar is even applied — a model that
needs grammar to save it every time is more fragile in production than one
that's already well-behaved raw. This step alone will likely be diagnostic for
Woyoung21 (watch for shell-artifact leakage in the raw output even where it
technically "looks like HTML").

### 3.3 Step 2 — production-shaped grammar + latency run

`eval.php` doesn't send the GBNF grammar (LM Studio can't take raw GBNF — see
`../LLM-MODEL-EVAL.md` §3.1's caveat), so measure the real request shape
directly against `/completion` with `curl`, timing each call:

```bash
time curl -s http://<sidecar-host>:8080/completion \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "prompt": "<|im_start|>system\n...(production system prompt from LlmPromptBuilder)...<|im_end|>\n<|im_start|>user\nMethod: GET\nPath: /admin/config.old<|im_end|>\n<|im_start|>assistant\n",
  "grammar": "<contents of resources/llm/html.gbnf>",
  "n_predict": 320,
  "temperature": 0.4,
  "top_p": 0.9,
  "repeat_penalty": 1.1,
  "stop": ["<|im_end|>", "</html>"]
}
JSON
```

Run this for a fixed set of ~15-20 paths spanning the categories
`eval.php`/`LLM-HONEYPOT-RESEARCH.md` already use (rare app login pages, app
dirs, api paths, product-name-bearing paths) against each candidate model, and
record per request:

- **Latency** — wall clock from `time`, plus llama.cpp's own
  `timings.predicted_per_second` in the JSON response (compare tokens/sec, not
  just wall time, since candidates may hit `n_predict` at different rates).
- **Servable-HTML rate** — did the sanitizer-equivalent checks pass: starts
  with `<!doctype html>` (grammar should guarantee this — flag any candidate
  where it doesn't, that's a grammar/model incompatibility bug, not a
  preference issue), no banned tags, no absolute URLs, under the byte cap.
  Reuse `hasPreambleOrFence()`/`looksLikeHtml()` logic from `eval.php` or the
  real `LlmOutputSanitizer` class if running this from inside a funnypot
  container.
- **"Juiciness"** — no existing automated scorer in the repo, so score by
  hand on a fixed rubric applied blind (don't know which model produced which
  output) across the same ~15-20 samples: does the page's content match the
  path's implied product/purpose; does it invent plausible-but-fake secondary
  details (version strings, nav links, form fields) versus a bare generic
  template; is it free of shell-transcript-style artifacts (the specific
  failure mode to watch for on Woyoung21); length/information density. This
  is the one part of the plan that's inherently manual — automate only the
  refusal/format/latency legs.

### 3.4 Decision rule

- If plain Qwen2.5-Coder-1.5B-Instruct doesn't clearly beat the 0.5B on
  juiciness for the common cases (bland login / not-authorized / under
  construction, per `../LLM-MODEL-EVAL.md` §2), there's no case for spending
  the extra RAM on *any* 1.5B-class model, Woyoung21 included — stop there.
- If it does clearly beat the 0.5B, only then is it worth also running
  Woyoung21 through the same rubric to see whether its shell-honeypot LoRA is
  strictly worse (expected, per §1's task-mismatch argument) or surprisingly
  neutral. Never adopt Woyoung21 on the strength of raw loss numbers or
  parameter count alone — the eval doc's whole thesis is that guard rails
  (grammar, sanitizer, gate) make *raw* model quality secondary to
  format-discipline and non-refusal, and Woyoung21 was never trained toward
  format-discipline on *this* format.
- License blocker: before shipping Woyoung21 anywhere reachable from a public
  repo, get an explicit license answer from the model author (open an HF
  discussion or contact `Woyoung21` directly) — do not infer Apache 2.0 from
  the base model and dataset licenses and ship it unverified, per the
  public-repo license-flag discipline `../LLM-MODEL-EVAL.md` §4 already
  applies to every other candidate.
