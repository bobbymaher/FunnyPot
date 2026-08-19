# Training-data sourcing + eval plan

How to build a high-fidelity (HTTP request → response) corpus for funnypot's fake-response model, and
how to measure whether it's any good. Grounded in a survey of released datasets + existing LLM
honeypots (see `research/honeypot-projects.md` for per-project notes). Read
`LLM-TRAINING-BRAINSTORM.md` + `LLM-TRAINING-STRATEGY.md` first for the why.

## Bottom line

The **request** side is easy (many public sources). The **response** side is the hard, valuable part,
and the highest-fidelity way to get it is to **record real software**, not to distill a model's guesses.
Self-distillation (what tonight's LoRA used) and big-model distillation both inherit a model's
hallucinated headers/versions — fingerprintable tells baked into the training data. Real captured
responses are ground truth. Every "response-side" research dataset that sounded promising is either SSH
(not HTTP), not released, or paywalled — so there is no shortcut around building this.

## The winning approach — record from real software (warcprox replay harness)

Bonus: this pipeline also produces your **eval oracle** for free (the real response to diff against).

**1. Targets (the response generators)** — Docker containers, on an isolated network, each tagged with
its identity so pairs are labeled:
- *Stock/benign (the header goldmine):* `nginx`, `httpd`, `tomcat`, `php:8-apache`, `wordpress`+`mysql`,
  `phpmyadmin`, node/express, python/FastAPI/Flask, `gitea`, `grafana`, `jenkins`, `elasticsearch`+`kibana`,
  `adminer`. These emit the real `Server`/`X-Powered-By`/`ETag`/`WWW-Authenticate` headers and genuine
  401/403/404/500 default bodies for the exact paths bots hit (`/wp-login.php`, `/xmlrpc.php`,
  `/server-status`, `/manager/html`, `/.git/config`, …).
- *Vulhub CVE envs* (`github.com/vulhub/vulhub`, MIT): the ones matching live scanner traffic — log4shell,
  Spring, Struts2, ThinkPHP, WebLogic, Confluence, GitLab, Drupal, phpunit eval-stdin, PHP-CGI.
- *App-vuln labs:* DVWA, OWASP Juice Shop, WebGoat, Mutillidae, bWAPP.
- *BaxBench* (`github.com/logic-star-ai/baxbench`) — **the accelerator**: 392 real backends (28 scenarios ×
  14 frameworks) shipping correct+buggy implementations, functional test suites (ready-made benign request
  drivers), and OpenAPI specs (structured fuzz seeds). Least-effort high-fidelity API pairs.

**2. Request corpus (the input distribution to fire):**
- *SecLists* `Discovery/Web-Content/` (raft-*, common.txt, CMS lists) — the paths bots actually hit.
- *nuclei-templates* — run `nuclei` through the proxy; capture the real responses.
- *PayloadsAllTheThings* — injection strings.
- **CSIC 2010 + ECML/PKDD 2007** — *replay these real request strings* against the containers. This is the
  key move that turns the big request-only academic datasets into request→response pairs. Mirror:
  `github.com/msudol/Web-Application-Attack-Datasets`.
- *funnypot's own hit logs + SANS DShield weblogs* — the true production distribution; replay to prioritize
  paths that actually get hit.

**3. Drive + capture (native WARC pairs):** run **warcprox** (`pip install warcprox; warcprox -z -n funnypot`)
as a recording proxy; point every driver at it via `HTTP_PROXY`. Drivers: `ffuf`/`feroxbuster` (wordlists),
`nuclei` (templates), a small Python replayer for CSIC/DShield/funnypot log lines. warcprox writes standard
WARC with paired request+response records (real headers, status, body). Plain HTTP against containers avoids
MITM-CA hassle. JSON alternative: `mitmdump -s` with a flow→JSONL addon.

**4. Normalize into JSONL** with `warcio`. Join response↔request (`WARC-Concurrent-To`), emit
`{method, path, query, req_headers, req_body, status, resp_headers(ordered), resp_body, server_software,
source_container}`. Then: **template volatile fields** (`Date`, random `ETag`, `Set-Cookie` ids, CSRF
nonces → placeholder tokens — nonces are what make a naive LLM honeypot detectable); **dedup** by
(path-class, status, normalized-body-hash); **preserve header order + casing** (order is itself a
server fingerprint).

**Yield:** raft-medium (~30k) × ~15 stock containers → a few hundred k raw responses → tens of thousands of
distinct deduped (path-pattern → response-template) pairs in a few machine-days.

**Gotchas:** LLMs emit wrong `Content-Length` and inconsistent repeats — both dead giveaways; compute
`Content-Length` deterministically and cache static-path responses instead of regenerating. Cap/side-store
large or binary bodies. Auth/stateful paths need seeded sessions, but most scanner hits are unauth GETs.
Mind redistribution licenses if you ever ship the corpus (WordPress GPL, etc.); internal training on OSS
default pages is fine.

## Seed cache directly from dd-honeypot (free, hand-authored)

`ThalesGroup/dd-honeypot` (Apache-2.0) ships ~7 hand-authored phpMyAdmin 5.2.0 pages at
`test/honeypots/php_my_admin/data.jsonl` as `{path, args, response}`. Not a training set (too small), but
7 legit ground-truth pages worth more than hundreds of distilled ones — drop them straight into funnypot's
cache (prepend `/` to `path`, fold `args` into the query). Adopt its record schema + the `is_static` flag
(seeds survive a cache-clear) + a `dump()`-style export of LLM-generated entries for human review→promotion.

## Ready-made datasets — grab-first shortlist

| Dataset | Use | HTTP? | Responses? | URL | License |
| --- | --- | --- | --- | --- | --- |
| **BaxBench** | response generator (run it) | ✅ | generates real | `github.com/logic-star-ai/baxbench` | open |
| **Honeyval** | eval harness + metrics | ✅ | runtime | `github.com/google-research/honeyval` | Apache-2.0 |
| **Vulhub** | CVE response envs | ✅ | via replay | `github.com/vulhub/vulhub` | MIT |
| **CSIC 2010** | request distribution (replay) | ✅ | request-only | `github.com/msudol/Web-Application-Attack-Datasets` | research |
| **ECML/PKDD 2007** | request distribution (replay) | ✅ | request-only | same msudol mirror | research |
| **SecLists** | paths bots hit | inputs | — | `github.com/danielmiessler/SecLists` | MIT |
| **nuclei-templates** | probe→matcher | inputs | partial | `github.com/projectdiscovery/nuclei-templates` | MIT |
| **Common Crawl** | benign header/body priors | ✅ | yes (WARC) | `commoncrawl.org/get-started` | open |
| **HTTP Archive** | header realism tables | ✅ | resp-only | BigQuery `httparchive.*` | public BQ |

**Fact-checks (claims that don't hold):** `hotal/honeypot_logs` and `palisaderesearch/LLM-Honeypot-Logs`
are **SSH, not HTTP, and gated** (useful for method/metrics only). The multi-agent "140,973 SQLi pairs"
dataset (arXiv 2603.02963) is **real ground truth but NOT released**. AIIPot's "17,604 HTTP" is
**unverified** (AIIPot is an IoT/Telnet honeypot). arXiv 2002.04059 is a modeling paper built on CSIC,
**not a dataset**.

## The RAG upgrade (fits a tiny CPU model best)

Because funnypot runs a *tiny* model at request time, the captured corpus doubles as a **retrieval index**:
at request time, retrieve the nearest real (path → response) exemplar and have the small model adapt it
(the DecoyPot insight). This sidesteps the small model's tendency to hallucinate implausible headers, and
it's the highest-ROI next step per the brainstorm — buildable with no training, reusing `ProbeClassifier`'s
lexical features (no embeddings needed to start).

## Eval — fingerprintability first

The captured corpus gives a **ground-truth oracle for free**: you already have the real container's
response to each request, so diff funnypot against reality.

1. **Response-diff exact-match** (cheapest, strongest): per request, compare funnypot vs the captured real
   response — status exact; header set-equality **and ordering**; `Content-Length` correctness; body
   similarity. Any mismatch is a literal fingerprint.
2. **Honeyval detection-gap** (adopt directly): run a hacking agent against funnypot and against the real
   app; measure detection TPR (agent flags funnypot) vs FPR on the real app. Target: funnypot TPR ≈ real-app
   FPR (indistinguishable). Honeyval reports LLM honeypots <~40% TPR vs ~100% for rule-based.
3. **Similarity** (regression signal during training): embedding cosine + BLEU/ROUGE/edit-distance vs real.
4. **Determinism:** same request twice — a real static path is byte-identical; a wobbling LLM is a tell.
5. **Latency + cost:** a CPU model must answer fast; track p50/p95 and CPU-ms/response (per tonight's finding,
   a slow generation is itself a fingerprint — cache + seed aggressively).
6. **Header-realism lint:** check `Server`/`Date` format, `Content-Length`, header casing+order against the
   claimed server's reference tables (built from the captured corpus or HTTP Archive).

## Recommended order

1. Ship **RAG** on the current 0.5B (no training) — highest short-term ROI, sidesteps hallucination.
2. Stand up the **warcprox replay harness** (BaxBench + Vulhub + stock containers + SecLists/CSIC) → the
   first ground-truth corpus + the eval oracle.
3. Adopt **Honeyval** + the response-diff metric to measure before/after.
4. Only then **distillation → LoRA** on the real corpus (never raw nuclei inversions; keep the sanitizer).
