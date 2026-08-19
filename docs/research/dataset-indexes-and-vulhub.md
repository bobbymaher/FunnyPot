# Dataset indexes + Vulhub ground-truth pipeline

Scope: mine two "awesome list" index repos for anything genuinely useful to funnypot's
tiny-model HTTP responder, and design a concrete pipeline to record real (request → response)
ground truth from Vulhub containers. Companion to `docs/LLM-TRAINING-DATA.md` (the existing
sourcing/eval plan) — this doc supplies the two index-repo shortlists it doesn't cover, and
turns its one-paragraph Vulhub sketch into a target list + tooling decision concrete enough to
build against. Read that doc first; this one doesn't repeat its RAG/eval/fingerprinting sections.

## 1. `Ashfaaq98/awesome-genai-cyberhub` — verdict: nothing to adopt

Scanned the root README plus the `honeypots/`, `offensive-security/`, `vulnerability-analysis/`
and `detection-engineering/` sub-pages (MIT license, root README explicitly links each topic
folder). Filtered against the brief: small self-hostable models, HTTP request/response datasets,
honeypot corpora.

- **Models section** (4 entries): SecureBERT (BERT *encoder*, not generative), Lily-Cybersecurity-7B,
  Foundation-Sec-8B, Sec-Gemini v1.0 (Google-hosted, not self-hostable). None fit — the encoder
  can't generate HTML, and 7–8B is an order of magnitude past what a t3.micro CPU responder can
  run; funnypot is already at the practical floor (Qwen2.5-Coder-0.5B, per
  `docs/LLM-TRAINING-STRATEGY.md`). Nothing smaller is listed.
- **Benchmarks & Datasets section** (~25 entries): all CTF/agent-evaluation benchmarks (NYU CTF
  Bench, CyberGym, Cybench, CVE-Bench, WebExploitBench…) or CTI/threat-intel benchmarks. Zero
  HTTP request/response datasets, zero honeypot corpora — these measure how well an *attacking*
  agent performs, not what a real server returns.
- **`honeypots/` sub-page** (the directly relevant one): lists galah, shelLM, VelLMes, DECEIVE,
  beelzebub, honeybee, llm-honeypot (PalisadeResearch) as tools, plus 5 papers (HoneyGPT, LLMPot,
  "LLM in the Shell", MySQL-Pot, LLM-Sherlock). **Every tool here is already surveyed in depth**
  in `docs/research/honeypot-projects.md` (galah's `cleanResponse`/rules.yaml/JSON contract,
  beelzebub's seeded-generation, DECEIVE's prompt split, VelLMes's HTTP persona prompt — all
  cited and mined there already). None publish a downloadable request/response corpus; they're
  live frameworks, not datasets. The 5 papers describe architectures, not released data.

**Conclusion:** this index is aimed at SOC/CTI/red-team tooling, not honeypot training data. It
independently corroborates that galah/beelzebub/DECEIVE are the honeypot tools worth reading —
already done — but adds no dataset, no corpus, no model funnypot doesn't already know about.

## 2. `shramos/Awesome-Cybersecurity-Datasets` — one dataset confirmed, one worth a look

No repo-level license (`license: null` via the GitHub API — the curation itself is
all-rights-reserved-by-default; irrelevant here since it's just an external-link index, each
target dataset carries its own terms). Scanned all 14 sections; most are IDS/malware/PCAP/fraud
datasets with no bearing on an HTTP honeypot. Relevant results:

| Dataset | Format | HTTP scope | License | Verdict |
| --- | --- | --- | --- | --- |
| **HTTP DATASET CSIC 2010** | raw HTTP request text (normal + anomalous, labeled) | requests only, no real responses | "research purposes," no formal redistribution license | **Already tracked** in `LLM-TRAINING-DATA.md` as a replay-corpus source. No new information here beyond confirming it's the one HTTP dataset shramos's list surfaces. |
| **500K HTTP Headers** (`hackertarget.com/500k-http-headers`) | raw text, 75MB, 5×100k-header shards keyed to an Alexa-top-500k site list, captured May 2014 | real `Server`/`X-Powered-By`/security-header combinations from live production sites, response side only (no bodies) | site says "available for research purposes," no formal license — treat as unclear/no-redistribution | **New, narrowly useful.** Not request/response *pairs* and 12 years stale (expect dated PHP/Apache/IIS version strings), but it's a real-world prior on which `Server`/`X-Powered-By`/cookie-flag combinations actually co-occur in the wild, casing/ordering included. Feeds the "header-realism lint" `LLM-TRAINING-DATA.md` already calls for (§ Eval, item 6) better than guessing plausible combos by hand. Use as a *reference table*, not training text — don't quote it verbatim into prompts/outputs, and don't redistribute the 75MB archive. Verify the link is still live before depending on it; unclear it's still updated. |
| **Fwaf-Machine-Learning-driven-Web-Application-Firewall** (`faizann24`) | two flat text files, `goodqueries.txt` / `badqueries.txt` | URL/query strings only, not full requests, no responses | no LICENSE file in repo | **Low value, skip.** String-level, not request-level; older and thinner than PayloadsAllTheThings/SecLists which funnypot already sources from. Redundant. |
| **2017-SUEE-data-set** (`vs-uulm`) | raw `.pcap` (port 80/443 capture, needs extraction) | full packets in/out of one Apache web server, but the *attack* traffic is slowloris-family DoS, not scanner/exploit probes | no LICENSE file in repo | **Skip.** DoS timing attacks aren't in scope for an HTTP-response honeypot (there's no interesting *response* to learn — it's about connection starvation, not content); would cost pcap-extraction effort for off-topic payoff. |
| Web Attack Payloads (`foospidy/payloads`), West Point NSA logs, ISOT, Common Crawl, Internet-Wide Scan Data Repository | — | — | — | Already covered by existing higher-quality sources (PayloadsAllTheThings/SecLists, funnypot's own hit logs, Common Crawl already listed in `LLM-TRAINING-DATA.md`) or too generic to add signal. Skip. |

**Bottom line:** shramos's list mostly reconfirms CSIC 2010 (no new information) and surfaces one
genuinely new item — the 500K HTTP Headers archive — as a *header-shape reference*, not a
training corpus. Everything else in its WebApps/Network/Host sections is off-topic (IDS/PCAP/
fraud/malware) or redundant with sources funnypot already tracks.

## 3. Vulhub ground-truth recording pipeline

`docs/LLM-TRAINING-DATA.md` already decided the *shape* of this (warcprox/mitmdump recording
proxy, template-then-dedupe, response-diff eval). What follows makes it concrete: an exact
target list (verified against the live repo, not guessed), a proxy decision tied to the actual
`{messages}` training schema, and the output contract.

### 3.1 Target shortlist (16, verified against `vulhub/vulhub` HEAD)

Vulhub has 154 top-level app directories, each holding one subdirectory per CVE with its own
`docker-compose.yml`. Picked for: (a) stacks that funnypot's own hit logs and the honeypot-
landscape survey already show get scanned in the wild, (b) diversity of `Server`/framework
identity so the responder learns *many* plausible personas, (c) a trigger path that reveals a
real version banner **without** requiring the exploit payload (safer, and often more valuable —
scanners fingerprint via banner far more often than they complete an RCE chain).

| # | Target (dir) | Image (pinned tag) | Why it's in the top 16 |
| --- | --- | --- | --- |
| 1 | `httpd/CVE-2021-41773` | apache httpd 2.4.49 | The most-scanned Apache CVE of the decade; trivial path-traversal GET, real Apache error/banner headers |
| 2 | `httpd/CVE-2021-42013` | apache httpd 2.4.50 | Same family, patched-then-rebroken — gives a second real Apache version banner for free |
| 3 | `php/CVE-2019-11043` | php-fpm + nginx | The nginx+PHP-FPM combo is funnypot's own likely stack; real nginx headers fronting real PHP errors |
| 4 | `thinkphp/5.0.23-rce` | ThinkPHP 5.0.23 | Extremely high real-world scan volume (Chinese botnet staple); distinctive `X-Powered-By: PHP` + framework error page shape |
| 5 | `struts2/s2-045` | Struts2 (Equifax CVE) | Still actively probed years later; classic `Content-Type` OGNL-injection trigger path |
| 6 | `spring/CVE-2022-22965` | Spring4Shell | Massive 2022 scan wave, still probed; real Spring Boot Whitelabel error page |
| 7 | `spring/CVE-2022-22947` | Spring Cloud Gateway | Different Spring stack persona (Actuator/Gateway banners) from #6 |
| 8 | `log4j/CVE-2021-44228` | Log4Shell host app | The single highest-volume scanned CVE ever; captures the JNDI-probe request shape against several plausible host apps |
| 9 | `weblogic/CVE-2020-14882` | Oracle WebLogic 12.2.1.3 | Heavily botnet-scanned via `/console`; unmistakable WebLogic banner/login chrome no other target has |
| 10 | `drupal/CVE-2018-7600` | Drupal (Drupalgeddon2) | Still scanned; real Drupal error/maintenance pages, GPL CMS persona |
| 11 | `gitlab/CVE-2021-22205` | GitLab CE/EE 13.10.1 | Distinct GitLab-branded 401/404 chrome; still shows up in scan logs |
| 12 | `confluence/CVE-2022-26134` | Confluence 7.13.6 | High scan volume since 2022 (OGNL RCE via URL path); Atlassian-branded chrome |
| 13 | `jenkins/CVE-2024-23897` | Jenkins | Recent + still relevant; real Jenkins CLI/console banner |
| 14 | `tomcat/CVE-2020-1938` | Tomcat (Ghostcat) | `/manager/html` is one of the most-probed paths on the internet; real Tomcat 401/403 chrome |
| 15 | `solr/CVE-2019-17558` | Apache Solr | `/solr/admin/` probes are constant background noise; distinctive Solr admin JSON/HTML shape |
| 16 | `phpmyadmin/CVE-2018-12613` | phpMyAdmin | Near-universal scanner target; matches the phpMyAdmin stock container already planned in `LLM-TRAINING-DATA.md` |

Two more worth a mention but left out of the core 16: **`shiro/CVE-2016-4437`** (the
Shiro-550 `rememberMe` cookie deserialization — extremely common in scan logs via a distinctive
`Cookie:` header, cheap to add as #17) and **`fastjson/1.2.47-rce`** (near-ubiquitous in
JSON-API probe traffic, #18). Add them if time allows; they were cut only to keep the initial
list to a clean "one build cycle" size.

**Explicitly not included:** WordPress — vulhub has **no `wordpress/` directory at all**
(confirmed against the live listing); WordPress-core ground truth still has to come from the
stock `wordpress`+`mysql` container `LLM-TRAINING-DATA.md` already lists, not Vulhub. Also
excluded: anything whose CVE lives on a non-HTTP protocol (ActiveMQ's `CVE-2023-46604` is
OpenWire on 61616, not HTTP; Redis unauth is the Redis wire protocol) — out of scope for the
*HTTP* responder, though worth a later pass if funnypot's TCP engine wants protocol-specific
ground truth too.

### 3.2 Proxy tooling — decision

`LLM-TRAINING-DATA.md` names both warcprox and mitmdump; here's the concrete pick. Given the
deliverable is directly the `{messages}` JSONL the LoRA step consumes (see 3.4), **use
`mitmdump` with a small scripted addon that writes JSONL directly** rather than
WARC-then-convert:

- All Vulhub containers speak plain HTTP (no TLS), so mitmproxy's regular proxy mode needs no
  MITM CA — point every driver's `HTTP_PROXY`/`--proxy` at `mitmdump`, zero cert hassle.
- `mitmdump -s record_addon.py -p 8080`, addon implements `response(flow)`: pulls
  method/path/query/headers/body from `flow.request` and status/headers/body from
  `flow.response` (already paired — no join step, unlike WARC), tags the record with the
  container/CVE it came from (env var set per docker-compose run), appends one JSON line.
- Keep warcprox as the fallback only if raw-packet fidelity is ever needed (e.g. to also compute
  TLS/TCP-level features later) — not needed for this pass.

### 3.3 Request corpus (drivers, all pointed through the proxy)

1. **Banner-only crawl** — one GET to each target's documented trigger path from its own vulhub
   README (`/console` for WebLogic, `/manager/html` for Tomcat, `/solr/admin/cores` for Solr…)
   *without* firing the exploit payload — captures the real version banner cheaply and safely.
2. **SecLists** `Discovery/Web-Content/raft-medium-words.txt` (+ CMS-specific lists) via
   `feroxbuster --proxy http://127.0.0.1:8080` per target — this is the highest-value driver:
   it's the *unknown-path 404 corpus* for each real stack, which is exactly funnypot's own
   use case (LLM answers unknown paths).
3. **nuclei**, `-proxy http://127.0.0.1:8080`, restricted to templates tagged for each target's
   CVE — captures the actual scanner probe shape *and* (if allowed to complete) the real
   exploit-trigger response, on an isolated, disposable, network-egress-blocked container only.
4. **CSIC 2010 replay** — a small Python script re-issuing the raw CSIC request lines (already
   tracked in `LLM-TRAINING-DATA.md`) against whichever container is currently up. Turns the
   big request-only academic set into request→response pairs on a *different* real stack than
   the one it was collected against — valuable as input-shape diversity even though the
   response won't match the original CSIC target app.
5. **funnypot's own production hit logs** (highest priority — replay the actually-observed path
   distribution first, so the recorded corpus matches funnypot's real traffic, not just a
   generic wordlist).

### 3.4 Output format — two files per target run

**`ground-truth.jsonl`** (the rich record — eval oracle + future header-model training +
header-realism lint): one line per captured exchange —
```json
{"method":"GET","path":"/manager/html","query":"","req_headers":{...},"status":401,
 "resp_headers":[["Server","Apache-Coyote/1.1"],["WWW-Authenticate","Basic realm=\"Tomcat Manager\""]],
 "resp_body":"<html>...", "source_container":"tomcat/CVE-2020-1938","captured_at":"..."}
```
Header order and casing preserved (ordering is itself part of the fingerprint,
per `LLM-TRAINING-DATA.md`); volatile fields (`Date`, random `ETag`/session ids, CSRF nonces)
templated to placeholders before dedup.

**`messages.jsonl`** (the LoRA-ready slice, one line per deduped example) — shaped to drop
straight into `mlx_lm.lora`'s chat-format training, matching the *exact* prompt contract
`src/App/Llm/LlmPromptBuilder.php` already builds at request time (system instruction with the
stack name substituted, one-shot exemplar structure implied, real method/path as the user turn,
the captured — templated, deduped — body as the assistant turn):
```json
{"messages": [
  {"role": "system", "content": "You generate a short, plausible fake web page for the HTTP request below... The server runs \"Apache Tomcat/9.0\"; keep the page consistent with that stack. ..."},
  {"role": "user", "content": "Method: GET\nPath: /manager/html"},
  {"role": "assistant", "content": "<html>...cleaned real Tomcat 401 body...</html>"}
]}
```
Only method+path→body is in scope for *this* file because that's all `LlmPromptBuilder` sends
the model today (status/headers are computed deterministically elsewhere per the existing docs)
— the richer `ground-truth.jsonl` is what carries status/header data forward for when/if a
header-generation pass gets built.

### 3.5 Safety / isolation

- Docker network `internal: true` (no egress) for every target — a genuinely-triggered RCE
  payload still can't beacon out.
- One target up at a time (`docker-compose up -d` → drive → `docker-compose down -v`) — most
  vulhub compose files claim fixed host ports, and disposability matters more than parallelism
  here.
- Pin image tags (already vulhub's convention, e.g. `vulhub/weblogic:12.2.1.3-2018`) so captures
  are reproducible.
- Never point any of this at a real/production instance of these products — vulhub images only.

### 3.6 Licensing — what the captured responses actually are

Vulhub's own compose/build files are MIT. The **software running inside** varies a lot, and
that's what governs the captured HTML:
- **Permissive/copyleft OSS** (httpd, php, nginx, ThinkPHP, Struts2, Spring, Drupal, Tomcat,
  Solr, phpMyAdmin, Log4j host apps): default/error pages are low-creativity functional text;
  internal-only training on them is low-risk. Don't republish vendor-branded static assets
  (logos, CSS) verbatim if the corpus is ever shared externally.
- **Proprietary/commercial, vulhub-repackaged** (`vulhub/weblogic:12.2.1.3-2018` bakes Oracle's
  binaries into a public Docker Hub image; `vulhub/confluence:7.13.6` and `vulhub/gitlab:*`
  likewise bundle Atlassian/GitLab EE binaries under vulhub's own account) — this already sits
  in a legal grey zone *vulhub* accepts, not one this project should extend. Treat captures from
  these three as **internal-only, never redistributed** — no shipping the corpus, no publishing
  example bodies that carry Oracle/Atlassian/GitLab copyright or trademark chrome, even in a blog
  post. This matches the existing guidance in `LLM-TRAINING-DATA.md` ("mind redistribution
  licenses... internal training on OSS default pages is fine") but is stricter for these three
  specifically because the *image itself*, not just the app, is a redistribution risk.
- Fine either way: training the local 0.5B model on this data and keeping the model + the raw
  corpus internal to funnypot's own infra.

## Bottom line

The two index repos added exactly one new artifact worth grabbing (500K HTTP Headers, as a
header-shape reference, not training text) and reconfirmed one already-tracked one (CSIC 2010).
Everything else filtered out as off-topic, redundant, or already surveyed. The real payoff of
this research pass is turning `LLM-TRAINING-DATA.md`'s one-paragraph Vulhub sketch into a
verified 16-target list + a proxy decision that lands directly in the `{messages}` schema
`LlmPromptBuilder` already expects — see the top-level summary for the effort/payoff call.
