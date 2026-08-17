# funnypot — research backlog (techniques from other honeypots)

_Synthesized from a 6-theme survey of the awesome-honeypots landscape (Glastopf, Snare/Tanner, galah, honeydet/potsnitch, CanaryTokens, endlessh/HellPot, T-Pot/hpfeeds, and more). Core invariant preserved: every served response must still satisfy the scanner matcher; never execute attacker input._

# FUNNYPOT — Prioritized Feature Backlog

Synthesized from all 6 theme reports, deduplicated. Core invariant preserved throughout: **every served response must still satisfy the scanner's matcher; nothing may execute attacker input or break the matcher-satisfaction guarantee.** "Reflect, never execute" is the recurring safety line — adopt other honeypots' response *coherence*, never their code-execution (TANNER PHPox, Glastopf sandbox, shockpot active-fetch all run attacker input; funnypot must not).

---

## 1. Ranked master table

| # | Feature/technique | Source project(s) | What it adds to funnypot | Already? | Effort | Value | Risk / notes |
|---|---|---|---|---|---|---|---|
| 1 | Standardized ECS-named flat-JSON event schema | qeeqbox, T-Pot | Stable field vocab (`source.ip`, `url.path`, `http.request.method`, `user_agent.original`, `event.action` + `matched_template`, `cve`, `persona`, `severity`, `mode`, `session_id`, `generationSource`) every SIEM parses | Partial (ad-hoc JSON-line) | S | high | Foundational; formalize on the Observer seam. Unlocks most of theme (e) |
| 2 | POST body + payload-header capture | bwpot, StrutsHoneypot | Record request_body, exploit-bearing headers, lengths | No | S | high | Prereq for cred-harvest, correlation, YARA. Honor existing body-size cap; StrutsHoneypot's `multipart→mmultipart` mangle-trick to avoid PHP parsing the exploit |
| 3 | Response-timing jitter + latency modeling | potsnitch | Realistic per-response delay/jitter, auth-fail ≥50ms, heavier paths slower; never uniform <5ms | No (instant+uniform = clean tell) | S–M | high | Kills an entire detector class cheaply. On PHP-FPM a delay pins a worker — cap max delay + concurrency (see #22) |
| 4 | Per-source 200-density cap; unmatched paths 404 w/ varied bodies | potsnitch | One prober must not pull an implausible number of "vulnerable" 200s across unrelated templates | Partial (suspicion gate, root guard) | M | high | The #1 structural tell scanner authors reach for first |
| 5 | Content-hash salting of cosmetic bytes | potsnitch (SHA256) | Salt timestamps/request-ids/whitespace/nonces so deterministic bodies don't hash to a shared global constant once public | Partial | S | high | Salt only non-load-bearing bytes — keep the matcher-satisfying bytes stable |
| 6 | Per-hit unique rendering of secret-shaped fields | flux | Per-hit entropy in secret-shaped fields stops fleet-wide fingerprinting across sensors, keeping structure deterministic | Partial/opposite | S | high | Resolves the real determinism-vs-multi-sensor tension |
| 7 | Header/version fidelity per persona (CVE-window-correct) | shockpot, galah, flux, beelzebub, potsnitch | Plausible `Server`/`X-Powered-By`, product-consistent header *set + ordering*, version strings inside CVE disclosure windows | Partial | S–M | high | Never leak `python`/`twisted`/PHP/Laravel |
| 8 | Malformed-request handling per persona | kippo_detect, honeydet | Odd methods, `HTTP/1337`, oversized/chunked/null-byte inputs handled as the claimed product would — never surface host-framework error | Unknown | M | high | The Kippo-`168430090` failure mode; else the PHP/Laravel host becomes the fingerprint |
| 9 | "Too-easy exploitation" gating | potsnitch (cve/http) | Model real product block/deny + disabled endpoints; traversal a real product blocks must 403/404, not 200+fake-file | Partial | M | high | The inert-fake-file emulators (git-config, htpasswd, sql-dump, /etc/passwd) unconditionally 200 — exactly what the cve/traversal check flags |
| 10 | Fake-login credential harvesting | tomcat-honeypot, flux, innerwarden | Capture creds POSTed to wp-login/htpasswd emulators (log, always "wrong") | Partial (serves page, no harvest) | S–M | high | **Reject garbage — accept-all is itself a tell** (potsnitch). Add auth-timing delay |
| 11 | Attack-class reflective emulators (SQLi fake-leak, XSS reflect, cmd-exec fake output, CRLF, XXE) | TANNER, Glastopf, Lophiid | For payload-bearing probes, reflect payload into a coherent body where matchers key on echoed input | Partial (11 path-keyed emulators) | M–L | high | Highest-leverage complement to inversion. **Reflect only, never execute** |
| 12 | AWS-key canary via Thinkst-minted IAM key | Canarytokens | `.aws`/`.env` emulator serves a real canary key; fires (CloudTrail-backed) when *used* against AWS API | No | S | high | Cheapest high-value win — paste a minted key; detection off-host, no infra on funnypot's side |
| 13 | Canary/DNS+HTTP tripwire primitive in cred emulators | Canarytokens, flux/Tracebit, honeyku, honeylambda | Per-response unique subdomain/URL in emulator output (git remote, wp-config DB host, web-bug pixel) fires on later resolve/GET — even from egress-blocked nets | No/Partial | M | high | Second, higher-confidence alert when they *use* what they stole. Toggle; trades some inert-fake ethos — never reuse a vendor's default domains/IPs (canarytokendetector) |
| 14 | Edge ban recipe: fail2ban filter + nftables/ipset, severity-tiered TTL | nginx-honeypot | Convert verdicts to cheap in-kernel IP drops (config 1h / CMS 24h / RCE 7d); cuts load + log noise | Partial (Observer, no recipe) | M | high | Ship alongside Docker demo; trusted-bypass ↔ `trusted-ips.conf` |
| 15 | Server-side behavioral scoring | Krawl, FCaptcha | No-JS signals (method mix, robots violation, timing CoV, multi-UA/IP, attack-URL patterns) sharpen suspicion gate; fills session-correlation gap | Partial | M | high | Exactly the signals a scanner *does* emit |
| 16 | Matcher-revalidation guardrail on any dynamic output | funnypot-native (enabled by galah pattern) | Serve a generated/reflected body only if it still satisfies the template matcher; else deterministic fallback | No | S–M | high | funnypot's unique edge: it owns the matcher, so it can *verify* output and defeat hallucinated tells. Precondition for #17/#19 |
| 17 | Offline LLM-as-maintainer loop | flux | LLM authors/tunes emulators & personas from Observer logs; runtime stays deterministic | No | M (process) | high | Captures LLM upside with zero runtime cost/latency/nondeterminism/hallucination |
| 18 | hpfeeds publisher (Observer sink) | hpfeeds, MHN, CHN, T-Pot, HoneyMap | Tiny PHP client publishes events → drop-in interop with the whole honeynet ecosystem | No | S–M | med–high | Wire format trivial (`4B len|1B opcode`; sha1(nonce+secret) auth); one integration, many consumers |
| 19 | Opt-in runtime LLM enrichment for "realistic" style on long-tail templates | galah, beelzebub, innerwarden | Full plausible body where inversion emits only a bare matcher-satisfying stub | No | L | med–high | Gate behind existing suspicion/severity chain; cache on template+persona+port; **must pass #16 or fall back**; jailbreak guardrails (beelzebub) |
| 20 | Multi-request session/campaign correlation | TANNER, Lophiid, flux, beelzebub | Stitch a source's stream into a session/campaign; classify actor; multi-step protocol coherence | No | M–L | med–high | Needs a store (funnypot is per-request stateless today); big analytics payoff |
| 21 | Pluggable alert/responder registry (webhook, Slack, syslog, CEF, email, Telegram) | modpot, Lophiid, Canarytokens | Batteries-included alerting off the Observer; modpot's `{honeypot_id,app,ts,ip,event}` maps 1:1 | Partial (hook only) | S–M each | med–high | Copy Canarytokens hygiene: ≤1 alert/IP/min, auto-disable webhook after 5 failures |
| 22 | Concurrency cap + verdict logging (tarpit guardrail) | HellPot, FCaptcha | Bounds self-exhaustion; observability | Partial | S | med (safety) | **Mandatory companion to #3/#23** — without it funnypot DoSes its own FPM pool |
| 23 | Bounded latency slow-response (`latencyMs`) | endlessh, HellPot, Krawl | Ties up scanner worker slot; cheap dwell | Partial (knob exists, unused) | S–M | med | Gate on high-confidence+severity, exempt trusted/root, cap delay + concurrency; prefer fixed pre-response sleep to byte-drip on PHP-FPM |
| 24 | File/WAR/upload capture as inert artifacts | tomcat-honeypot, Lophiid | Accept + store attacker uploads (multipart) for study | No | M | med | Store only, never deploy/execute; size cap + type quarantine |
| 25 | GeoIP / IP-reputation enrichment | Lophiid, honeylambda, MHN, DionaeaFR | Tag events with country/ASN/reputation (MaxMind `.mmdb`, self-contained) | No | S–M | med | Prereq for maps + smarter scoring/ban. Cymon is dead — use GreyNoise/AbuseIPDB/MaxMind |
| 26 | Automatic request/attack tagging | Lophiid | Tag events by template-id/severity/attack-class at log time | Partial | S | med | Mostly a schema formalization of data funnypot already has |
| 27 | Response caching keyed template+persona+port | galah | Bounds LLM cost/latency; restores determinism for repeats | Partial (seeded determinism) | S–M | med (if LLM) | Only needed once an LLM path exists; TTL 0/-1/hours |
| 28 | Token-budget cap + jailbreak guardrails on LLM | galah (DoW), beelzebub | Spend a token only past the gate; cap spend; stop honeypot-LLM self-reveal | No | S–M | med (if LLM) | Reuse existing kill-switch/suspicion/severity chain as the LLM trigger |
| 29 | robots.txt tripwire | HellPot, Krawl | Serve `Disallow`; any hit = high-signal bot tell | No | S | med | Cheap canary; well-behaved clients never trip |
| 30 | Spider trap: fake internal links | Krawl | Seed synth bodies with links to more fake-vuln endpoints → deeper maze + more correlation signal | No | S–M | med | Low self-risk (just more requests to you), no worker-holding |
| 31 | Prometheus metrics | Lophiid, beelzebub | Hits, verdicts, persona mix; hang off existing demo dashboard | No | S | med | Cheap ops observability |
| 32 | Pluggable log sinks/formatters (syslog/CEF/Splunk/JSON/DB) | qeeqbox, MHN/CHN hpfeeds-logger | Same event, multiple emitters behind the Observer | No | M | med | Formatters behind the seam |
| 33 | 1×1 beacon / web-bug response style | honeyku, honeylambda | Tracking-pixel style embeddable in served fake docs (sql-dump, package.json) | No | S | med | Fits per-endpoint emulator + response-style model |
| 34 | Vary error/40x bodies; random error-code injection | potsnitch, honeydet, Krawl | Kill "identical error across probes" tell; flaky-real feel | Partial (3 styles) | S | med | Ensure fall-through isn't one constant string |
| 35 | CIF/STIX indicator export | CHN hpfeeds-cif, MHN | Push attacker IPs/hashes/URLs to CIFv3 or STIX/TAXII | No | M | med | hpfeeds-cif is the reference pattern |
| 36 | Bind served canary to probing scanner/session | DCEPT | Record which persona/seed each token went to → attribution when it later fires | Partial (seed→persona map) | M | med | Reuse the seed→persona mapping as the binding DB |
| 37 | Page cloning / honeypage flattening for baseline index | SNARE, modpot | Clone a real front page into one self-contained HTML so the non-template index looks genuine | No | M | med | Improves the surface a scanner first hits; modpot's flattener is the concrete tool |
| 38 | Aggregate analytics dashboard | Kippo-Graph, DionaeaFR | HTTP stat views: top templates/CVEs, top IPs/UAs, top personas, requests-over-time | No (live-feed only) | M | med | Reads the standardized log |
| 39 | Real-time animated geo attack map | T-Pot, HoneyMap, MHN | Websocket-fed map on demo dashboard | Partial | M–L | med | Depends on #25 (GeoIP); demo-only value |
| 40 | Captured-payload scanning (YARA + VT) | Lophiid | Classify captured bodies/uploads | No | M | med | Depends on #2/#24 landing first |
| 41 | DShield community-feed submission | DShield-docker | POST attacker ip+ts+port to SANS ISC | No | S–M | low–med | DShield is firewall/SSH-oriented; HTTP-probe is a weaker fit. **API format unverified (403)** |
| 42 | Log retention / rotation | T-Pot ILM, qeeqbox | max_bytes/backup_count + retention window on file sink | Partial | S | low | Minor ops nicety |

---

## 2. Grouped by theme (ranked within group by value/effort)

**(a) Believability & anti-detection hardening**
`#3 timing jitter` → `#5 hash-salting` → `#6 per-hit secret uniqueness` → `#7 header/version fidelity` → `#4 200-density cap` → `#8 malformed-request handling` → `#9 too-easy-exploit gating` → `#34 vary error bodies` → `#37 page cloning`.
Note: funnypot's coherent-persona model *already* neutralizes potsnitch's entire framework/anomaly class (mixed-OS, too-many-ports, cross-path incoherence) and trusted-bypass handles scanner self-detection — keep both strict.

**(b) Attacker-interaction capture**
`#2 POST/header capture` → `#10 credential harvest` → `#11 reflective emulators` → `#20 session/campaign correlation` → `#24 upload capture` → `#40 YARA/VT scan`.

**(c) Canary tokens & threat-intel**
`#12 AWS-key canary` → `#18 hpfeeds publisher` → `#13 DNS/HTTP tripwire` → `#33 web-bug pixel` → `#25 GeoIP enrichment` → `#21 alert channels` → `#36 token↔session binding` → `#35 CIF/STIX` → `#41 DShield`.

**(d) Tarpit / anti-bot**
`#14 edge ban recipe` → `#15 behavioral scoring` → `#22 concurrency guardrail` → `#29 robots tripwire` → `#30 spider trap` → `#23 bounded latency`. (Severity-tiered dwell/ban policy reuses the existing severity ceiling, 1:1 onto nuclei severity.)

**(e) Logging / ops / deployment**
`#1 ECS schema` → `#26 attack tagging` → `#31 Prometheus` → `#32 log sinks/formatters` → `#38 analytics dashboard` → `#39 geo map` → `#42 retention`.

**(f) Optional LLM enrichment**
`#16 matcher-revalidation guardrail` → `#17 offline LLM-maintainer loop` → `#27 caching` → `#28 budget+jailbreak guards` → `#19 runtime enrichment layer`.

---

## 3. Top 8 to do next

1. **#1 ECS-named JSON schema + #2 POST/header capture** — one small foundational pair on the Observer seam that every downstream feature (alerting, correlation, threat-intel, harvesting) depends on; cheapest highest-leverage move.
2. **#3 Response-timing jitter** — deterministic instant responses are currently a clean, uniform honeypot tell that kills funnypot in one probe; adding bounded latency+jitter defeats an entire detector class for S–M effort.
3. **#12 AWS-key canary + #13 DNS/HTTP tripwire in the cred emulators** — turns funnypot's already-served fake `.env`/`.aws` payloads into live tripwires, converting "waste triage time now" into a second, higher-confidence alert when the loot is actually used, with near-zero infra via Thinkst.
4. **#14 Edge-ban recipe (fail2ban filter + nftables, severity-tiered TTL)** — funnypot already produces rich probe verdicts; this cheaply converts them into in-kernel IP drops, closing the blocklist-feedback gap while cutting load and log noise.
5. **#5 hash-salting + #6 per-hit secret uniqueness** — once funnypot is public its deterministic bodies get catalogued by content hash and fingerprinted across sensors; salting cosmetic bytes and per-hit-unique secret fields removes that liability while keeping the matcher bytes stable.
6. **#7 Header/version fidelity per persona (CVE-window-correct)** — a cheap, high-value evasion win that makes the banner *confirm* authenticity to the scanner instead of leaking framework tells.
7. **#10 Fake-login credential harvesting (reject garbage, add auth-delay)** — a small extension to emulators funnypot already ships that captures attacker creds, with the built-in guard that accept-all is itself a detection tell.
8. **#16 Matcher-revalidation guardrail + #17 offline LLM-maintainer loop** — the guardrail is funnypot's architecturally unique advantage (it owns the matcher, so it can verify any generated output) and is the safe precondition for all future LLM work; the offline maintainer loop banks the LLM upside now with zero runtime risk.

All eight are high-value, S–M effort, and fit the deterministic template-inversion core — none touches the matcher guarantee or executes attacker input.

---

## 4. Deliberately NOT doing

- **Active second-stage fetch / command execution** (shockpot wget/curl/ping run, TANNER PHPox, Glastopf PHP sandbox) — literally runs attacker-directed input; SSRF/open-proxy/abuse risk and a direct violation of the inert-fake invariant. Adopt their response *coherence* (reflect) never their execution. If ever needed for malware collection, do it out-of-band, sandboxed, opt-in — never inline in the response path.
- **gzip / decompression bombs** — none of the five tarpit projects use one (HellPot explicitly avoids it); only fires if the client auto-inflates, your own CDN/WAF may inflate and blow up instead of the attacker, flips funnypot from passive deception to an active payload with a worse legal story. Do not add.
- **Infinite / endless response body stream** (HellPot, Krawl) — conflicts with funnypot's body-size cap and is a worker-per-connection killer on PHP-FPM (self-DoS). Only viable as opt-in on an async runtime (Swoole/RoadRunner) or pushed to the edge; not core.
- **Ephemeral daily rebuild-to-clean** (bwpot) — needed only when backends are *real* vulnerable apps that can be truly compromised; funnypot serves fakes, so N/A.
- **Breadcrumb-spreading host agent / LSASS injection / registry planting** (Honeybits, DCEPT agent) — a different deployment model (host agent, auditd/go-audit) off-thesis for an HTTP template-inversion library. Adjacent, not a funnypot feature.
- **Non-HTTP network-service emulation & passive auth sniffing** (OpenCanary, DCEPT DC monitor) — funnypot is HTTP template-inversion; out of scope.
- **Full MHN/T-Pot-style central control plane with sensor registration** (MHN, T-Pot hive/sensor, CHN) — funnypot is a library embedded in host apps, so each app already *is* a sensor; "publish to a central collector over hpfeeds/TLS" (#18) captures the multi-sensor value at a fraction of the cost. Build the publisher, not the control plane.
- **PoW timing gate / WebDriver-CDP / mouse-keystroke biometrics** (FCaptcha) — needs a JS runtime and real browser input the scanners funnypot faces don't have. Only the server-visible slice (timing gate, trusted-proxy gating, verdict logging) transfers, and those arrive via #3/#22 anyway.

Note: **tarpit/slow-drip has no clean reference implementation** among the surveyed HTTP honeypots (endlessh is SSH, HellPot needs an event loop) — hence #23 is scoped as a *bounded* delay with a mandatory concurrency guardrail (#22), not an endlessh-style hold, because classic PHP-FPM makes the blast radius your own pool.
