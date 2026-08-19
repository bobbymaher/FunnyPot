# OWASP CoreRuleSet as a funnypot-core detection source — research notes

Evaluates integrating [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset) (CRS) — the
ModSecurity/Coraza generic-attack ruleset — into funnypot-core as a SECOND upstream signal source,
alongside the existing nuclei-templates pipeline. CRS covers attack CLASSES (SQLi, XSS, LFI, RCE,
scanner fingerprints, protocol anomalies) rather than nuclei's per-CVE probes, so it is a coverage
multiplier for generic/opportunistic attackers, not a replacement for anything nuclei does.

**Bottom line up front:** CRS does not fit funnypot-core's nuclei-corpus pipeline (`Compiler.php` /
route-persona-bundle machinery) — it has no response contract to invert. It fits the OTHER, smaller
pipeline already in the repo almost exactly: the hand-authored `templates/attack/*.yaml` +
`TemplateAttackEmulator` runtime-regex layer. Recommended role: **CRS as a generic attack-class
DETECTOR** that widens the match regex behind funnypot's existing hand-authored response archetypes
(sqli/xss/lfi/rce/xxe/ssrf/…), and secondarily as a **category signal for the LLM sidecar's prompt
selection**. This is option (a) from the brief, with (b) as a natural downstream consumer of the same
tags — not a separate design.

---

## (a) How the existing nuclei pipeline works

funnypot-core actually ships **two independent template pipelines**, not one. Understanding both
matters because CRS maps cleanly onto the second, not the first.

### Pipeline 1 — the nuclei corpus (compile-time response inversion)

Nuclei templates are never vendored into the repo; they're pulled from
`projectdiscovery/nuclei-templates` (external, MIT) at build time only.

- **Parser**: `vendor/bobbymaher/funnypot-core/src/Compiler/TemplateLoader.php:22` (`loadFile()`) and
  `:45` (`fromArray()`). Parses nuclei's YAML `http:`/`requests:` block into a `LoadedTemplate`:
  id, severity, tags, product (from `info.metadata.product`), method, paths, matchers,
  `matchers-condition`, `requestCount`, `flow` presence, and an `eligibility` bag (raw/payloads/
  body/fuzzing/unsafe/name/req-condition) used by the eligibility gate. Only the FIRST `http`
  request block is lifted (nuclei's own clustering only looks at one request); raw HTTP requests
  get their request-line lifted into method+path (`parseRawRequest()`, :150).
- **Gate A** (`ClusterableFilter`) inverts nuclei's own `IsClusterable()` check plus excludes
  interactsh/OOB, xpath-only, and variable-path templates — this doubles as the request-eligibility
  filter.
- **Gate B** (`Classifier`) classifies each matcher (status/size/word/regex/dsl/`compare_versions`)
  as invertible or not per `matchers-condition`, and on success builds a `SatisfyPlan`: the actual
  (status, body-words, forbidden-words, size, header-words) that would satisfy that nuclei template.
- **Merge**: `BundlePartitioner` graph-colors compatible `SatisfyPlan`s from the same `(method,
  normalized-path)` group into conflict-free "persona bundles" (one coherent product identity per
  response — see `SPEC.md` §2/§5) — because ONE HTTP response has exactly one status line, "vulnerable
  to everything at once" is physically impossible, so different attacker identities deterministically
  land on different, individually-coherent personas.
- **Orchestration**: `Compiler.php:38` (`compile()`) drives load → Gate A → Gate B → group → partition
  → emit. Output is a single frozen literal PHP array,
  `resources/compiled/nuclei-index.full.php` (+ `manifest.json` + `skipped.json` audit trail), written
  by `ArtifactWriter.php`. **Runtime cost is one hash probe on `"METHOD normalized-path"`; there is
  zero parsing/regex evaluation at request time for this corpus** — the update workflow's own comment
  says it plainly: *"parsing/compiling happens HERE, once. Consumers never parse templates; they just
  `composer update`."*
- **Update automation**: `vendor/bobbymaher/funnypot-core/.github/workflows/update-templates.yml`.
  Weekly cron (Mondays 06:00 UTC) + `workflow_dispatch` with a `tag` override. Resolves the latest
  `nuclei-templates` git tag → shallow-clones it → `bin/funnypot compile /tmp/nuclei-templates/http
  --out=resources/compiled/nuclei-index.full.php` (lines 57-60) → recompiles funnypot's OWN
  attack/route templates and folds new pages back in (`compile-emulators`, `compile-routes`,
  `merge-routes`, lines 62-68) → runs the unit+compiler suite → **runs real nuclei in Docker against
  a `php -S` server backed by the compiled artifact** as the golden acceptance proof (line 73-74,
  `tests/acceptance/run.sh`) → opens a PR with the refreshed artifacts only if everything is green
  (lines 76-95).
- **License provenance**: nuclei-templates is MIT (© 2025 ProjectDiscovery, Inc.); the compiled
  artifact's header comment stamps this (`ArtifactWriter.php:69-70`) and the verbatim notice ships at
  `resources/UPSTREAM-LICENSE.md` (referenced in `SPEC.md:14-15`, `README.md:152-155`).
  funnypot-core itself is `"license": "MIT"` (`composer.json`).

### Pipeline 2 — hand-authored attack/route templates (runtime regex, funnypot's own DSL)

This is the pipeline CRS actually resembles. It is **vendored in the repo** (not pulled from an
upstream at build time — today it's 100% hand-written) at `templates/attack/*.yaml` (31 files: sqli,
xss, lfi×5, cmdi×2, ssti×2, xxe, webshell, open-redirect, shellshock, struts-ognl, confluence-ognl,
spring-actuator, ivanti, fortios, imds, f5-icontrol, citrix-bleed, phpcgi×2, phpunit-rce,
owncloud-graphapi, geoserver, thinkphp) and `templates/route/*.yaml` (known-path decoy pages: `.git/
config`, `.env`, `wp-login`, `phpinfo`, `.npmrc`, `id_rsa`, etc.).

Format (`templates/attack/50-sqli.yaml`, verbatim):
```yaml
id: attack-sqli
severity: high
priority: 50
tags: [attack, sqli]
match:
  - in: request
    regex: '(?:\'\s*or\s*\'?1\'?\s*=\s*\'?1|"\s*or\s*"?1"?\s*=|\bunion\s+(?:all\s+)?select\b|...)'
response:
  headers:
    Content-Type: "text/html; charset=utf-8"
  body: "You have an error in your SQL syntax; ...\n"
expect: ["SQL syntax"]
```
`match` entries are ANDed; `in` is one of `request` (path+query+body, both raw and
`rawurldecode`d — `TemplateAttackEmulator::surface()`, :158-186), `path`, `query`, `body`, `header`,
or `header:Name`. `response.body`/`headers` may use a small CLOSED directive vocabulary
(`DirectiveRenderer.php`): `{{canned.X}}` (fixed fake `/etc/passwd` etc.), `{{fake.NAME:enc:len}}`
(seeded-per-persona fabricated secret), `{{match.N}}` (bounded reflection of a regex capture, only
when the template author sets `capture: true` on that condition), `{{pick:a,b,c}}`, `{{canary.KEY}}`.

- **Compiler**: `vendor/bobbymaher/funnypot-core/src/Compiler/EmulatorCompiler.php`. Rule ORDER is
  first-match-wins, controlled by an explicit `priority:` field (lower first, then `id`) — the `NN-`
  filename prefix is purely cosmetic (`EmulatorCompiler.php:16-17`, sort at `:51-53`). Build-time lints
  make "compiles but silently wrong" a hard failure: duplicate ids reject (`:43-46`), every `{{...}}`
  must be a known directive prefix (`assertKnownDirectives`, :140-160 — an unknown directive is almost
  always a typo that would otherwise render as dead literal text), static header text must never
  contain CR/LF/NUL (`assertStaticHeaderClean`, :163-169), and an optional `expect:` marker list is
  rendered with EMPTY captures and asserted present (`assertMarkers`, :179-194) so a directive typo or
  a marker that only exists via reflection fails the build.
- **CLI**: `bin/funnypot compile-emulators` (funnypot-core `bin/funnypot:32-55`) reads
  `templates/attack/*.yaml`, writes the frozen array to `resources/compiled/funnypot-attack.php`.
- **Runtime**: `TemplateAttackEmulator.php`. `emulate()` (:67-110) walks rules in compiled order,
  first whose ALL `match` conditions hold (`match()`, :123-156) wins; its response is rendered through
  `DirectiveRenderer` with that rule's captures + the request's persona seed, then a C8 CRLF/NUL check
  runs on every rendered header before the response is returned (:89-95). Attacker-controlled match
  surfaces are capped at 32KB before regex evaluation to bound catastrophic backtracking
  (`MAX_SURFACE`, :113).
- **Catalog auto-registration**: `src/Compiler/CatalogCompiler.php` (main funnypot repo, not core)
  scans `templates/attack/*.yaml` + `templates/route/*.yaml` + `templates/protocol/*.yaml` and derives
  the operator-facing on/off catalog (`EmulationCatalog`) — category is picked from a fixed,
  ordered tag list, `CATEGORY_TAGS` (`CatalogCompiler.php:22-25`):
  `rce, deserialization, ssti, sqli, xxe, ssrf, lfi, traversal, redirect, xss, injection,
  disclosure, auth, default-login, exposure`. **This is materially the same taxonomy CRS uses for its
  own `attack-*` tags** — the strongest existing-code signal that CRS output belongs on this axis.
  Adding a template and recompiling auto-registers it; the catalog is never hand-maintained.

---

## (b) CRS structure + license

Repo: `github.com/coreruleset/coreruleset`, an OWASP flagship project. **License confirmed
Apache-2.0** (fetched `LICENSE` directly: "Apache License, Version 2.0"; README badge + footer confirm
— © 2006-2020 Trustwave and contributors, © 2021-2026 CRS project). This is a **different license
family than nuclei-templates' MIT** — Apache-2.0 requires preserving the copyright/license notice and
stating changes, and carries an explicit patent grant. funnypot's existing per-upstream
`resources/UPSTREAM-LICENSE.md` + manifest tag/SHA-stamping pattern generalizes, but needs a SEPARATE
file (e.g. `resources/UPSTREAM-LICENSE-CRS.md`) — don't fold Apache-2.0 text into the existing MIT
notice. Latest release tag at research time: `v4.29.0` (dev branch reports `4.30.0-dev` in file
headers).

### Layout
`rules/*.conf` — one file per numbered category:
`REQUEST-901-INITIALIZATION`, `REQUEST-905-COMMON-EXCEPTIONS`, `REQUEST-911-METHOD-ENFORCEMENT`,
`REQUEST-913-SCANNER-DETECTION`, `REQUEST-920/921/922-PROTOCOL-*`,
`REQUEST-930-LFI`, `931-RFI`, `932-RCE`, `933-PHP`, `934-GENERIC`, `941-XSS`, `942-SQLI`,
`943-SESSION-FIXATION`, `944-JAVA`, `949-BLOCKING-EVALUATION`,
`RESPONSE-950..959-DATA-LEAKAGES/*` (response-side rules — irrelevant to funnypot, which never sees
the real backend's response). Plus `rules/*.data` — plain curated phrase/dictionary files (one entry
per line, `#`-comments), e.g. `scanners-user-agents.data` (241 known-scanner UA substrings, hand-
curated — "attempts to machine-generate a larger list leads to a lot of false positives"),
`sql-errors.data`, `php-errors.data`, `web-shells-php.data`, `lfi-os-files.data`. **These `.data` files
are a second useful raw asset independent of the rule regexes** — e.g. `sql-errors.data` is a curated
corpus of real DB error strings; inverted from CRS's detection use, it's directly reusable as flavor
text for funnypot's own fake-error response bodies.

### Rule syntax
`SecRule VARIABLE(S) "OPERATOR" "ACTIONS"`. Real example (942100, from
`rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf`):
```
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*|XML://@* "@detectSQLi" \
    "id:942100,phase:2,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
     msg:'SQL Injection Attack Detected via libinjection',\
     tag:'attack-sqli',tag:'paranoia-level/1',tag:'OWASP_CRS/ATTACK-SQLI',\
     severity:'CRITICAL',\
     setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
A pure-regex variant (942140, DB-name detection):
```
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)\b(?:d(?:atabas|b_nam)e...\b" \
    "id:942140,phase:2,block,capture,t:none,t:urlDecodeUni,\
     msg:'SQL Injection Attack: Common DB Names Detected', tag:'attack-sqli', severity:'CRITICAL', ..."
```

- **Variables** (`ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_HEADERS:Name`,
  `REQUEST_FILENAME`, `REQUEST_BODY`, `XML:/*`) map fairly directly onto funnypot's `match[].in`
  surfaces (`query`/`body`/`header:Name`/`path`/`request`).
- **Operators** — the critical split for portability:
  - `@rx <regex>` — plain PCRE-compatible regex, **directly portable** to funnypot's `regex:`.
  - `@pmFromFile <file>.data` — phrase match against a dictionary, portable as an alternation of
    escaped literals (or a `contains` chain).
  - `@detectSQLi` / `@detectXSS` / `@detectXSSlibinjection` — calls into the **libinjection C
    library**, not a regex at all. These are exactly CRS's highest-confidence, lowest-false-positive
    rules (942100 for SQLi, 941100 for XSS — both PL1, both `severity:'CRITICAL'`) and **cannot be
    mechanically inverted into a PCRE pattern**. This is the single biggest technical gap versus
    nuclei, where 100% of matchers are declarative. Options: drop (record in a skipped-audit like
    nuclei's `skipped.json`), or hand-port a small approximation of libinjection's simplest folding
    heuristics as an explicit, human-reviewed regex — never silently.
- **Actions**: `id` (CRS's own numbering — analog to nuclei's `id:`), `phase` (1 = headers, 2 = body),
  `tag:'attack-sqli'` (→ funnypot `tags:`, and via `CATEGORY_TAGS` the catalog category — free),
  `severity:'CRITICAL'|'ERROR'|'WARNING'|'NOTICE'` (→ funnypot severity, needs an explicit mapping;
  funnypot's default `severityCeiling` is `high`, so CRITICAL-tagged CRS rules should compile to
  `high`, not `critical`, unless the operator raises the ceiling), `msg:`/`logdata:` (CRS's own audit
  logging — discard, never copy into a response body), and `setvar:'tx.inbound_anomaly_score_pl1=+
  %{tx.critical_anomaly_score}'`. **Most CRS rules don't block on their own** — default "anomaly
  scoring" mode accumulates a per-request score across every matching rule; a separate rule in
  `REQUEST-949-BLOCKING-EVALUATION.conf` compares the total against a threshold (`crs-setup.conf.
  example`: default `inbound_anomaly_score_threshold=5`) and only THEN blocks. This is a materially
  different execution model from nuclei's independent-per-template matcher, and from funnypot's own
  first-match-wins attack emulator — CRS's score-accumulation semantics don't need to be replicated;
  a single fired rule is still a valid, meaningful "this looks like class X" detection signal on its
  own for funnypot's purposes (a honeypot wants ANY plausible signal, not calibrated blocking).
- **Paranoia levels (PL1-PL4)**: each `.conf` file repeats its full rule set once per level, gated by
  `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt N" ...,skipAfter:END-<FILE>` blocks (see
  `REQUEST-913-SCANNER-DETECTION.conf`). PL1 is CRS's own production-safe default; PL2-4 are
  progressively more aggressive and explicitly documented by CRS as more false-positive-prone
  (opt-in for WAF operators). A CRS parser reads `tag:'paranoia-level/N'` to bucket rules — **PL1-only
  should be the default import**, mirroring funnypot's own conservative-default posture
  (`mode=detect` + `gate=>false` install-inert default, `severityCeiling=high` — see `SPEC.md` §4);
  PL2-4 behind an explicit opt-in flag.
- **`chain`**: expresses multi-condition AND across separate `SecRule` lines — portable, maps onto
  funnypot's multiple (already-ANDed) `match:` entries; just needs multi-line grouping during parse.
- **Regex provenance**: many `.conf` regexes are themselves GENERATED from a separate
  `regex-assembly/*.ra` source format by a Go tool (`crs-toolchain`), not hand-written in the `.conf`.
  A funnypot CRS parser should consume the generated `.conf` regex directly — exactly as it already
  treats nuclei's authored YAML (not nuclei's Go source) as the interchange format — no dependency on
  `crs-toolchain`/Go needed.

---

## (c)/(d) Recommended integration design

### Why CRS maps to Pipeline 2, not Pipeline 1

Nuclei templates carry BOTH a detection surface (method+path+matchers) AND enough structure to
computationally derive a full byte-exact RESPONSE that satisfies that specific scanner's matcher —
the entire value of `Compiler.php`'s inversion engine (§3 of `SPEC.md`: IN/OUT classifier, per-matcher
satisfaction, regex-witness generation, persona-bundle partitioning) is "make nuclei itself believe
this fake response is the real vulnerable app". CRS rules have **no such structure to invert**: a
rule says "if `ARGS` looks like `UNION SELECT`, add N to the anomaly score" — no `matchers` block, no
expected response shape, and most rules aren't even path-scoped (they apply to `ARGS`/`REQUEST_BODY`
on any URL). There is no "real CRS" analog to "run real nuclei and prove it's satisfied" (§6) —
CRS is a request classifier, not a response verifier, so forcing it through the nuclei pipeline means
inventing responses with no upstream ground truth to certify against.

CRS rules ARE structurally identical to `templates/attack/*.yaml`: (surface, regex) conditions ANDed
together, tagged by attack CLASS (not CVE/product), matched against an arbitrary request, with **no
canonical response in the source at all** — `templates/attack/50-sqli.yaml`'s hand-authored fake-MySQL-
error body has no nuclei/CRS counterpart to derive it from; a human (or funnypot's LLM sidecar) always
authors it. CRS only ever supplies the DETECTION side, and dramatically broadens it.

This is exactly option (a) from the brief — **CRS as a generic attack-class detector feeding the
decision** — and it's well-precedented by code that already exists: `CatalogCompiler`'s
`CATEGORY_TAGS` is already CRS's `attack-*` taxonomy in miniature. Option (b) is not an alternative
design, it's a direct beneficiary of (a): funnypot already has a probe-gated LLM sidecar
(`funnypot-llm`, per prior work) that renders fake HTML for unknown paths; feeding it "this request
scored `attack-sqli` + `attack-scanner-detection`" (CRS category tags) as a prompt-selection signal is
free once CRS rules are tagged the funnypot way — no separate design needed.

### Data model

- New source directory, e.g. `templates/attack-crs/*.yaml` — same schema `EmulatorCompiler` already
  accepts (`id`, `severity`, `tags`, `priority`, `match`, `response`, `expect`), so **zero runtime
  code changes**: `TemplateAttackEmulator` and `DirectiveRenderer` need not know CRS exists. Only a
  new build-time generator is needed (parallel to `TemplateLoader`/`EmulatorCompiler`, not a
  replacement).
- **Aggregate, don't emit 1:1.** CRS has hundreds of PL1 rules across a dozen attack classes; emitting
  one funnypot template per CRS rule id would (a) blow past `TemplateAttackEmulator`'s linear
  first-match-wins scan, (b) require inventing hundreds of distinct responses funnypot has no basis to
  author, and (c) mostly restate the same small set of classes funnypot already has one response
  archetype for. Instead, **aggregate every portable PL1 CRS rule of a given `attack-*` tag into a
  single generic `regex:` alternation feeding the SAME existing response archetype** — e.g. CRS's
  ~15-20 portable PL1 `attack-sqli` regex/pmFromFile rules become one broadened alternation inside (or
  alongside) `attack-sqli`'s existing `50-sqli.yaml`, multiplying detection recall against funnypot's
  current ~6 hand-picked patterns while keeping exactly one response per class, as today.
- **Portability filter** (mirrors nuclei's Gate A/B skip audit): keep `@rx` and `@pmFromFile` rules;
  reject (log to a `skipped-crs.json` sidecar, same shape as nuclei's `skipped.json`) `@detectSQLi`/
  `@detectXSS`/other opaque-library operators, pure anomaly-scoring bookkeeping rules (no `block`/
  detection value on their own), and PL2-4 rules unless a future opt-in flag is set.
- **Severity mapping**: CRS `CRITICAL`→funnypot `high` (respects `severityCeiling` default),
  `ERROR`→`medium`, `WARNING`/`NOTICE`→`low` — explicit table, not 1:1 string reuse.
- **Tags**: carry CRS's `attack-*` tag straight through (already funnypot's vocabulary via
  `CATEGORY_TAGS`); add a `crs` + `crs-pl1` provenance tag so the catalog/on-off UI can group and the
  operator can distinguish "funnypot's own sqli rule" from "CRS-broadened sqli coverage" if ever
  needed for debugging false positives.
- **`.data` dictionaries as a second asset**: independent of the rule regexes, mine `sql-errors.data`/
  `php-errors.data`/`web-shells-php.data`/`lfi-os-files.data` as raw material for response-body flavor
  text (they're curated real error strings) — a content asset, not a detection asset; flag as a
  separate, smaller follow-up rather than bundling into the parser itself.

---

## (e) Fingerprint-safety gate

The codebase already states the exact policy this needs, in `templates/attack/65-xss-reflect.yaml`'s
comment: *"the one rule that echoes attacker bytes — the bounded exception to 'never reflect input'
... ONLY the matched payload ({{match.0}}) is reflected, into a fixed page; nothing else from the
request, nothing stored."* CRS import must uphold that as the DEFAULT, not the exception:

1. **Never copy CRS's own text into a response.** `msg:`, `logdata:`, and any block-page text are
   CRS's own audit/detection vocabulary — an attacker who has fingerprinted ModSecurity+CRS before
   would recognize CRS's canned phrasing (e.g. "SQL Injection Attack Detected via libinjection") or a
   raw rule id (`942100`) instantly. The CRS-import generator must draw response bodies ONLY from
   funnypot's own existing hand-authored archetypes (already in-persona: fake MySQL/Apache/etc. error
   text) — never synthesize response text from a CRS rule's `msg:`/`logdata:` field. Add a build-time
   lint (`assertNoCrsLeakage()`, parallel to `EmulatorCompiler`'s existing `assertStaticHeaderClean()`)
   that scans generated `response.body`/`headers` for signature substrings (`OWASP_CRS`,
   `ModSecurity`, `Coraza`, bare 6-digit CRS rule ids, `libinjection`) and fails the build if found —
   same "compiles but silently wrong = build failure" discipline the existing compiler already
   enforces for directive typos and CRLF injection.
2. **Reflection stays opt-in, per-template, human-reviewed.** The CRS-import codegen must never emit
   `capture: true` or `{{match.*}}` in generated templates by default — that's the same bounded
   exception the hand-authored XSS template deliberately, consciously opted into. If a CRS-sourced
   rule is ever worth reflecting (e.g. broadening the existing XSS reflect rule with more CRS XSS
   variants), a human promotes that specific case, same as any other template edit — never a parser
   default.
3. **Never leak the DETECTOR, only the attack class.** The whole point of "extract intent, not the
   regex" from the task brief is already satisfied structurally: the compiled `funnypot-attack.php`
   array is server-side only (never sent to the client), so the CRS regex itself isn't literally
   echoed at request time regardless of source. The actual leak surface is narrower and is fully
   covered by point 1 — response CONTENT, not the match mechanism.
4. **Correctness caveat, not a safety gap, but worth flagging alongside this:** CRS's rules assume its
   own transformation pipeline ran first (`t:utf8toUnicode`, `t:urlDecodeUni`, `t:htmlEntityDecode`,
   `t:jsDecode`, `t:cssDecode`, `t:removeNulls` — see 941100's `t:` chain). `TemplateAttackEmulator::
   surface()` (`TemplateAttackEmulator.php:158-186`) only does raw + one `rawurldecode()` pass. A CRS-
   derived regex imported verbatim will have MORE false negatives on double-encoded/HTML-entity/JS-
   escaped obfuscation than CRS itself does, since funnypot's surface lacks CRS's decode chain. Not a
   fingerprint risk, but should be documented as a known gap in the same spirit as `SPEC.md`'s
   "known residual tells" section (§5) — honest about the limitation rather than silent.

---

## (f) Auto-update GitHub Action sketch

Mirrors `update-templates.yml` closely; new workflow (e.g.
`vendor/bobbymaher/funnypot-core/.github/workflows/update-crs.yml`), staggered cron so PRs don't
collide (e.g. Wednesdays 06:00 UTC vs nuclei's Mondays):

```yaml
name: update-crs
on:
  schedule:
    - cron: '0 6 * * 3'
  workflow_dispatch:
    inputs:
      tag: { description: 'coreruleset tag (blank = latest release)', required: false, default: '' }
permissions:
  contents: write
  pull-requests: write
jobs:
  recompile:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with: { php-version: '8.3', extensions: mbstring, ctype, coverage: none }
      - run: composer install --no-interaction --prefer-dist --no-progress

      - name: Resolve coreruleset tag
        id: crs
        run: |
          TAG="${{ github.event.inputs.tag }}"
          if [ -z "$TAG" ]; then
            TAG=$(git ls-remote --tags --sort=-v:refname \
              https://github.com/coreruleset/coreruleset.git \
              | grep -oE 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 | sed 's#refs/tags/##')
          fi
          echo "tag=$TAG" >> "$GITHUB_OUTPUT"

      - name: Fetch coreruleset
        run: git clone --depth 1 --branch "${{ steps.crs.outputs.tag }}" \
               https://github.com/coreruleset/coreruleset.git /tmp/coreruleset

      - name: Parse + aggregate CRS rules -> funnypot attack-crs templates
        run: php bin/funnypot compile-crs /tmp/coreruleset/rules \
               --out=templates/attack-crs/ --pl=1
        # New command: parses .conf (@rx/@pmFromFile only, PL1 by default),
        # aggregates by attack-* tag into readable YAML (same shape as templates/attack/*.yaml,
        # human-diffable in the PR), runs assertNoCrsLeakage + existing directive/CRLF lints,
        # writes skipped-crs.json for anything dropped (opaque operators, PL2-4, anomaly-only rules).

      - name: Recompile emulator index (now includes CRS-sourced templates)
        run: php bin/funnypot compile-emulators

      - name: Unit + compiler tests
        run: vendor/bin/phpunit

      - name: CRS fidelity check (no live WAF needed)
        run: php bin/funnypot verify-crs-fixtures /tmp/coreruleset/tests/regression/tests \
               templates/attack-crs/
        # CRS ships its OWN regression corpus as tests/regression/tests/<FILE>/<rule-id>.yaml —
        # literal attack payloads with expect_ids (e.g. 942100.yaml: data:"var=1234 OR 1=1" ->
        # expect_ids:[942100]). Replay every fixture payload for a rule id we imported against the
        # generated funnypot regex and assert it still matches -- the CRS-side analog of running
        # real nuclei against the compiled artifact, without needing a live ModSecurity/Coraza.

      - uses: peter-evans/create-pull-request@v6
        with:
          commit-message: "chore: refresh attack-crs templates from coreruleset ${{ steps.crs.outputs.tag }}"
          branch: auto/update-crs
          delete-branch: true
          title: "Update CRS-sourced attack templates — coreruleset ${{ steps.crs.outputs.tag }}"
          body: |
            Automated refresh from coreruleset `${{ steps.crs.outputs.tag }}`.
            PL1 rules only; opaque-operator and PL2-4 rules recorded in skipped-crs.json.
            Fixture-replay + unit/compiler suite both green.
          add-paths: |
            templates/attack-crs/
            resources/compiled/funnypot-attack.php
            resources/skipped-crs.json
```

Also needed once, not per-run: `resources/UPSTREAM-LICENSE-CRS.md` (Apache-2.0 text + CRS copyright
notice, tag/SHA stamped like the existing nuclei manifest), and extending `ArtifactWriter`'s manifest
shape (or a sibling `manifest-crs.json`) with CRS tag+SHA+rule-counts+skipped-count, matching
`Compiler.php::manifest()`'s existing fields.

**Stretch, gold-standard lane** (optional, closer to nuclei's own acceptance rigor): spin up
Coraza or ModSecurity+CRS in Docker in CI, replay the same fixture payloads against it, and assert
CRS ITSELF still fires the expected rule id before trusting the fixture — catches CRS-side fixture
drift, not just funnypot-side regex drift. Not required for a first cut; the fixture-only replay above
is cheap and already meaningfully non-circular.

---

## Sources consulted

- `vendor/bobbymaher/funnypot-core/src/Compiler/{TemplateLoader,Compiler,ClusterableFilter,
  EmulatorCompiler,ArtifactWriter}.php`, `src/Template/{TemplateAttackEmulator,
  DirectiveRenderer}.php`, `SPEC.md`, `README.md`, `composer.json`,
  `.github/workflows/update-templates.yml`, `bin/funnypot`, `templates/attack/*.yaml` (all 31 read
  for shape; 6 read in full).
- `src/Compiler/CatalogCompiler.php`, `src/Policy/EmulationCatalog.php` (main funnypot repo).
- `github.com/coreruleset/coreruleset` (fetched directly): `LICENSE`, `README.md`,
  `crs-setup.conf.example`, `rules/` directory listing, `rules/REQUEST-942-APPLICATION-ATTACK-SQLI.
  conf`, `rules/REQUEST-913-SCANNER-DETECTION.conf`, `rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf`,
  `rules/scanners-user-agents.data`, `regex-assembly/` listing,
  `tests/regression/tests/REQUEST-942-APPLICATION-ATTACK-SQLI/942100.yaml`, release tag list
  (latest `v4.29.0` at research time).
