# funnypot — emulator backlog (fake vulns mined from other honeypots)

> **Build status** (attack-class, template engine)
> The template engine is hardened and all attack-class emulation is now data (compiled
> funnypot templates), not hand-coded signatures. 20 attack rules ship.
> - **Done (migrated originals):** shellshock (1), struts OGNL (2), phpunit computed-md5 (3),
>   XXE (6), open-redirect (9), LFI unix+windows, cmdi unix+windows, SSTI numeric+twig, SQLi, XSS.
> - **Done (backlog):** Confluence 26134 (5), php-cgi 1823 source (4), LFI breadth — shadow /
>   group / environ (13), product config smb.conf (26), Glastopf `[php]` known-probe (14).
> - **Deferred — marker needs real-template verification (notes §4/§cross-cutting):** RFI (10),
>   CRLF splitting (15), PHP object injection (16). Several RFI templates are OOB/interactsh
>   and unsatisfiable in-band; CRLF can't be faked without reflecting attacker header bytes.
>
> **Build status** (route-template half, `kind: route`) — BUILT + real-nuclei verified.
> One data-driven RouteTemplateEmulator + a compiled `funnypot-routes.php` replace all 11
> hand-coded endpoint emulators (enrich: dress a bundle the nuclei index already routes to).
> Brand-new pages carry a `new_page` block → RouteBundleSynth freezes a bundle → `merge-routes`
> folds it into the index (additive, idempotent).
> - **Done (enrich):** the 11 (git/dotenv/xmlrpc/wp-config/wp-login/phpinfo/htpasswd/
>   apache-status/package-json/ssh-key/sql-dump) + Tomcat manager (7).
> - **Done (new_page):** Basic-Auth 401 (23), beelzebub fake-secrets bundle (21) —
>   credentials.txt / terraform.tfstate / users.csv / SQL backup — and phpMyAdmin login (18).
> - **Done (product-login enrich):** WebLogic (20), Exchange/OWA (19), Citrix Gateway (11),
>   Adminer, Joomla, WordPress readme (25), Django admin (24), Apache directory listing (22).
>   26 route templates ship.
> - **Still open (low value / blocked):** file-upload serve-back (8, more attack-class than
>   route), robots/TRACE/OPTIONS (27), Drupal (17, markers are awkward CHANGELOG fragments on
>   a root bundle), MCP server (29), Lophiid appliance packs (28, GPLv2-gated). Attack side:
>   RFI (10) / CRLF (15) / PHP object injection (16) still need real-template marker checks.


_Extracted from TANNER/SNARE/Glastopf, product/CVE honeypots (Struts, Tomcat, Citrix, Drupal, phpMyAdmin, OWA…), LLM/config honeypots (galah, beelzebub, Lophiid, modpot), and a broad sweep. All items are safely canned (output-only or bounded/computed reflection) — never execute attacker input._

# FUNNYPOT EMULATOR BACKLOG — synthesized from 4 honeypot-extraction reports

All items below are NEW (funnypot's existing 5 signatures / 11 endpoint emulators / ~6,343 nuclei inversions excluded). Everything listed is safely canned (output-only or bounded/computed reflection); items needing execution/OOB are in the "NOT doing" list, not here. Duplicates across reports are merged; the "source" column names every honeypot that independently surfaced the idea.

## 1. Ranked master table (new emulations, safe-canned only)

| # | Vuln / class | Source honeypot(s) | Trigger (request shape) | Canned response + marker it satisfies | Fits as | Effort | Value |
|---|---|---|---|---|---|---|---|
| 1 | **Shellshock CVE-2014-6271** | shockpot | `() {` in ANY header (UA/Referer/Cookie) | echo marker + reuse canned `/etc/passwd` in body | attack-Signature | S | High |
| 2 | **Struts2 OGNL CVE-2017-5638** | StrutsHoneypot | `%{` / `#` in Content-Type (+ multipart filename) | route into existing `uid=0(root)` / reflected OGNL marker | attack-Signature | S | High |
| 3 | **phpunit CVE-2017-9841 eval-stdin** | Lophiid (goja), servletpot (CRC32) | POST `/vendor/phpunit/.../eval-stdin.php`, body `<?…md5(x)…?>` | compute real MD5 of arg, append `LINUX` on `php_uname` — no PHP run | attack-Signature (computed reflect) | S-M | High |
| 4 | **php-cgi CVE-2012-1823 source disclosure** | Glastopf | `?-s` / `?-w` query (`\?\-[sw]`) | fixed fake highlighted/stripped PHP source | endpoint-Emulator | S | High |
| 5 | **Confluence OGNL CVE-2022-26134** | ConfluencePot | `${` in URL path/param | resp header `X-Cmd-Response:` w/ fake `uid=0(root)` + fake Confluence landing | attack-Signature (or product) | S-M | High |
| 6 | **XXE → file disclosure** | TANNER, Reactive-WAH (paper) | POST XML w/ `<!DOCTYPE…ENTITY SYSTEM "file:///etc/passwd">` | reuse existing canned `/etc/passwd`, bounded-reflected in parse output | attack-Signature | S-M | Med-High |
| 7 | **Tomcat Manager / status (static)** | Glastopf, honeyhttpd | `/manager/html`, `/manager/status` | static fake Tomcat manager/status HTML, `Server: Apache-Coyote/1.1` | endpoint-Emulator | S | High |
| 8 | **File-upload / webshell** | honeyup, honeyhttpd | multipart `POST upload.php` (field `fileToUpload`) | fake `success: D:\xampp\...\<uuid>-<name>` path; neutered serve-back (`"Scripting Engine not enabled."`), never persist to served path | Signature + endpoint-Emulator | M | High |
| 9 | **Open-redirect** | honeyup, django-admin | `?url=`/`?redirect=`/`?next=` external URL | `302 Location:` bounded-reflecting supplied URL | attack-Signature | S | Med |
| 10 | **RFI marker** | TANNER, Glastopf, servletpot | param starts `http(s)://`/`ftp://` or leading `|`/`[` | canned "included remote content" marker — never fetch | attack-Signature | S-M | Med |
| 11 | **Citrix ADC CVE-2019-19781** | CitrixHoneypot | `/vpn/`, `/vpn/../vpns/cfg/smb.conf`, POST `newbm.pl` | fake login page; canned `smb.conf`; canned 403; `Server: Apache` | product-deep | M | High |
| 12 | **SQLi result rows (UNION/dump)** | TANNER | `UNION SELECT`, `information_schema` | fake users/version rows — extends current error-only SQLi | product-deep / extend SQLi sig | M-H | Med-High |
| 13 | **LFI breadth + include-warning** | Glastopf | `/etc/shadow`, `/etc/group`, `/proc/self/environ` | add those canned files + fake `Warning: include() failed to open stream…` fallback | enrich existing LFI Signature | S | Med |
| 14 | **php-cgi / PHP known-probe markers** | servletpot (CRC32), TANNER, Glastopf | `[php]…[/php]`, `echo(md5(x))`, `phpinfo()`, `system(id)` | hardcoded expected marker for the known probe (SSTI-style allowlist) | attack-Signature | M | Med |
| 15 | **CRLF / response splitting** | TANNER, SNARE | `%0d%0a` + injected header in param | emit ONE whitelisted fixed canned header (never attacker bytes) | attack-Signature (bounded) | M | Med |
| 16 | **PHP object injection** | TANNER | `O:<n>:"…"` serialized in param | canned marker string | attack-Signature | S | Low |
| 17 | **Drupal CVE-2019-6340** | drupot, bwpot | `/node/…` REST | Drupal-8 fingerprint + reflect canned RCE marker (one better than drupot's bare 422) | product-deep | M | Med-High |
| 18 | **phpMyAdmin login + fake authed panel** | Glastopf, modpot, phpmyadmin_honeypot, Lophiid | `/phpmyadmin`, `/pma`, `login.php` | static PMA login → fake authed UI + fake phpinfo | product-deep | M | Med |
| 19 | **Exchange/OWA fingerprint + logon** | owa-honeypot, modpot | `/owa`,`/ecp`,`/EWS`,`/Autodiscover`… | 401 `Server: Microsoft-IIS/7.5` + `X-Powered-By: ASP.NET`; fake `logon.aspx` (15.1.1466) | product-deep | M | Med |
| 20 | **Oracle WebLogic** (CVE-2017-10271/2019-2725/2020-14882) | bwpot (pointer) | `/wls-wsat/…`, `/console/…` | canned XMLDecoder/console error or reflected marker | product-deep | M-H | Med-High |
| 21 | **beelzebub fake-secrets bundle** | beelzebub maze | GET `*/terraform.tfstate`, `credentials.txt`, `users.csv`, `docker-compose.yml`, `nginx.conf`, `.htaccess`, `access.log`, `error.log`, `migration.sql`, `id_rsa.pub` | coherent per-stack fake config/creds files | endpoint-Emulators (batch) | S each | Med-High (bundle) |
| 22 | **Fake Apache autoindex ("Index of /")** | honeyup, beelzebub | GET a directory path | canned `Index of /…` listing w/ parent-dir/file rows | endpoint-Emulator | S | Med |
| 23 | **Basic-Auth 401 challenge panel** | basic-auth-pot, honeyhttpd, beelzebub, OWASP-PH | GET a "protected" path / `Authorization:` header | `401 WWW-Authenticate: Basic realm=…`, product-specific realm + `Server` | endpoint-Emulator | S | Med |
| 24 | **Django admin login** | django-admin-honeypot | `/admin/`, `/admin/login/` | pixel-perfect Django login; always "enter the correct username and password"; `?next=` redirect | product-deep / Emulator | S-M | Med |
| 25 | **WordPress endpoint pack** | wordpot, HoneyPress | `recent-backups`/`downloadfile`; `/?author=N`; `/readme.html`; wp-mobile-detector `resize.php`; `*thumb`/`uploadify` | recent-backups→reuse `/etc/passwd`; author-enum→username `admin`; readme→`Version 2.8`; timthumb→`no image specified` | endpoint-Emulators (batch) | S each | Med |
| 26 | **Product config-file disclosure (generalized LFI)** | CitrixHoneypot | traversal to known product config path | canned product config (e.g. `smb.conf`) — generalizes LFI past `/etc/passwd` | endpoint-Emulator | S | Med |
| 27 | **robots.txt / TRACE / OPTIONS / PUT / 405+Allow** | Glastopf, beelzebub | method/path | static robots; bounded TRACE echo; `Allow:` header; `201` | minor Emulators | S | Low |
| 28 | **Lophiid edge-appliance packs** (Ivanti, Fortinet, PAN GlobalProtect, SonicWall, F5 Big-IP, ColdFusion, TeamCity, Metabase, CraftCMS, GeoServer, OFBiz, Cleo, Aspera…) | Lophiid | product-specific RECON + CVE URIs | captured real HTML/JSON + per-product `Server`/version header | product-deep (bulk) | M-H per product | High **(licensing flag)** |
| 29 | **MCP tool-server honeypot** | beelzebub, Lophiid | JSON-RPC `initialize` / tool calls | fake MCP tool list + canned tool output leaking fake PII | product-deep | M | Med |

## 2. Grouped by type (ranked by value/effort within group)

**(a) New attack-class Signatures** — Shellshock (1) › Struts2 OGNL (2) › phpunit-9841 computed-md5 (3) › Confluence-26134 (5) › XXE (6) › open-redirect (9) › RFI-marker (10) › PHP known-probe (14) › CRLF-bounded (15) › SQLi UNION rows (12, or extend existing) › PHP-object-injection (16).

**(b) New endpoint Emulators** — php-cgi-1823 source (4) › Tomcat manager/status static (7) › file-upload neutered serve-back (8) › beelzebub fake-secrets bundle (21) › LFI breadth enrichment (13) › fake autoindex (22) › Basic-Auth 401 panel (23) › product config disclosure/smb.conf (26) › WordPress endpoint pack (25) › robots/TRACE/OPTIONS/PUT (27).

**(c) Product-deep emulators** — Citrix-19781 (11) › Tomcat Manager full (deploy WAR-capture-not-run, `tomcat:tomcat` realm) › Drupal-8/6340 (17) › WebLogic (20) › phpMyAdmin deep (18) › OWA/Exchange (19) › Django admin (24) › MCP server (29) › Lophiid appliance packs (28, gated on GPLv2 licensing).

## 3. TOP 10 TO BUILD NEXT (highest value-per-effort, all safely canned, all widen scanner surface)

1. **Shellshock `() {` header Signature** — highest ROI; still mass-scanned, and no current signature fires on the header surface. Reuse existing `/etc/passwd` body.
2. **Struts2 OGNL-in-Content-Type Signature** — routes straight into funnypot's existing `uid=0(root)` output; new trigger surface (headers), tiny build.
3. **phpunit CVE-2017-9841 computed-MD5 Signature** — hyper-common probe; marker is *computed* (`md5(arg)` + `LINUX`), textbook reflect-never-execute.
4. **php-cgi CVE-2012-1823 `?-s/?-w` source-disclosure Emulator** — classic static-canned probe with a nuclei template; trivial fixed body.
5. **Confluence CVE-2022-26134 (`${` → `X-Cmd-Response: uid=0(root)`)** — single canned response header satisfies the exploit check; one of the most-scanned RCEs.
6. **XXE → canned `/etc/passwd` Signature** — near-free: reuses funnypot's existing passwd body inside an XML-parse response.
7. **Tomcat Manager / status static Emulator** — heavy scanner target; static fake HTML + Coyote `Server` header, low effort.
8. **Open-redirect Signature** — bounded `302 Location:` reflection; broad nuclei coverage, minimal code.
9. **File-upload/webshell Emulator (neutered serve-back)** — biggest genuine class gap; fake XAMPP success path + `"Scripting Engine not enabled."` on retrieval, never persist to a served path.
10. **beelzebub fake-secrets bundle** (`terraform.tfstate`, `credentials.txt`, `users.csv`, `docker-compose.yml`, `access.log`/`error.log`) — one pattern, many endpoints, extends the existing `.env`/`wp-config` family; juicy fake creds scanners love.

*Just below the line:* Citrix-19781, RFI-marker, LFI-breadth enrichment, phpMyAdmin deep.

## 4. Deliberately NOT doing (violates never-execute / not fakeable in-band)

- **Log4Shell / JNDI (CVE-2021-44228) exploit output** & **SSRF** — proof is an out-of-band interactsh/DNS callback; nothing to reflect in-band. Nuclei's OOB templates are unsatisfiable by a reflect-only responder. (Detect-and-log + benign 200 is the ceiling; not worth a canned marker.)
- **shockpot active fetch** (real ping/wget/curl/telnet in `perform_commands`) — executes attacker input / SSRF-fetches.
- **bwpot** (real WordPress/phpMyAdmin/Tomcat + `eval(base64_decode())` webshell) — runs the real vulnerable apps; the exact opposite of the invariant. Useful only as a **target catalog** (its one net-new pointer, WebLogic, is captured above as a canned item).
- **TANNER live-DB queries, PHPOX eval (php_code/object injection general case), template-image execution**; **Glastopf/TANNER RFI fetch** and **php-cgi POST** branch — all execute attacker input. Only the *class* is portable as a canned marker (already captured); the execution path is out.
- **Lophiid PAYLOAD_FETCHING** — active outbound fetch of second-stage payloads (shockpot-class egress).
- **HellPot infinite Markov tarpit** — a resource-exhaustion attack that also risks funnypot's own sockets/memory; not a bounded canned response.
- **honeyup zip-bomb `public_html.zip`** — retaliatory/harm-causing; abuse and legal risk; against reflect-never-harm.
- **LLM long-tail fallback / dynamic command-injection output** (galah, beelzebub LLMHoneypot, Lophiid COMMAND_INJECTION responder) — non-executing but **not canned** and gives **no guaranteed marker**. If ever adopted, it belongs as an explicit optional fallback *mode*, never the canned core.
- **SNARE site-cloning & dork-injection** — attraction/realism on a different architectural axis (site mirror vs per-request middleware); not vuln fakes.
- **TCP protocol emulators** (redis/mssql/postgres/mqtt/ldap/smb/rdp/vnc/telnet/ssh) — out of funnypot's HTTP scope.

## Cross-cutting notes for the build

- **CRLF caution:** funnypot's C8 header guard is deliberately anti-CRLF. Item 15 must emit only a fixed whitelisted header, never attacker bytes — verify against the actual nuclei CRLF template before building.
- **Techniques worth adopting alongside the emulators** (not vulns): honeyup's **neutered serve-back** should be the template for both file-upload (8) and RFI (10); Lophiid's **content-templating macros** (`%%STRING%%`, `%%REQUEST_SOURCE_IP%%`, cookie-exp) defeat static-hash fingerprinting of the honeypot and raise realism cheaply; per-product `Server`/error-page chrome (honeyhttpd) lifts every product-deep emulator.
- **Licensing:** Lophiid is **GPLv2** — do not directly ingest its captured-content packs (item 28) without clearing the copyleft implication; re-capture or re-author instead.
- **Marker verification:** confirm nuclei-marker compatibility for RFI (10) and CRLF (15) against the real templates first — several RFI templates are interactsh/OOB and won't fire regardless.
