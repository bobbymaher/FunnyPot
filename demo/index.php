<?php

/**
 * funnypot — standalone honeypot demo (front controller for `php -S`).
 *
 *   GET /            -> "Welcome to funnypot" homepage + live dashboard of recent hits
 *   anything else    -> run funnypot: detect the scanner probe, serve a fake if matched,
 *                       and LOG every request (detection and non-detection alike)
 *
 * Every hit is appended as one JSON line to the log file (FUNNYPOT_LOG, default
 * demo/storage/hits.log) and echoed to stderr so `docker logs` shows it live.
 *
 * Env:
 *   FUNNYPOT_STYLE   minimal | realistic | taunt   (default realistic)
 *   FUNNYPOT_LOG     path to the hit log            (default demo/storage/hits.log)
 */

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\Honeytoken;
use Funnypot\Http\ResponseEmitter;
use Funnypot\Log4ShellProbe;
use Funnypot\RequestContext;

$logFile = getenv('FUNNYPOT_LOG') ?: __DIR__ . '/storage/hits.log';
@mkdir(dirname($logFile), 0777, true);

// Coherent chrome: one consistent X-Powered-By on every response (nginx owns Server), so
// header recon can't catch a version mismatch between the fake bodies and the server banner.
$poweredBy = getenv('FUNNYPOT_POWERED_BY') ?: 'PHP/8.1.27';
header('X-Powered-By: ' . $poweredBy);

$context = RequestContext::fromGlobals();
$clientIp = demo_client_ip();

// Anti-fingerprint tripwire: plant a signed bait cookie on every response and classify what
// comes back — a client that returns it tampered (role escalated) is a high-signal probe no
// ordinary visitor produces. Off unless FUNNYPOT_HONEYTOKEN_KEY is set.
$honeytokenKey = getenv('FUNNYPOT_HONEYTOKEN_KEY') ?: '';
$tokenVerdict = 'off';
if ($honeytokenKey !== '') {
    $token = new Honeytoken($honeytokenKey);
    $tokenVerdict = $token->inspect($_COOKIE['sess'] ?? null);
    header('Set-Cookie: ' . $token->cookie('sess', 'r=user'), false);
}

// A believable robots.txt whose Disallow list dangles the juicy honeypot paths at a crawler.
if ($context->method === 'GET' && $context->path === '/robots.txt') {
    header('Content-Type: text/plain; charset=utf-8');
    echo demo_robots();

    return true;
}

// A browser viewing our own dashboard auto-requests /favicon.ico. If it came from our
// page (same-origin Referer), ignore it — no honeypot, no log noise. A scanner probing
// favicon directly (no/foreign Referer) still gets served.
if ($context->path === '/favicon.ico') {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($host !== '' && strpos($referer, '://' . $host) !== false) {
        http_response_code(204);

        return true;
    }
}

// Password-gated admin actions (retention prune / clear) — POST only; the public view stays
// open. Disabled unless FUNNYPOT_ADMIN_PASSWORD is set.
if ($context->method === 'POST' && $context->path === '/' && isset($_GET['admin'])) {
    demo_admin($logFile, (string) $_GET['admin']);

    return true;
}

// Homepage / dashboard (and its JSON feed for live AJAX updates).
if ($context->method === 'GET' && ($context->path === '/' || $context->path === '/index.php')) {
    if (isset($_GET['feed'])) {
        demo_feed($logFile);
    } else {
        demo_render_shell($logFile);
    }

    return true;
}

// Honeypot path: detect + (gated) respond.
$style = getenv('FUNNYPOT_STYLE') ?: 'realistic';
$funnypot = Honeypot::default(new Config(
    mode: 'respond',
    gate: static fn (RequestContext $r): bool => true,          // standalone honeypot: everything hostile-looking gets a fake
    // A deliberate honeypot wants to look maximally vulnerable, so serve even the
    // critical (fake-RCE) responses. Consumers keep the safe 'high' default.
    severityCeiling: getenv('FUNNYPOT_CEILING') ?: 'critical',
    responseStyle: $style,
    personaSeed: static fn (RequestContext $r) => $clientIp ?: 'anon',
    // Small random delay so responses don't look like an instant honeypot. Keep modest
    // so the fpm worker pool isn't exhausted under a scan; tune via env.
    latencyMs: (int) (getenv('FUNNYPOT_LATENCY_MS') ?: 0),
    latencyJitterMs: (int) (getenv('FUNNYPOT_JITTER_MS') ?: 40),
    // Interactive attack-class emulation (LFI/SQLi/SSTI/cmd-inj/reflected-XSS) on any
    // endpoint, not just nuclei-known paths. On by default in the demo.
    attackEmulation: getenv('FUNNYPOT_ATTACK') !== '0',
    // Coherent X-Powered-By on the fake responses too, so they match the server chrome.
    poweredBy: $poweredBy
));

$detection = $funnypot->detect($context);
$response = $funnypot->respond($context);

// When a fake was served, log what it actually satisfied (template match OR attack class);
// otherwise fall back to the detect() signal.
$logged = $response !== null ? $response->satisfies : $detection;

demo_log($logFile, [
    'ts' => gmdate('c'),
    'ip' => $clientIp,
    'method' => $context->method,
    'path' => substr($context->path, 0, 200),
    'ua' => substr($context->headers['User-Agent'] ?? '', 0, 160),
    'matched' => $logged->matched,
    'severity' => $logged->highestSeverity,
    'templates' => array_slice($logged->templateIds(), 0, 8),
    'served' => $response !== null,
    'style' => $style,
    // capture the exploit payload an attacker POSTs (truncated)
    'body' => $context->rawBody !== null ? substr($context->rawBody, 0, 300) : null,
    'referer' => substr($context->headers['Referer'] ?? '', 0, 160) ?: null,
    // Threat-intel enrichment: OOB probes we can't fake but should flag.
    'log4shell' => Log4ShellProbe::present($context) ?: null,
    'honeytoken' => $tokenVerdict !== 'off' ? $tokenVerdict : null,
]);

if ($response !== null) {
    ResponseEmitter::emit($response);

    return true;
}

// An archive probe (.zip / .tar.gz) on a path with no template: instead of a plain 404,
// hand back a nested decoy archive. Peeling it — layer after layer of archives down to
// fabricated secrets — wastes the attacker's time. Bounded (a few KB, extracts to a few KB):
// a time sink, never a decompression bomb.
if (demo_serve_decoy_archive($context, $logFile, $clientIp)) {
    return true;
}

// Non-detection (or matched-but-declined): a believable server 404, not a constant
// "Not Found" string that screams honeypot.
http_response_code(404);
header('Content-Type: text/html');
echo demo_not_found();

return true;

// --------------------------------------------------------------------------

/**
 * Serve a nested decoy archive for a .zip / .tar.gz probe that would otherwise 404. The
 * decoys are prebuilt static assets (scripts/build-decoys.sh) named after what was asked
 * for, so the response looks like a real backup download. Returns true when it served one.
 *
 * Off-switch: FUNNYPOT_DECOY_ARCHIVE=0. GET only.
 */
function demo_serve_decoy_archive(RequestContext $r, string $logFile, string $clientIp): bool
{
    if ($r->method !== 'GET' || getenv('FUNNYPOT_DECOY_ARCHIVE') === '0') {
        return false;
    }

    // Longest suffix first so .tar.gz wins over .gz.
    $map = [
        '.tar.gz' => ['backup.tar.gz', 'application/gzip'],
        '.tgz' => ['backup.tar.gz', 'application/gzip'],
        '.gz' => ['backup.tar.gz', 'application/gzip'],
        '.zip' => ['backup.zip', 'application/zip'],
    ];
    $path = strtolower($r->path);
    $decoy = null;
    $ctype = '';
    foreach ($map as $ext => [$file, $type]) {
        if (substr($path, -strlen($ext)) === $ext) {
            $decoy = $file;
            $ctype = $type;
            break;
        }
    }
    if ($decoy === null) {
        return false;
    }

    $full = __DIR__ . '/decoys/' . $decoy;
    if (!is_file($full)) {
        return false;
    }
    $bytes = (string) file_get_contents($full);

    // Name the download after the requested file so it reads like a genuine backup.
    $name = basename($r->path);
    if ($name === '' || strpos($name, '.') === false) {
        $name = $decoy;
    }
    $name = preg_replace('/[^\w.\-]/', '_', $name);

    demo_log($logFile, [
        'ts' => gmdate('c'),
        'ip' => $clientIp,
        'method' => 'GET',
        'path' => substr($r->path, 0, 200),
        'event' => 'decoy-archive',
        'decoy' => $decoy,
    ]);

    http_response_code(200);
    header('Content-Type: ' . $ctype);
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Length: ' . strlen($bytes));
    echo $bytes;

    return true;
}

/**
 * A robots.txt whose Disallow list is bait — every entry points at one of the honeypot's own
 * juicy fakes, so a crawler that "politely" probes disallowed paths walks straight into a trap.
 */
function demo_robots(): string
{
    return "User-agent: *\n"
        . "Disallow: /.git/\n"
        . "Disallow: /.env\n"
        . "Disallow: /backup/\n"
        . "Disallow: /wp-admin/\n"
        . "Disallow: /phpmyadmin/\n"
        . "Disallow: /admin/\n"
        . "Disallow: /credentials.txt\n"
        . "Disallow: /backup.sql\n"
        . "Disallow: /.aws/\n"
        . "Sitemap: https://www.example.com/sitemap.xml\n";
}

/**
 * A believable server 404 — indistinguishable from a real nginx not-found, so an
 * unmatched probe doesn't reveal a honeypot via a tell-tale minimal error body.
 */
function demo_not_found(): string
{
    return "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
        . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
        . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
}

function demo_client_ip(): string
{
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($xff !== '') {
        return trim(explode(',', $xff)[0]);
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/** @param array<string,mixed> $entry */
function demo_log(string $logFile, array $entry): void
{
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n";
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
    @file_put_contents('php://stderr', $line);
}

/** @return array<int,array<string,mixed>> newest first */
function demo_recent(string $logFile, int $limit = 200): array
{
    if (!is_file($logFile)) {
        return [];
    }
    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $lines = array_slice($lines, -$limit);
    $rows = [];
    foreach (array_reverse($lines) as $l) {
        $row = json_decode($l, true);
        if (is_array($row)) {
            $rows[] = $row;
        }
    }

    return $rows;
}

/**
 * Live JSON feed. DELTA mode: return only the rows appended since the client's byte-offset
 * cursor, so a poll ships just the new rows — not the whole tail every time. `after` empty or
 * a stale cursor (after log rotation/prune) returns a fresh snapshot with reset=true.
 *
 * Modes via $_GET:
 *   feed=1&after=<byteOffset>  live delta (default)
 *   feed=older&skip=<n>        page back through history (newest-first, 100 at a time)
 */
function demo_feed(string $logFile): void
{
    header('Content-Type: application/json');
    header('Cache-Control: no-store');

    if (($_GET['feed'] ?? '') === 'older') {
        $skip = max(0, (int) ($_GET['skip'] ?? 0));
        $rows = demo_recent($logFile, $skip + 100);
        $page = array_slice($rows, $skip, 100);
        echo json_encode([
            'rows' => array_map('demo_row', $page),
            'more' => count($rows) > $skip + 100,
        ], JSON_UNESCAPED_SLASHES);

        return;
    }

    $size = is_file($logFile) ? (int) filesize($logFile) : 0;
    $after = (int) ($_GET['after'] ?? 0);
    $reset = ($after <= 0 || $after > $size);

    // reset -> newest 100 as a snapshot; otherwise just what was appended past the cursor.
    $rows = $reset
        ? array_reverse(demo_recent($logFile, 100))
        : demo_read_from($logFile, $after);

    echo json_encode([
        'cursor' => $size,
        'reset' => $reset,
        'rows' => array_map('demo_row', $rows),
        'stats' => demo_stats($logFile),
    ], JSON_UNESCAPED_SLASHES);
}

/**
 * The compact row shape the dashboard renders.
 *
 * @param array<string,mixed> $r
 * @return array<string,mixed>
 */
function demo_row(array $r): array
{
    return [
        'ts' => (string) ($r['ts'] ?? ''),
        'ip' => (string) ($r['ip'] ?? ''),
        'method' => (string) ($r['method'] ?? ''),
        'path' => (string) ($r['path'] ?? ''),
        'matched' => !empty($r['matched']),
        'severity' => (string) ($r['severity'] ?? ''),
        'served' => !empty($r['served']),
        'templates' => array_slice((array) ($r['templates'] ?? []), 0, 6),
        'body' => (string) ($r['body'] ?? ''),
    ];
}

/**
 * Rows appended to the log after byte offset $from, oldest-first. The cursor is always the
 * previous file size, i.e. a newline boundary, so fgets() reads whole lines.
 *
 * @return array<int,array<string,mixed>>
 */
function demo_read_from(string $logFile, int $from): array
{
    $rows = [];
    $fh = @fopen($logFile, 'rb');
    if ($fh === false) {
        return $rows;
    }
    if (@fseek($fh, $from) === 0) {
        while (($line = fgets($fh)) !== false) {
            $row = json_decode(trim($line), true);
            if (is_array($row)) {
                $rows[] = $row;
            }
        }
    }
    fclose($fh);

    return $rows;
}

/**
 * Stats over a recent tail window (labelled honestly on the UI). The optional SQLite store
 * gives true all-time aggregates; the file-only mode reports the window.
 *
 * @return array<string,int>
 */
function demo_stats(string $logFile): array
{
    $rows = demo_recent($logFile, 5000);
    $detections = $served = $harvested = 0;
    $ips = [];
    foreach ($rows as $r) {
        if (!empty($r['matched'])) {
            $detections++;
        }
        if (!empty($r['served'])) {
            $served++;
        }
        if (!empty($r['body'])) {
            $harvested++;
        }
        $ips[(string) ($r['ip'] ?? '')] = true;
    }

    return [
        'total' => count($rows),
        'detections' => $detections,
        'served' => $served,
        'ips' => count($ips),
        'harvested' => $harvested,
    ];
}

/**
 * Password-gated admin actions. The dashboard VIEW stays public; only mutating actions
 * (retention prune, clear) require FUNNYPOT_ADMIN_PASSWORD. Disabled if that env is unset.
 */
function demo_admin(string $logFile, string $action): void
{
    header('Content-Type: application/json');
    header('Cache-Control: no-store');

    $pass = getenv('FUNNYPOT_ADMIN_PASSWORD') ?: '';
    $given = (string) ($_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ($_POST['key'] ?? ''));
    if ($pass === '' || !hash_equals($pass, $given)) {
        http_response_code(403);
        echo json_encode(['error' => $pass === '' ? 'admin disabled (set FUNNYPOT_ADMIN_PASSWORD)' : 'forbidden']);

        return;
    }

    if ($action === 'prune') {
        $keep = max(0, (int) ($_POST['keep'] ?? 1000));
        demo_prune($logFile, $keep);
        echo json_encode(['ok' => true, 'kept' => $keep]);

        return;
    }
    if ($action === 'clear') {
        @file_put_contents($logFile, '', LOCK_EX);
        echo json_encode(['ok' => true, 'cleared' => true]);

        return;
    }

    http_response_code(400);
    echo json_encode(['error' => 'unknown action']);
}

/** Retention: rewrite the log keeping only the newest $keep lines. */
function demo_prune(string $logFile, int $keep): void
{
    if (!is_file($logFile)) {
        return;
    }
    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $lines = array_slice($lines, -$keep);
    @file_put_contents($logFile, $lines === [] ? '' : implode("\n", $lines) . "\n", LOCK_EX);
}

/**
 * The dashboard shell: static HTML + JS that polls demo_feed() and updates in place —
 * no full-page refresh. New rows flash; a live dot shows the connection.
 */
function demo_render_shell(string $logFile): void
{
    header('Content-Type: text/html; charset=utf-8');

    $css = <<<CSS
      :root{--bg:#12100c;--panel:#1c1913;--ink:#f3e9d2;--muted:#a8987a;--amber:#f0b400;--red:#ff6b5e;--line:#2e2a20}
      *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
      .wrap{max-width:1000px;margin:0 auto;padding:28px 18px}
      .head{display:flex;align-items:center;gap:14px;margin:0 0 4px}
      h1{font-size:30px;margin:0}.honey{color:var(--amber)}
      .live{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;display:inline-flex;align-items:center;gap:6px}
      .live .dot{width:8px;height:8px;border-radius:50%;background:#555;transition:background .3s}
      .live.on .dot{background:#39d353;box-shadow:0 0 8px #39d353;animation:pulse 1.6s infinite}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
      p.lead{color:var(--muted);margin:0 0 22px}
      .stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
      .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
      .stat b{display:block;font-size:26px;color:var(--amber)}.stat span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
      table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
      th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
      th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
      td.path{word-break:break-all;max-width:340px}
      .badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:700}
      .scan{background:rgba(240,180,0,.14);color:var(--amber);border:1px solid rgba(240,180,0,.35)}
      .miss{background:rgba(168,152,122,.12);color:var(--muted);border:1px solid var(--line)}
      .served{color:var(--red);font-weight:700}
      .ids{color:var(--muted);font-size:12px}
      tr.flash{animation:flash 1.4s ease-out}
      @keyframes flash{from{background:rgba(240,180,0,.28)}to{background:transparent}}
      .empty{color:var(--muted);text-align:center;padding:20px}
      .payload{color:var(--red);font-size:12px;word-break:break-all;margin-top:3px;white-space:pre-wrap}
      .payload b{color:var(--muted);font-weight:600}
      .controls{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
      .btn{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:7px 14px;font:inherit;font-size:13px;cursor:pointer}
      .btn:hover{border-color:var(--amber)}.btn:disabled{opacity:.5;cursor:default}
      .admin{margin-left:auto;display:flex;gap:8px}.admin .btn{color:var(--muted)}
      .note{color:var(--muted);font-size:11px;margin-top:4px}
      footer{color:var(--muted);margin-top:18px;font-size:12px}
    CSS;

    $js = <<<'JS'
      const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
      const $=id=>document.getElementById(id);
      let cursor=0, older=0, started=false;
      const seen=new Set();
      const key=r=>[r.ts,r.ip,r.method,r.path,r.severity||''].join('|');
      function rowEl(r){
        const tr=document.createElement('tr');
        const badge=r.matched?`<span class="badge scan">SCAN ${esc((r.severity||'').toUpperCase())}</span>`:'<span class="badge miss">404</span>';
        const ids=(r.templates&&r.templates.length)?`<div class="ids">${esc(r.templates.join(', '))}</div>`:'';
        const payload=r.body?`<div class="payload"><b>payload:</b> ${esc(r.body)}</div>`:'';
        const served=r.served?'<span class="served">served</span>':'&mdash;';
        const t=(r.ts||'').substr(11,8);
        tr.innerHTML=`<td>${t}</td><td>${esc(r.ip)}</td><td class="path"><b>${esc(r.method)}</b> ${esc(r.path)}${ids}${payload}</td><td>${badge}</td><td>${served}</td>`;
        return tr;
      }
      const empty=()=>{$('rows').innerHTML='<tr><td colspan=5 class=empty>No hits yet &mdash; point a scanner at this host.</td></tr>';};
      async function tick(){
        try{
          const d=await (await fetch('/?feed=1&after='+cursor,{cache:'no-store'})).json();
          const tb=$('rows');
          if(d.reset){tb.innerHTML='';seen.clear();older=0;}
          // delta rows arrive oldest-first; prepend so the newest lands on top.
          d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);const el=rowEl(r);if(started)el.classList.add('flash');tb.insertBefore(el,tb.firstChild);});
          while(tb.children.length>500)tb.removeChild(tb.lastChild);
          cursor=d.cursor;
          if(d.stats)['total','detections','served','ips','harvested'].forEach(k=>$(k).textContent=d.stats[k]);
          if(!tb.children.length)empty();
          started=true;$('live').classList.add('on');
        }catch(e){$('live').classList.remove('on');}
      }
      async function loadOlder(){
        const b=$('older');b.disabled=true;
        try{
          const d=await (await fetch('/?feed=older&skip='+older,{cache:'no-store'})).json();
          const tb=$('rows');
          d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);tb.appendChild(rowEl(r));});
          older+=d.rows.length;
          b.style.display=d.more?'':'none';
        }finally{b.disabled=false;}
      }
      function token(){let t=sessionStorage.getItem('fp_admin');if(!t){t=prompt('Admin password')||'';if(t)sessionStorage.setItem('fp_admin',t);}return t;}
      async function admin(action,body){
        const t=token();if(!t)return;
        const r=await fetch('/?admin='+action,{method:'POST',headers:{'X-Admin-Token':t,'Content-Type':'application/x-www-form-urlencoded'},body:body||''});
        if(r.status===403){sessionStorage.removeItem('fp_admin');alert('Admin disabled server-side, or wrong password.');return;}
        alert(JSON.stringify(await r.json()));cursor=0;older=0;seen.clear();tick();
      }
      $('older').onclick=loadOlder;
      $('prune').onclick=()=>{if(confirm('Prune the log to the newest 1000 lines?'))admin('prune','keep=1000');};
      $('clear').onclick=()=>{if(confirm('Delete ALL captured data? This cannot be undone.'))admin('clear');};
      tick();setInterval(tick,3000);
    JS;

    echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
    echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
    echo "<title>funnypot</title><style>{$css}</style></head><body><div class=wrap>";
    echo "<div class=head><h1>Welcome to <span class=honey>funnypot</span> &#127855;</h1>";
    echo "<span id=live class=live><span class=dot></span> live</span></div>";
    echo "<p class=lead>This host is a honeypot. Each row is a scanner probing for a vulnerability &mdash; served a plausible fake, its time wasted. Updates live.</p>";
    echo "<div class=stats>";
    echo "<div class=stat><b id=total>&mdash;</b><span>requests</span></div>";
    echo "<div class=stat><b id=detections>&mdash;</b><span>scans detected</span></div>";
    echo "<div class=stat><b id=served>&mdash;</b><span>fakes served</span></div>";
    echo "<div class=stat><b id=ips>&mdash;</b><span>unique IPs</span></div>";
    echo "<div class=stat><b id=harvested>&mdash;</b><span>payloads captured</span></div>";
    echo "</div>";
    echo "<div class=note>stats cover the recent window (last 5,000 events).</div>";
    echo "<table><thead><tr><th>time</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead>";
    echo "<tbody id=rows><tr><td colspan=5 class=empty>connecting&hellip;</td></tr></tbody></table>";
    echo "<div class=controls><button id=older class=btn>load older</button>";
    echo "<span class=admin><button id=prune class=btn title='keep newest 1000 events'>prune</button><button id=clear class=btn>clear</button></span></div>";
    echo "<footer>funnypot &mdash; a honeypot that turns scanner probes into wasted time.</footer>";
    echo "<script>{$js}</script>";
    echo "</div></body></html>";
}
