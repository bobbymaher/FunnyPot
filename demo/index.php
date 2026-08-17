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
use Funnypot\Http\ResponseEmitter;
use Funnypot\NucleiInverter;
use Funnypot\RequestContext;

$logFile = getenv('FUNNYPOT_LOG') ?: __DIR__ . '/storage/hits.log';
@mkdir(dirname($logFile), 0777, true);

// Never leak the real PHP version — replace the banner with a plausible fake.
header('X-Powered-By: ' . (getenv('FUNNYPOT_POWERED_BY') ?: 'PHP/7.4.33'));

$context = RequestContext::fromGlobals();
$clientIp = demo_client_ip();

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
$funnypot = NucleiInverter::default(new Config(
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
    attackEmulation: getenv('FUNNYPOT_ATTACK') !== '0'
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
]);

if ($response !== null) {
    ResponseEmitter::emit($response);

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
 * JSON feed of recent hits + stats, polled by the dashboard for live updates.
 */
function demo_feed(string $logFile): void
{
    $rows = demo_recent($logFile);
    $detections = 0;
    $served = 0;
    $ips = [];
    $out = [];
    foreach ($rows as $r) {
        if (!empty($r['matched'])) {
            $detections++;
        }
        if (!empty($r['served'])) {
            $served++;
        }
        $ips[$r['ip'] ?? ''] = true;
        $out[] = [
            'ts' => (string) ($r['ts'] ?? ''),
            'ip' => (string) ($r['ip'] ?? ''),
            'method' => (string) ($r['method'] ?? ''),
            'path' => (string) ($r['path'] ?? ''),
            'matched' => !empty($r['matched']),
            'severity' => (string) ($r['severity'] ?? ''),
            'served' => !empty($r['served']),
            'templates' => array_slice((array) ($r['templates'] ?? []), 0, 6),
            // captured exploit payload / credentials the attacker POSTed
            'body' => (string) ($r['body'] ?? ''),
        ];
    }

    $harvested = 0;
    foreach ($out as $row) {
        if ($row['body'] !== '') {
            $harvested++;
        }
    }

    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode([
        'stats' => [
            'total' => count($rows),
            'detections' => $detections,
            'served' => $served,
            'ips' => count($ips),
            'harvested' => $harvested,
        ],
        'rows' => $out,
    ], JSON_UNESCAPED_SLASHES);
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
      footer{color:var(--muted);margin-top:18px;font-size:12px}
    CSS;

    $js = <<<'JS'
      const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
      const seen=new Set();let first=true;
      const set=(id,v)=>{document.getElementById(id).textContent=v;};
      async function tick(){
        try{
          const d=await (await fetch('/?feed=1',{cache:'no-store'})).json();
          set('total',d.stats.total);set('detections',d.stats.detections);
          set('served',d.stats.served);set('ips',d.stats.ips);set('harvested',d.stats.harvested);
          const tb=document.getElementById('rows');
          if(!d.rows.length){tb.innerHTML='<tr><td colspan=5 class=empty>No hits yet &mdash; point a scanner at this host.</td></tr>';}
          else{
            tb.innerHTML=d.rows.map(r=>{
              const key=r.ts+'|'+r.ip+'|'+r.path;
              const isNew=!first&&!seen.has(key);
              const badge=r.matched?`<span class="badge scan">SCAN ${esc((r.severity||'').toUpperCase())}</span>`:'<span class="badge miss">404</span>';
              const ids=(r.templates&&r.templates.length)?`<div class="ids">${esc(r.templates.join(', '))}</div>`:'';
              const payload=r.body?`<div class="payload"><b>payload:</b> ${esc(r.body)}</div>`:'';
              const served=r.served?'<span class="served">served</span>':'&mdash;';
              const t=(r.ts||'').substr(11,8);
              return `<tr class="${isNew?'flash':''}"><td>${t}</td><td>${esc(r.ip)}</td><td class="path"><b>${esc(r.method)}</b> ${esc(r.path)}${ids}${payload}</td><td>${badge}</td><td>${served}</td></tr>`;
            }).join('');
          }
          d.rows.forEach(r=>seen.add(r.ts+'|'+r.ip+'|'+r.path));
          first=false;document.getElementById('live').classList.add('on');
        }catch(e){document.getElementById('live').classList.remove('on');}
      }
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
    echo "<table><thead><tr><th>time</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead>";
    echo "<tbody id=rows><tr><td colspan=5 class=empty>connecting&hellip;</td></tr></tbody></table>";
    echo "<footer>funnypot &mdash; the inverse of a nuclei scanner.</footer>";
    echo "<script>{$js}</script>";
    echo "</div></body></html>";
}
