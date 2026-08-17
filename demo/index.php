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
require __DIR__ . '/lib/store.php';
require __DIR__ . '/lib/geo.php';

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\Honeytoken;
use Funnypot\Http\ResponseEmitter;
use Funnypot\Log4ShellProbe;
use Funnypot\RequestContext;

$logFile = getenv('FUNNYPOT_LOG') ?: __DIR__ . '/storage/hits.log';
@mkdir(dirname($logFile), 0777, true);

// Hit store: JSON-lines log is canonical; a SQLite mirror (when pdo_sqlite is present and
// FUNNYPOT_DB is not 'off') powers real all-time stats, geoip, and O(1) delta/pagination.
$store = new Store($logFile, getenv('FUNNYPOT_DB') ?: __DIR__ . '/storage/funnypot.sqlite');
$geo = new Geo(getenv('FUNNYPOT_GEO_DB') ?: __DIR__ . '/storage/dbip-country.csv.gz');

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
    demo_admin($store, $geo, (string) $_GET['admin']);

    return true;
}

// Homepage / dashboard (and its JSON feed for live AJAX updates).
if ($context->method === 'GET' && ($context->path === '/' || $context->path === '/index.php')) {
    if (isset($_GET['feed'])) {
        demo_feed($store);
    } else {
        demo_render_shell();
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

$store->append([
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
    // GeoIP enrichment at write time (country + lat/lon for the attacker map).
    'geo' => $geo->lookup($clientIp),
]);

if ($response !== null) {
    ResponseEmitter::emit($response);

    return true;
}

// An archive probe (.zip / .tar.gz) on a path with no template: instead of a plain 404,
// hand back a nested decoy archive. Peeling it — layer after layer of archives down to
// fabricated secrets — wastes the attacker's time. Bounded (a few KB, extracts to a few KB):
// a time sink, never a decompression bomb.
if (demo_serve_decoy_archive($context, $store, $clientIp)) {
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
function demo_serve_decoy_archive(RequestContext $r, Store $store, string $clientIp): bool
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

    $store->append([
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

/**
 * Live JSON feed backed by the Store. Modes via $_GET:
 *   feed=1&after=<cursor>  delta — only rows since the cursor (opaque: row id or byte offset)
 *   feed=older&skip=<n>    page back through history, newest-first, 100 at a time
 * The Store decides DB vs file semantics; the client treats the cursor as opaque.
 */
function demo_feed(Store $store): void
{
    header('Content-Type: application/json');
    header('Cache-Control: no-store');

    if (($_GET['feed'] ?? '') === 'older') {
        echo json_encode($store->older(max(0, (int) ($_GET['skip'] ?? 0))), JSON_UNESCAPED_SLASHES);

        return;
    }

    $out = $store->delta((int) ($_GET['after'] ?? 0));
    $out['stats'] = $store->stats();
    $out['widgets'] = $store->widgets();
    echo json_encode($out, JSON_UNESCAPED_SLASHES);
}

/**
 * Password-gated admin actions. The VIEW stays public; only mutating actions (retention
 * prune, clear, DB backfill) require FUNNYPOT_ADMIN_PASSWORD. Disabled if that env is unset.
 */
function demo_admin(Store $store, Geo $geo, string $action): void
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
        $store->prune(max(0, (int) ($_POST['keep'] ?? 1000)));
        echo json_encode(['ok' => true]);

        return;
    }
    if ($action === 'clear') {
        $store->clear();
        echo json_encode(['ok' => true, 'cleared' => true]);

        return;
    }
    if ($action === 'import') {
        echo json_encode(['ok' => true, 'imported' => $store->import()]);

        return;
    }
    if ($action === 'geoip') {
        // Build the IP→country range table from the fetched DB-IP CSV.
        echo json_encode(['ok' => true, 'ranges' => $geo->import()]);

        return;
    }

    http_response_code(400);
    echo json_encode(['error' => 'unknown action']);
}

/**
 * The dashboard shell: static HTML + JS that polls the feed and updates in place —
 * no full-page refresh. New rows flash; a live dot shows the connection.
 */
function demo_render_shell(): void
{
    header('Content-Type: text/html; charset=utf-8');

    $css = <<<CSS
      :root{--bg:#12100c;--panel:#1c1913;--ink:#f3e9d2;--muted:#a8987a;--amber:#f0b400;--red:#ff6b5e;--line:#2e2a20}
      *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
      .wrap{max-width:1180px;margin:0 auto;padding:28px 18px}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin:16px 0}
      .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
      .card h3{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
      .wl{list-style:none;margin:0;padding:0}
      .wl li{display:flex;justify-content:space-between;gap:8px;padding:3px 0;border-bottom:1px solid var(--line);font-size:13px}
      .wl li:last-child{border:0}.wl .n{color:var(--amber);font-variant-numeric:tabular-nums}
      .wl li.click{cursor:pointer}.wl li.click:hover{color:var(--amber)}
      .bar{position:relative;background:var(--line);border-radius:4px;height:17px;overflow:hidden;margin:3px 0}
      .bar>i{position:absolute;left:0;top:0;bottom:0;background:rgba(240,180,0,.30)}
      .bar>label{position:relative;display:flex;justify-content:space-between;padding:0 7px;font-size:11px;line-height:17px}
      .hist{display:flex;align-items:flex-end;gap:2px;height:56px;margin-top:4px}
      .hist>div{flex:1;background:rgba(240,180,0,.4);min-height:2px;border-radius:2px 2px 0 0}
      #map{height:300px;border-radius:10px;border:1px solid var(--line);margin:16px 0;background:#0d0b08}
      .leaflet-container{background:#0d0b08!important}
      .filter{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:6px 10px;font:inherit;font-size:13px}
      tr.hide{display:none}
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
      let cursor=0, older=0, started=false, filter='';
      const seen=new Set();
      const key=r=>[r.ts,r.ip,r.method,r.path,r.severity||''].join('|');
      let map=null, markers=null;
      function initMap(){
        if(!window.L||map)return;
        map=L.map('map',{worldCopyJump:true}).setView([25,10],2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:6,subdomains:'abcd',attribution:'&copy; OpenStreetMap &copy; CARTO'}).addTo(map);
        markers=L.layerGroup().addTo(map);
      }
      function plot(r){
        if(!markers||r.lat==null||r.lon==null)return;
        const m=L.circleMarker([r.lat,r.lon],{radius:4,color:'#f0b400',weight:1,fillColor:'#f0b400',fillOpacity:.7}).addTo(markers);
        const layers=markers.getLayers();if(layers.length>300)markers.removeLayer(layers[0]);
        setTimeout(()=>{try{m.setStyle({fillOpacity:.2,opacity:.3});}catch(e){}},4000);
      }
      function applyFilter(){document.querySelectorAll('#rows tr').forEach(tr=>tr.classList.toggle('hide', filter!=='' && !(tr.dataset.ip||'').includes(filter)));}
      function rowEl(r){
        const tr=document.createElement('tr');tr.dataset.ip=r.ip||'';
        const badge=r.matched?`<span class="badge scan">SCAN ${esc((r.severity||'').toUpperCase())}</span>`:'<span class="badge miss">404</span>';
        const ids=(r.templates&&r.templates.length)?`<div class="ids">${esc(r.templates.join(', '))}</div>`:'';
        const payload=r.body?`<div class="payload"><b>payload:</b> ${esc(r.body)}</div>`:'';
        const served=r.served?'<span class="served">served</span>':'&mdash;';
        const cc=r.cc?` <span class="ids">${esc(r.cc)}</span>`:'';
        const t=(r.ts||'').substr(11,8);
        tr.innerHTML=`<td>${t}</td><td>${esc(r.ip)}${cc}</td><td class="path"><b>${esc(r.method)}</b> ${esc(r.path)}${ids}${payload}</td><td>${badge}</td><td>${served}</td>`;
        return tr;
      }
      const empty=()=>{$('rows').innerHTML='<tr><td colspan=5 class=empty>No hits yet &mdash; point a scanner at this host.</td></tr>';};
      function renderWidgets(w){
        if(!w)return;
        $('w_talkers').innerHTML=(w.talkers||[]).map(t=>`<li class="click" data-ip="${esc(t.ip)}"><span>${esc(t.ip)}${t.cc?' <span class=ids>'+esc(t.cc)+'</span>':''}</span><span class="n">${t.n}</span></li>`).join('')||'<li>&mdash;</li>';
        const cmax=Math.max(1,...(w.countries||[]).map(c=>c.n));
        $('w_countries').innerHTML=(w.countries||[]).map(c=>`<div class="bar"><i style="width:${Math.round(c.n/cmax*100)}%"></i><label><span>${esc(c.cc)}</span><span>${c.n}</span></label></div>`).join('')||'&mdash;';
        $('w_templates').innerHTML=(w.templates||[]).map(t=>`<li><span>${esc(t.t)}</span><span class="n">${t.n}</span></li>`).join('')||'<li>&mdash;</li>';
        const hmax=Math.max(1,...(w.histogram||[]).map(h=>h.n));
        $('w_hist').innerHTML=(w.histogram||[]).map(h=>`<div style="height:${Math.round(h.n/hmax*100)}%" title="${esc(h.h)}: ${h.n}"></div>`).join('');
        document.querySelectorAll('#w_talkers li.click').forEach(li=>li.onclick=()=>{filter=li.dataset.ip;$('filter').value=filter;applyFilter();});
      }
      async function tick(){
        try{
          const d=await (await fetch('/?feed=1&after='+cursor,{cache:'no-store'})).json();
          const tb=$('rows');
          if(d.reset){tb.innerHTML='';seen.clear();older=0;if(markers)markers.clearLayers();}
          d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);const el=rowEl(r);if(started)el.classList.add('flash');tb.insertBefore(el,tb.firstChild);plot(r);});
          while(tb.children.length>500)tb.removeChild(tb.lastChild);
          cursor=d.cursor;
          if(d.stats)['total','detections','served','ips','harvested'].forEach(k=>$(k).textContent=d.stats[k]);
          renderWidgets(d.widgets);
          if(!tb.children.length)empty();else applyFilter();
          started=true;$('live').classList.add('on');
        }catch(e){$('live').classList.remove('on');}
      }
      async function loadOlder(){
        const b=$('older');b.disabled=true;
        try{
          const d=await (await fetch('/?feed=older&skip='+older,{cache:'no-store'})).json();
          const tb=$('rows');
          d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);tb.appendChild(rowEl(r));});
          older+=d.rows.length;applyFilter();
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
      $('prune').onclick=()=>{if(confirm('Prune to the newest 1000 events?'))admin('prune','keep=1000');};
      $('clear').onclick=()=>{if(confirm('Delete ALL captured data? This cannot be undone.'))admin('clear');};
      $('filter').oninput=e=>{filter=e.target.value.trim();applyFilter();};
      initMap();tick();setInterval(tick,3000);
    JS;

    echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
    echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
    echo "<link rel=stylesheet href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css' crossorigin>";
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
    echo "<div id=map></div>";
    echo "<div class=grid>";
    echo "<div class=card><h3>top talkers</h3><ul class=wl id=w_talkers></ul></div>";
    echo "<div class=card><h3>source countries</h3><div id=w_countries></div></div>";
    echo "<div class=card><h3>templates fired</h3><ul class=wl id=w_templates></ul></div>";
    echo "<div class=card><h3>activity (hourly)</h3><div class=hist id=w_hist></div></div>";
    echo "</div>";
    echo "<div class=controls style='margin-bottom:8px'><input id=filter class=filter placeholder='filter by ip&hellip;'>";
    echo "<span class=note style='margin:0 0 0 auto'>stats: all-time (DB) or recent window (file mode)</span></div>";
    echo "<table><thead><tr><th>time</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead>";
    echo "<tbody id=rows><tr><td colspan=5 class=empty>connecting&hellip;</td></tr></tbody></table>";
    echo "<div class=controls><button id=older class=btn>load older</button>";
    echo "<span class=admin><button id=prune class=btn title='keep newest 1000 events'>prune</button><button id=clear class=btn>clear</button></span></div>";
    echo "<footer>funnypot &mdash; a honeypot that turns scanner probes into wasted time. &middot; map &copy; OpenStreetMap, CARTO</footer>";
    echo "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js' crossorigin></script>";
    echo "<script>{$js}</script>";
    echo "</div></body></html>";
}
