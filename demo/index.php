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

$context = RequestContext::fromGlobals();
$clientIp = demo_client_ip();

// Homepage / dashboard.
if ($context->method === 'GET' && ($context->path === '/' || $context->path === '/index.php')) {
    demo_render_dashboard($logFile);

    return true;
}

// Honeypot path: detect + (gated) respond.
$style = getenv('FUNNYPOT_STYLE') ?: 'realistic';
$funnypot = NucleiInverter::default(new Config(
    mode: 'respond',
    gate: static fn (RequestContext $r): bool => true,          // standalone honeypot: everything hostile-looking gets a fake
    responseStyle: $style,
    personaSeed: static fn (RequestContext $r) => $clientIp ?: 'anon'
));

$detection = $funnypot->detect($context);
$response = $funnypot->respond($context);

demo_log($logFile, [
    'ts' => gmdate('c'),
    'ip' => $clientIp,
    'method' => $context->method,
    'path' => substr($context->path, 0, 200),
    'ua' => substr($context->headers['User-Agent'] ?? '', 0, 160),
    'matched' => $detection->matched,
    'severity' => $detection->highestSeverity,
    'templates' => array_slice($detection->templateIds(), 0, 8),
    'served' => $response !== null,
    'style' => $style,
]);

if ($response !== null) {
    ResponseEmitter::emit($response);

    return true;
}

// Non-detection (or matched-but-declined): a plain 404, still logged above.
http_response_code(404);
header('Content-Type: text/plain');
echo "Not Found\n";

return true;

// --------------------------------------------------------------------------

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

function demo_render_dashboard(string $logFile): void
{
    $rows = demo_recent($logFile);
    $total = count($rows);
    $detections = 0;
    $served = 0;
    $ips = [];
    foreach ($rows as $r) {
        if (!empty($r['matched'])) {
            $detections++;
        }
        if (!empty($r['served'])) {
            $served++;
        }
        $ips[$r['ip'] ?? ''] = true;
    }
    $uniqueIps = count($ips);

    header('Content-Type: text/html; charset=utf-8');
    $e = static fn ($s): string => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');

    echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
    echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
    echo "<meta http-equiv=refresh content=5>";
    echo "<title>funnypot</title><style>";
    echo <<<CSS
      :root{--bg:#12100c;--panel:#1c1913;--ink:#f3e9d2;--muted:#a8987a;--amber:#f0b400;--red:#ff6b5e;--line:#2e2a20}
      *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
      .wrap{max-width:1000px;margin:0 auto;padding:28px 18px}
      h1{font-size:30px;margin:0 0 4px}.honey{color:var(--amber)}
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
      footer{color:var(--muted);margin-top:18px;font-size:12px}
      a{color:var(--amber)}
    CSS;
    echo "</style></head><body><div class=wrap>";
    echo "<h1>Welcome to <span class=honey>funnypot</span> &#127855;</h1>";
    echo "<p class=lead>This host is a honeypot. Every request below is a scanner probing for a vulnerability &mdash; it is served a plausible fake and its time is wasted. Page auto-refreshes every 5s.</p>";

    echo "<div class=stats>";
    echo "<div class=stat><b>{$total}</b><span>requests</span></div>";
    echo "<div class=stat><b>{$detections}</b><span>scans detected</span></div>";
    echo "<div class=stat><b>{$served}</b><span>fakes served</span></div>";
    echo "<div class=stat><b>{$uniqueIps}</b><span>unique IPs</span></div>";
    echo "</div>";

    if ($rows === []) {
        echo "<p class=lead>No hits yet. Point a scanner at this host &mdash; e.g. <code>nuclei -u http://THIS_HOST -t http/exposures/</code> &mdash; and watch them land.</p>";
    } else {
        echo "<table><thead><tr><th>time (utc)</th><th>ip</th><th>request</th><th>verdict</th><th>fake?</th></tr></thead><tbody>";
        foreach ($rows as $r) {
            $matched = !empty($r['matched']);
            $badge = $matched
                ? "<span class='badge scan'>SCAN " . $e(strtoupper((string) ($r['severity'] ?? ''))) . "</span>"
                : "<span class='badge miss'>404</span>";
            $ids = !empty($r['templates']) ? "<div class=ids>" . $e(implode(', ', $r['templates'])) . "</div>" : '';
            $served = !empty($r['served']) ? "<span class=served>served</span>" : "&mdash;";
            $time = $e(substr((string) ($r['ts'] ?? ''), 11, 8));
            echo "<tr><td>{$time}</td><td>" . $e($r['ip'] ?? '') . "</td>"
                . "<td class=path><b>" . $e($r['method'] ?? '') . "</b> " . $e($r['path'] ?? '') . $ids . "</td>"
                . "<td>{$badge}</td><td>{$served}</td></tr>";
        }
        echo "</tbody></table>";
    }

    echo "<footer>funnypot &mdash; the inverse of a nuclei scanner. Log: " . $e($logFile) . "</footer>";
    echo "</div></body></html>";
}
