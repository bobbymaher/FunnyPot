<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\Http\ResponseEmitter;
use Funnypot\Log4ShellProbe;
use Funnypot\Policy\EmulationPolicy;
use Funnypot\RequestContext;
use Geo;

/**
 * The honeypot itself: run an incoming probe through the funnypot-core engine (detect + gated
 * respond), log every request, and serve either the fake, a decoy archive, or a believable 404.
 * Also owns the two small deception endpoints that sit next to it (robots.txt, favicon).
 */
final class HoneypotController
{
    public function __construct(
        private HitStore $store,
        private Geo $geo,
        private AppConfig $config,
        private string $decoyDir,
        private ?Blocklist $blocklist = null,
        private ?AbuseIpdb $abuse = null,
        private ?LlmFakeResponder $llmFakes = null,
    ) {
    }

    /** A small delay applied to the LLM fake and the plain 404 so their timing matches a served
     *  template fake (which already delays inside the engine), leaving at most one timing bucket. */
    private function serveDelay(): void
    {
        $ms = $this->config->latencyMs + ($this->config->jitterMs > 0 ? random_int(0, $this->config->jitterMs) : 0);
        if ($ms > 0) {
            usleep($ms * 1000);
        }
    }

    /** True if the client IP is a known attacker (present in the intel blocklist). */
    private function known(string $ip): bool
    {
        return $this->blocklist !== null && $this->blocklist->isKnown($ip);
    }

    /** The real client IP: first X-Forwarded-For hop, else REMOTE_ADDR. */
    public static function clientIp(): string
    {
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') {
            return trim(explode(',', $xff)[0]);
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /** A robots.txt whose Disallow list is bait: every entry points at one of the honeypot's fakes. */
    public function robots(): void
    {
        header('Content-Type: text/plain; charset=utf-8');
        echo "User-agent: *\n"
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
     * A browser viewing our own dashboard auto-requests /favicon.ico. If it came from our page
     * (same-origin Referer), ignore it — no honeypot, no log noise. A scanner probing favicon
     * directly (no/foreign Referer) falls through to be served + logged. Returns true when handled.
     */
    public function faviconSameOrigin(): bool
    {
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if ($host !== '' && strpos($referer, '://' . $host) !== false) {
            http_response_code(204);

            return true;
        }

        return false;
    }

    /** Run the probe through the engine, log it, and emit a fake / decoy archive / believable 404. */
    public function handle(RequestContext $context, string $clientIp, string $tokenVerdict): void
    {
        // The emulation catalog's on/off choices become the engine's deny-set + corpus flag.
        $policy = EmulationPolicy::fromPackage(is_file($this->config->vulnsPath) ? $this->config->vulnsPath : null);
        $funnypot = Honeypot::default(new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,          // standalone honeypot: everything hostile-looking gets a fake
            severityCeiling: $this->config->severityCeiling,
            responseStyle: $this->config->style,
            personaSeed: static fn (RequestContext $r) => $clientIp ?: 'anon',
            latencyMs: $this->config->latencyMs,
            latencyJitterMs: $this->config->jitterMs,
            attackEmulation: $this->config->attackEmulation,
            poweredBy: $this->config->poweredBy,
            exclude: $policy->disabledIds(),
            nucleiReflection: $policy->nucleiEnabled(),
        ));

        $detection = $funnypot->detect($context);
        $response = $funnypot->respond($context);

        // When a fake was served, log what it actually satisfied; else the detect() signal.
        $logged = $response !== null ? $response->satisfies : $detection;

        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => $context->method,
            'path' => substr($context->path, 0, 200),
            'ua' => substr($context->headers['User-Agent'] ?? '', 0, 160),
            'matched' => $logged->matched,
            'severity' => $logged->highestSeverity,
            'templates' => array_slice($logged->templateIds(), 0, 8),
            'served' => $response !== null,
            'style' => $this->config->style,
            'body' => $context->rawBody !== null ? substr($context->rawBody, 0, 300) : null,
            'referer' => substr($context->headers['Referer'] ?? '', 0, 160) ?: null,
            'log4shell' => Log4ShellProbe::present($context) ?: null,
            'honeytoken' => $tokenVerdict !== 'off' ? $tokenVerdict : null,
            'geo' => $this->geo->lookup($clientIp),
            'known_attacker' => $this->known($clientIp),
        ]);

        if ($response !== null) {
            ResponseEmitter::emit($response);
        } elseif (!$this->serveDecoyArchive($context, $clientIp)) {
            // A plausible unknown path may get an LLM-generated fake; everything else (declined,
            // failed, or the responder being off) falls through to the believable plain 404.
            $llm = $this->llmFakes?->respond($context, $clientIp);
            $this->serveDelay();
            if ($llm !== null) {
                ResponseEmitter::emit($llm);
            } else {
                // Non-detection (or matched-but-declined): a believable server 404, not a constant string.
                http_response_code(404);
                header('Content-Type: text/html');
                echo "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
                    . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
                    . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
            }
        }

        // Queue an AbuseIPDB report for the matched attacker (a fast local write; the drain worker
        // sends it). The comment carries the port hit and the full URL, per the report format.
        $this->maybeReport($logged->matched, $clientIp, $context);
    }

    /** Queue a matched web attacker for AbuseIPDB, with the port + URL in the comment. */
    private function maybeReport(bool $matched, string $clientIp, RequestContext $context): void
    {
        if (!$matched || $this->abuse === null) {
            return;
        }
        $port = (int) ($_SERVER['SERVER_PORT'] ?? 0);
        $httpsVal = (string) ($_SERVER['HTTPS'] ?? '');
        $https = ($httpsVal !== '' && $httpsVal !== 'off') || $port === 443;
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
        $url = ($host !== '' ? ($https ? 'https' : 'http') . '://' . $host : '') . $context->path;
        $comment = sprintf('funnypot web honeypot, port %d: %s %s', $port, $context->method, substr($url, 0, 180));
        $this->abuse->enqueue($clientIp, $comment, '21');   // web app attack
    }

    /**
     * Serve a nested decoy archive for a .zip / .tar.gz probe that would otherwise 404. The decoys
     * are prebuilt static assets named after what was asked for. Off-switch: decoyArchive=false.
     * GET only. Returns true when it served one.
     */
    private function serveDecoyArchive(RequestContext $r, string $clientIp): bool
    {
        if ($r->method !== 'GET' || !$this->config->decoyArchive) {
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

        $full = $this->decoyDir . '/' . $decoy;
        if (!is_file($full)) {
            return false;
        }
        $bytes = (string) file_get_contents($full);

        $name = basename($r->path);
        if ($name === '' || strpos($name, '.') === false) {
            $name = $decoy;
        }
        $name = preg_replace('/[^\w.\-]/', '_', $name);

        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => 'GET',
            'path' => substr($r->path, 0, 200),
            'event' => 'decoy-archive',
            'decoy' => $decoy,
            'geo' => $this->geo->lookup($clientIp),
            'known_attacker' => $this->known($clientIp),
        ]);

        http_response_code(200);
        header('Content-Type: ' . $ctype);
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('Content-Length: ' . strlen($bytes));
        echo $bytes;

        return true;
    }
}
