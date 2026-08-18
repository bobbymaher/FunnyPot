<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Report attacker IPs to AbuseIPDB (ported from iCabbiTools' AbuseIPDBService::reportIP). Opt-in,
 * and wrapped in guards so it can only ever report real, external attackers:
 *
 *  - INVARIANT (non-negotiable): never report our own IP. If our own IPs are not known, nothing is
 *    reported at all (fail safe), so the honeypot can never flag itself from its own test traffic.
 *  - only public, routable IPs (never RFC1918 / reserved).
 *  - per-IP dedup window (default 6h) and a daily cap (default 1000, the free tier) so a scan burst
 *    cannot spam the API. iCabbiTools has the dedup but not the daily cap; this adds it.
 *
 * State (dedup + daily count) lives in intel.db. The HTTP sender is injectable for tests.
 */
final class AbuseIpdb
{
    private ?PDO $db = null;

    /**
     * @param string   $apiKey     AbuseIPDB API key ('' disables)
     * @param string   $intelDbPath intel.db (shared with the blocklist)
     * @param string[] $selfIps    our own public IP(s); reporting is disabled if this is empty
     * @param int      $dailyCap   stop reporting once this many reports have been sent today
     * @param int      $dedupHours do not re-report the same IP within this many hours
     * @param callable(string,array<string>,string):array{status:int,body:string}|null $sender
     */
    public function __construct(
        private string $apiKey,
        private string $intelDbPath,
        private array $selfIps = [],
        private int $dailyCap = 1000,
        private int $dedupHours = 6,
        private $sender = null,
    ) {
    }

    /**
     * Report an attacker IP. Returns whether it was reported and why not if it was skipped. Never
     * throws — a reporting failure must not affect the honeypot response.
     *
     * @return array{reported:bool,reason:string}
     */
    public function report(string $ip, string $comment): array
    {
        if ($this->apiKey === '') {
            return $this->skip('no api key');
        }
        // Fail safe: without our own IP list we cannot guarantee we are not reporting ourselves.
        if ($this->selfIps === []) {
            return $this->skip('self ips not configured');
        }
        if (in_array($ip, $this->selfIps, true)) {
            return $this->skip('self');                 // the invariant
        }
        if (!self::reportable($ip)) {
            return $this->skip('not a public ip');
        }

        try {
            if ($this->recentlyReported($ip)) {
                return $this->skip('deduped');
            }
            if ($this->dailyCount() >= $this->dailyCap) {
                return $this->skip('daily cap');
            }

            $send = $this->sender ?? [$this, 'httpPost'];
            $res = $send(
                'https://api.abuseipdb.com/api/v2/report',
                ['Key: ' . $this->apiKey, 'Accept: application/json'],
                http_build_query([
                    'ip' => $ip,
                    'categories' => '14,21',   // port scan + web app attack
                    'comment' => substr($comment, 0, 900),
                    'timestamp' => gmdate('c'),
                ])
            );

            $this->recordReported($ip);
            $this->bumpDaily();
            $status = (int) ($res['status'] ?? 0);

            return ['reported' => $status >= 200 && $status < 300, 'reason' => 'http ' . $status];
        } catch (Throwable $e) {
            return $this->skip('error: ' . $e->getMessage());
        }
    }

    /** @return array{reported:bool,reason:string} */
    private function skip(string $reason): array
    {
        return ['reported' => false, 'reason' => $reason];
    }

    /** Public, routable IPs only: never RFC1918, loopback or other reserved space. */
    private static function reportable(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private function recentlyReported(string $ip): bool
    {
        $st = $this->db()->prepare('SELECT reported_at FROM abuse_reports WHERE ip = :ip');
        $st->execute([':ip' => $ip]);
        $at = $st->fetchColumn();
        if ($at === false) {
            return false;
        }

        return (strtotime((string) $at) ?: 0) > time() - $this->dedupHours * 3600;
    }

    private function recordReported(string $ip): void
    {
        $st = $this->db()->prepare('INSERT OR REPLACE INTO abuse_reports (ip, reported_at) VALUES (:ip, :at)');
        $st->execute([':ip' => $ip, ':at' => gmdate('c')]);
    }

    private function dailyCount(): int
    {
        $st = $this->db()->prepare('SELECT n FROM abuse_daily WHERE day = :d');
        $st->execute([':d' => gmdate('Y-m-d')]);
        $n = $st->fetchColumn();

        return $n === false ? 0 : (int) $n;
    }

    private function bumpDaily(): void
    {
        $this->db()->prepare(
            'INSERT INTO abuse_daily (day, n) VALUES (:d, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1'
        )->execute([':d' => gmdate('Y-m-d')]);
    }

    /**
     * @param string[] $headers
     * @return array{status:int,body:string}
     */
    private function httpPost(string $url, array $headers, string $body): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => implode("\r\n", array_merge($headers, ['Content-Type: application/x-www-form-urlencoded'])),
            'content' => $body,
            'timeout' => 5,
            'ignore_errors' => true,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return ['status' => $status, 'body' => $resp === false ? '' : $resp];
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $dir = dirname($this->intelDbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $this->intelDbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        @chmod($this->intelDbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('CREATE TABLE IF NOT EXISTS abuse_reports (ip TEXT PRIMARY KEY, reported_at TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS abuse_daily (day TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)');

        return $this->db = $db;
    }
}
