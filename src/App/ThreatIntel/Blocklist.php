<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use PDO;
use Throwable;

/**
 * Known-attacker IP blocklist. Fetches public attacker/botnet IP feeds, corroborates across them
 * (an IP's "lists" count = how many feeds named it), and stores the result in its own SQLite file
 * (intel.db, separate from the hit store so a bulk refresh never contends with hit ingest). The
 * honeypot asks isKnown() at write time to flag a hit as coming from a known attacker.
 *
 * Ported from iCabbiTools' URLBlocklistService fetch/parse; the Laravel cache + Redis set become a
 * single indexed SQLite table. CIDR-range feed entries are skipped for now (exact IPs only).
 */
final class Blocklist
{
    /** Public plaintext IP feeds. ipsum ships an "IP count" corroboration column; the rest are flat. */
    private const SOURCES = [
        'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'https://www.blocklist.de/downloads/export-ips_all.txt',
        'https://cinsscore.com/list/ci-badguys.txt',
        'https://lists.blocklist.de/lists/ssh.txt',
    ];

    private ?PDO $db = null;

    /**
     * @param string $dbPath   intel.db path
     * @param int    $minLists an IP must appear in at least this many feeds to count as known (>=1)
     */
    public function __construct(private string $dbPath, private int $minLists = 1)
    {
        $this->minLists = max(1, $minLists);
    }

    /** Is this IP a known attacker (present in >= minLists feeds)? Never throws. */
    public function isKnown(string $ip): bool
    {
        if ($ip === '' || $ip === 'unknown') {
            return false;
        }
        try {
            $st = $this->db()->prepare('SELECT lists FROM blocklist WHERE ip = :ip');
            $st->execute([':ip' => $ip]);
            $lists = $st->fetchColumn();

            return $lists !== false && (int) $lists >= $this->minLists;
        } catch (Throwable $e) {
            return false; // no intel db yet / unreadable: fail open (not flagged), never break a request
        }
    }

    public function count(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM blocklist')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /**
     * Refresh the blocklist from the feeds. $fetch(url) returns the body or null; the default uses
     * a bounded HTTP GET. Tests inject a fetcher so no network is touched. Returns counts.
     *
     * @param callable(string):?string|null $fetch
     * @param string[]|null                 $sources
     * @return array{sources:int,ips:int}
     */
    public function import(?callable $fetch = null, ?array $sources = null): array
    {
        $fetch ??= static function (string $url): ?string {
            $ctx = stream_context_create(['http' => ['timeout' => 20, 'user_agent' => 'funnypot'], 'https' => ['timeout' => 20]]);
            $body = @file_get_contents($url, false, $ctx);

            return $body === false ? null : $body;
        };

        $counts = [];
        $ok = 0;
        foreach ($sources ?? self::SOURCES as $url) {
            $body = $fetch($url);
            if ($body === null || $body === '') {
                continue;
            }
            $ok++;
            foreach (preg_split('/\r?\n/', $body) ?: [] as $line) {
                $parsed = self::parseLine($line);
                if ($parsed === null) {
                    continue;
                }
                [$ip, $c] = $parsed;
                $counts[$ip] = ($counts[$ip] ?? 0) + $c;
            }
        }

        $db = $this->db();
        $db->beginTransaction();
        $db->exec('DELETE FROM blocklist');
        $st = $db->prepare('INSERT OR REPLACE INTO blocklist (ip, lists) VALUES (:ip, :l)');
        foreach ($counts as $ip => $c) {
            $st->execute([':ip' => $ip, ':l' => $c]);
        }
        $db->commit();

        return ['sources' => $ok, 'ips' => count($counts)];
    }

    /**
     * Extract [ip, count] from a feed line, or null. Comments and CIDR ranges are skipped; an
     * ipsum-style trailing integer is the corroboration count, otherwise 1.
     *
     * @return array{0:string,1:int}|null
     */
    private static function parseLine(string $line): ?array
    {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || $line[0] === ';') {
            return null;
        }
        $parts = preg_split('/\s+/', $line) ?: [];
        $ipPart = $parts[0] ?? '';
        if ($ipPart === '' || strpos($ipPart, '/') !== false) {
            return null; // CIDR ranges need range storage: a follow-up
        }
        if (filter_var($ipPart, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $count = (isset($parts[1]) && ctype_digit($parts[1])) ? max(1, (int) $parts[1]) : 1;

        return [$ipPart, $count];
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $dir = dirname($this->dbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        // Shared by the root refresh runner and the www-data web workers: force 0666 before WAL so
        // the -wal/-shm sidecars inherit it (same reasoning as the hit store).
        @chmod($this->dbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec('CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, lists INTEGER NOT NULL DEFAULT 1)');

        return $this->db = $db;
    }
}
