<?php

declare(strict_types=1);

/**
 * Demo hit store. The JSON-lines log stays the canonical record; when pdo_sqlite is available
 * (and not disabled with FUNNYPOT_DB=off) a SQLite mirror is dual-written in-request for real
 * all-time aggregates, geoip joins, and O(1) delta/pagination by row id. A DB insert can never
 * fail the request. With no DB the store falls back to the JSON-lines file (byte-offset delta,
 * a recent-window for stats) so the demo still runs standalone with zero setup.
 */
final class Store
{
    private ?PDO $db = null;

    public function __construct(private string $logFile, ?string $dbPath)
    {
        if ($dbPath !== null && $dbPath !== 'off' && extension_loaded('pdo_sqlite')) {
            try {
                $this->db = $this->open($dbPath);
            } catch (Throwable $e) {
                $this->db = null; // fall back to file-only
            }
        }
    }

    public function usingDb(): bool
    {
        return $this->db !== null;
    }

    /** Append a hit. File first (canonical), then a best-effort DB mirror. */
    public function append(array $entry): void
    {
        $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n";
        @file_put_contents($this->logFile, $line, FILE_APPEND | LOCK_EX);
        @file_put_contents('php://stderr', $line);

        if ($this->db !== null) {
            try {
                $this->insert($entry);
            } catch (Throwable $e) {
                // never let logging break the honeypot
            }
        }
    }

    /**
     * Rows appended since the client's opaque cursor (row id in DB mode, byte offset in file
     * mode). Returns oldest-first so the client prepends them newest-on-top.
     *
     * @return array{cursor:int,reset:bool,rows:array<int,array<string,mixed>>}
     */
    public function delta(int $cursor): array
    {
        if ($this->db !== null) {
            $max = (int) $this->db->query('SELECT COALESCE(MAX(id),0) FROM hits')->fetchColumn();
            $reset = ($cursor <= 0 || $cursor > $max);
            if ($reset) {
                $rows = array_reverse($this->dbRows('SELECT * FROM hits ORDER BY id DESC LIMIT 100'));
            } else {
                $st = $this->db->prepare('SELECT * FROM hits WHERE id > :c ORDER BY id ASC LIMIT 500');
                $st->execute([':c' => $cursor]);
                $rows = array_map([$this, 'mapDbRow'], $st->fetchAll(PDO::FETCH_ASSOC));
            }

            return ['cursor' => $max, 'reset' => $reset, 'rows' => $rows];
        }

        // file mode: byte-offset cursor
        $size = is_file($this->logFile) ? (int) filesize($this->logFile) : 0;
        $reset = ($cursor <= 0 || $cursor > $size);
        $rows = $reset ? array_reverse($this->fileRecent(100)) : $this->fileFrom($cursor);

        return ['cursor' => $size, 'reset' => $reset, 'rows' => array_map([$this, 'mapRow'], $rows)];
    }

    /**
     * A page of older history, newest-first, skipping the newest $skip.
     *
     * @return array{rows:array<int,array<string,mixed>>,more:bool}
     */
    public function older(int $skip): array
    {
        if ($this->db !== null) {
            $st = $this->db->prepare('SELECT * FROM hits ORDER BY id DESC LIMIT 100 OFFSET :o');
            $st->bindValue(':o', $skip, PDO::PARAM_INT);
            $st->execute();
            $rows = array_map([$this, 'mapDbRow'], $st->fetchAll(PDO::FETCH_ASSOC));
            $more = (int) $this->db->query('SELECT COUNT(*) FROM hits')->fetchColumn() > $skip + 100;

            return ['rows' => $rows, 'more' => $more];
        }

        $all = $this->fileRecent($skip + 100);
        $page = array_slice($all, $skip, 100);

        return ['rows' => array_map([$this, 'mapRow'], $page), 'more' => count($all) > $skip + 100];
    }

    /** @return array<string,int> all-time in DB mode; a recent window in file mode. */
    public function stats(): array
    {
        if ($this->db !== null) {
            $r = $this->db->query(
                "SELECT COUNT(*) total, COALESCE(SUM(matched),0) detections, COALESCE(SUM(served),0) served,
                        COUNT(DISTINCT ip) ips, COALESCE(SUM(CASE WHEN body<>'' THEN 1 ELSE 0 END),0) harvested
                 FROM hits"
            )->fetch(PDO::FETCH_ASSOC) ?: [];

            return array_map('intval', [
                'total' => $r['total'] ?? 0, 'detections' => $r['detections'] ?? 0,
                'served' => $r['served'] ?? 0, 'ips' => $r['ips'] ?? 0, 'harvested' => $r['harvested'] ?? 0,
            ]);
        }

        $rows = $this->fileRecent(5000);
        $detections = $served = $harvested = 0;
        $ips = [];
        foreach ($rows as $r) {
            $detections += !empty($r['matched']) ? 1 : 0;
            $served += !empty($r['served']) ? 1 : 0;
            $harvested += !empty($r['body']) ? 1 : 0;
            $ips[(string) ($r['ip'] ?? '')] = true;
        }

        return ['total' => count($rows), 'detections' => $detections, 'served' => $served, 'ips' => count($ips), 'harvested' => $harvested];
    }

    /**
     * Aggregate widgets for the dashboard: top talker IPs, top source countries, top fired
     * templates, and an hourly histogram. DB mode = all-time; file mode = the recent window.
     *
     * @return array<string,array<int,array<string,mixed>>>
     */
    public function widgets(): array
    {
        return $this->db !== null ? $this->dbWidgets() : $this->fileWidgets();
    }

    /** @return array<string,array<int,array<string,mixed>>> */
    private function dbWidgets(): array
    {
        $rows = fn (string $sql): array => $this->db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        try {
            $templates = $rows(
                "SELECT je.value t, COUNT(*) n FROM hits, json_each(hits.templates) je
                 WHERE hits.matched=1 GROUP BY je.value ORDER BY n DESC LIMIT 12"
            );
        } catch (Throwable $e) {
            $templates = []; // SQLite built without JSON1
        }

        return [
            'talkers' => $rows("SELECT ip, COUNT(*) n, MAX(cc) cc FROM hits WHERE ip<>'' GROUP BY ip ORDER BY n DESC LIMIT 10"),
            'countries' => $rows("SELECT cc, COUNT(*) n FROM hits WHERE cc<>'' GROUP BY cc ORDER BY n DESC LIMIT 12"),
            'templates' => $templates,
            'histogram' => array_reverse($rows("SELECT substr(ts,1,13) h, COUNT(*) n FROM hits WHERE ts<>'' GROUP BY h ORDER BY h DESC LIMIT 24")),
        ];
    }

    /** @return array<string,array<int,array<string,mixed>>> */
    private function fileWidgets(): array
    {
        $ip = $cc = $tm = $hr = [];
        foreach ($this->fileRecent(5000) as $r) {
            $i = (string) ($r['ip'] ?? '');
            if ($i !== '') {
                $ip[$i] = ($ip[$i] ?? 0) + 1;
            }
            $c = (string) (($r['geo']['cc'] ?? ''));
            if ($c !== '') {
                $cc[$c] = ($cc[$c] ?? 0) + 1;
            }
            if (!empty($r['matched'])) {
                foreach ((array) ($r['templates'] ?? []) as $t) {
                    $tm[(string) $t] = ($tm[(string) $t] ?? 0) + 1;
                }
            }
            $h = substr((string) ($r['ts'] ?? ''), 0, 13);
            if ($h !== '') {
                $hr[$h] = ($hr[$h] ?? 0) + 1;
            }
        }
        arsort($ip);
        arsort($cc);
        arsort($tm);
        ksort($hr);
        $top = static function (array $a, string $key, int $n): array {
            $out = [];
            foreach (array_slice($a, 0, $n, true) as $k => $v) {
                $out[] = [$key => $k, 'n' => $v];
            }

            return $out;
        };

        return [
            'talkers' => $top($ip, 'ip', 10),
            'countries' => $top($cc, 'cc', 12),
            'templates' => $top($tm, 't', 12),
            'histogram' => $top(array_slice($hr, -24, 24, true), 'h', 24),
        ];
    }

    /** Retention: keep the newest $keep events in both stores. */
    public function prune(int $keep): void
    {
        if (is_file($this->logFile)) {
            $lines = @file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            $lines = array_slice($lines, -$keep);
            @file_put_contents($this->logFile, $lines === [] ? '' : implode("\n", $lines) . "\n", LOCK_EX);
        }
        if ($this->db !== null) {
            $st = $this->db->prepare('DELETE FROM hits WHERE id <= (SELECT COALESCE(MAX(id),0) FROM hits) - :k');
            $st->execute([':k' => $keep]);
        }
    }

    public function clear(): void
    {
        @file_put_contents($this->logFile, '', LOCK_EX);
        if ($this->db !== null) {
            $this->db->exec('DELETE FROM hits');
        }
    }

    /** Backfill the DB from the JSON-lines log (idempotent-ish: clears then re-imports). */
    public function import(): int
    {
        if ($this->db === null || !is_file($this->logFile)) {
            return 0;
        }
        $this->db->exec('DELETE FROM hits');
        $n = 0;
        $fh = fopen($this->logFile, 'rb');
        if ($fh === false) {
            return 0;
        }
        $this->db->beginTransaction();
        while (($line = fgets($fh)) !== false) {
            $row = json_decode(trim($line), true);
            if (is_array($row)) {
                $this->insert($row);
                $n++;
            }
        }
        $this->db->commit();
        fclose($fh);

        return $n;
    }

    // --- SQLite plumbing ---

    private function open(string $path): PDO
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, ip TEXT, method TEXT, path TEXT,
                matched INTEGER DEFAULT 0, severity TEXT, served INTEGER DEFAULT 0,
                templates TEXT, body TEXT, event TEXT,
                log4shell INTEGER DEFAULT 0, honeytoken TEXT,
                cc TEXT, city TEXT, lat REAL, lon REAL, asn TEXT
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ip ON hits(ip)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)');

        return $db;
    }

    private function insert(array $e): void
    {
        static $st = null;
        if ($st === null) {
            $st = $this->db->prepare(
                'INSERT INTO hits (ts,ip,method,path,matched,severity,served,templates,body,event,log4shell,honeytoken,cc,city,lat,lon,asn)
                 VALUES (:ts,:ip,:method,:path,:matched,:severity,:served,:templates,:body,:event,:log4shell,:honeytoken,:cc,:city,:lat,:lon,:asn)'
            );
        }
        $geo = $e['geo'] ?? [];
        $st->execute([
            ':ts' => (string) ($e['ts'] ?? ''),
            ':ip' => (string) ($e['ip'] ?? ''),
            ':method' => (string) ($e['method'] ?? ''),
            ':path' => (string) ($e['path'] ?? ''),
            ':matched' => !empty($e['matched']) ? 1 : 0,
            ':severity' => (string) ($e['severity'] ?? ''),
            ':served' => !empty($e['served']) ? 1 : 0,
            ':templates' => json_encode(array_values((array) ($e['templates'] ?? [])), JSON_UNESCAPED_SLASHES),
            ':body' => (string) ($e['body'] ?? ''),
            ':event' => (string) ($e['event'] ?? ''),
            ':log4shell' => !empty($e['log4shell']) ? 1 : 0,
            ':honeytoken' => (string) ($e['honeytoken'] ?? ''),
            ':cc' => (string) ($geo['cc'] ?? ''),
            ':city' => (string) ($geo['city'] ?? ''),
            ':lat' => isset($geo['lat']) ? (float) $geo['lat'] : null,
            ':lon' => isset($geo['lon']) ? (float) $geo['lon'] : null,
            ':asn' => (string) ($geo['asn'] ?? ''),
        ]);
    }

    /** @return array<int,array<string,mixed>> */
    private function dbRows(string $sql): array
    {
        return array_map([$this, 'mapDbRow'], $this->db->query($sql)->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return array<string,mixed> */
    private function mapDbRow(array $r): array
    {
        return [
            'ts' => (string) ($r['ts'] ?? ''),
            'ip' => (string) ($r['ip'] ?? ''),
            'method' => (string) ($r['method'] ?? ''),
            'path' => (string) ($r['path'] ?? ''),
            'matched' => !empty($r['matched']),
            'severity' => (string) ($r['severity'] ?? ''),
            'served' => !empty($r['served']),
            'templates' => array_slice((array) json_decode((string) ($r['templates'] ?? '[]'), true), 0, 6),
            'body' => (string) ($r['body'] ?? ''),
            'cc' => (string) ($r['cc'] ?? ''),
            'lat' => $r['lat'] !== null ? (float) $r['lat'] : null,
            'lon' => $r['lon'] !== null ? (float) $r['lon'] : null,
        ];
    }

    /** @return array<string,mixed> */
    private function mapRow(array $r): array
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
            'cc' => (string) (($r['geo']['cc'] ?? '')),
        ];
    }

    // --- file-mode helpers ---

    /** @return array<int,array<string,mixed>> newest-first */
    private function fileRecent(int $limit): array
    {
        if (!is_file($this->logFile)) {
            return [];
        }
        $lines = @file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
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

    /** @return array<int,array<string,mixed>> oldest-first, appended after byte offset $from */
    private function fileFrom(int $from): array
    {
        $rows = [];
        $fh = @fopen($this->logFile, 'rb');
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
}
