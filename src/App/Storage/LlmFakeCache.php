<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;
use Throwable;

/**
 * Cache of LLM-generated fake pages, keyed by normalised method+path. Same PDO idiom as
 * SqliteHitStore (WAL, busy_timeout, 0666 before WAL, fail-open) in its own file so it never
 * contends with hit ingest. One deterministic fake per path, served byte-identical forever (a
 * per-visitor difference would itself be a fingerprint). No freshness TTL; invalidation is a
 * prompt_version bump. A single-flight lock stops a burst of first-hits from all generating at once.
 */
final class LlmFakeCache
{
    private ?PDO $db = null;

    public function __construct(private string $dbPath)
    {
    }

    /** The cached fake for this key at the current prompt version, or null (a stale version is a miss). */
    public function get(string $key, string $promptVersion): ?array
    {
        try {
            $db = $this->db();
            $st = $db->prepare('SELECT status, content_type, body FROM llm_cache WHERE cache_key = :k AND prompt_version = :v');
            $st->execute([':k' => $key, ':v' => $promptVersion]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                return null;
            }
            $db->prepare('UPDATE llm_cache SET served_count = served_count + 1, last_served_at = :t WHERE cache_key = :k')
                ->execute([':t' => gmdate('c'), ':k' => $key]);

            return ['status' => (int) $row['status'], 'content_type' => (string) $row['content_type'], 'body' => (string) $row['body']];
        } catch (Throwable $e) {
            return null;
        }
    }

    public function put(string $key, int $status, string $contentType, string $body, string $promptVersion): void
    {
        try {
            $now = gmdate('c');
            $this->db()->prepare(
                'INSERT OR REPLACE INTO llm_cache (cache_key, status, content_type, body, prompt_version, created_at, last_served_at, served_count)
                 VALUES (:k, :s, :c, :b, :v, :t, :t, 0)'
            )->execute([':k' => $key, ':s' => $status, ':c' => $contentType, ':b' => $body, ':v' => $promptVersion, ':t' => $now]);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    /**
     * All cached fakes for the operator dashboard, most-recently-served first. Bodies are included
     * (each is small, capped by the sanitizer's maxBytes) so the operator can read a response and
     * judge whether to delete it.
     *
     * @return list<array<string,mixed>>
     */
    public function all(int $limit = 1000): array
    {
        try {
            $st = $this->db()->prepare(
                'SELECT cache_key, status, content_type, prompt_version, created_at, last_served_at,
                        served_count, LENGTH(body) AS bytes, body
                 FROM llm_cache ORDER BY last_served_at DESC LIMIT :lim'
            );
            $st->bindValue(':lim', max(1, $limit), PDO::PARAM_INT);
            $st->execute();

            return array_map(static fn (array $r): array => [
                'key' => (string) $r['cache_key'],
                'status' => (int) $r['status'],
                'content_type' => (string) $r['content_type'],
                'prompt_version' => (string) $r['prompt_version'],
                'created_at' => (string) $r['created_at'],
                'last_served_at' => (string) $r['last_served_at'],
                'served_count' => (int) $r['served_count'],
                'bytes' => (int) $r['bytes'],
                'body' => (string) $r['body'],
            ], $st->fetchAll(PDO::FETCH_ASSOC) ?: []);
        } catch (Throwable $e) {
            return [];
        }
    }

    /** Summary for the dashboard header: entry count, total body bytes, total serves. */
    public function stats(): array
    {
        try {
            $r = $this->db()->query(
                'SELECT COUNT(*) n, COALESCE(SUM(LENGTH(body)),0) bytes, COALESCE(SUM(served_count),0) served FROM llm_cache'
            )->fetch(PDO::FETCH_ASSOC) ?: [];

            return ['entries' => (int) ($r['n'] ?? 0), 'bytes' => (int) ($r['bytes'] ?? 0), 'served' => (int) ($r['served'] ?? 0)];
        } catch (Throwable $e) {
            return ['entries' => 0, 'bytes' => 0, 'served' => 0];
        }
    }

    /** Delete one cached fake the operator judged a bad response. True if a row was removed. */
    public function delete(string $key): bool
    {
        try {
            $st = $this->db()->prepare('DELETE FROM llm_cache WHERE cache_key = :k');
            $st->execute([':k' => $key]);

            return $st->rowCount() > 0;
        } catch (Throwable $e) {
            return false;
        }
    }

    /** Drop every cached fake (operator reset). Returns how many were removed. */
    public function clearAll(): int
    {
        try {
            return (int) $this->db()->exec('DELETE FROM llm_cache');
        } catch (Throwable $e) {
            return 0;
        }
    }

    public const ACQUIRE_WON = 'won';   // this caller holds the lock and must generate
    public const ACQUIRE_BUSY = 'busy'; // another caller is already generating this same key
    public const ACQUIRE_FULL = 'full'; // the global concurrency cap is reached; do not generate

    /**
     * Atomic single-flight + concurrency cap. Takes the lock for $key only if no peer already holds
     * it AND fewer than $maxConcurrent generations are in flight. SQLite serialises writers, so the
     * count is evaluated under the same write lock as the insert — the cap is a hard ceiling with no
     * check-then-act race, even under a burst of simultaneous requests.
     */
    public function acquire(string $key, int $maxConcurrent): string
    {
        $db = $this->db();
        try {
            // BEGIN IMMEDIATE grabs the write lock now, so the dup check + count + insert all see one
            // consistent state; no other writer can slip a lock in between them.
            $db->exec('BEGIN IMMEDIATE');

            $dup = $db->prepare('SELECT 1 FROM llm_inflight WHERE cache_key = :k');
            $dup->execute([':k' => $key]);
            if ($dup->fetchColumn()) {
                $db->exec('COMMIT');

                return self::ACQUIRE_BUSY;
            }

            $count = (int) $db->query('SELECT COUNT(*) FROM llm_inflight')->fetchColumn();
            if ($count >= max(1, $maxConcurrent)) {
                $db->exec('COMMIT');

                return self::ACQUIRE_FULL;
            }

            $db->prepare('INSERT INTO llm_inflight (cache_key, started_at) VALUES (:k, :t)')
                ->execute([':k' => $key, ':t' => gmdate('c')]);
            $db->exec('COMMIT');

            return self::ACQUIRE_WON;
        } catch (Throwable $e) {
            try {
                $db->exec('ROLLBACK');
            } catch (Throwable $e2) {
                // no active transaction to roll back
            }

            return self::ACQUIRE_FULL;  // on lock contention or any storage error, shed to the plain 404
        }
    }

    public function release(string $key): void
    {
        try {
            $this->db()->prepare('DELETE FROM llm_inflight WHERE cache_key = :k')->execute([':k' => $key]);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    public function inflightCount(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM llm_inflight')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /** Poll briefly for the lock winner's result (the losing caller waits, then falls back to 404). */
    public function awaitOther(string $key, string $promptVersion, int $waitMs = 300): ?array
    {
        $steps = max(1, (int) ($waitMs / 50));
        for ($i = 0; $i < $steps; $i++) {
            usleep(50000);
            $hit = $this->get($key, $promptVersion);
            if ($hit !== null) {
                return $hit;
            }
        }

        return null;
    }

    /** LRU eviction to a byte budget (sum of body lengths), run from the retention timer. Rows removed. */
    public function retainBytes(int $maxBytes): int
    {
        if ($maxBytes <= 0) {
            return 0;
        }
        try {
            $db = $this->db();
            $total = (int) $db->query('SELECT COALESCE(SUM(LENGTH(body)), 0) FROM llm_cache')->fetchColumn();
            if ($total <= $maxBytes) {
                return 0;
            }
            $removed = 0;
            while ($total > $maxBytes) {
                $rows = $db->query('SELECT cache_key, LENGTH(body) len FROM llm_cache ORDER BY last_served_at ASC LIMIT 50')
                    ->fetchAll(PDO::FETCH_ASSOC);
                if ($rows === []) {
                    break;
                }
                $del = $db->prepare('DELETE FROM llm_cache WHERE cache_key = :k');
                foreach ($rows as $r) {
                    $del->execute([':k' => $r['cache_key']]);
                    $total -= (int) $r['len'];
                    $removed++;
                    if ($total <= $maxBytes) {
                        break;
                    }
                }
            }

            return $removed;
        } catch (Throwable $e) {
            return 0;
        }
    }

    /** Reclaim inflight rows left by a crashed winner. Returns how many were cleared. */
    public function reapInflight(int $secs = 15): int
    {
        try {
            $st = $this->db()->prepare('DELETE FROM llm_inflight WHERE started_at < :c');
            $st->execute([':c' => gmdate('c', time() - $secs)]);

            return $st->rowCount();
        } catch (Throwable $e) {
            return 0; // best-effort
        }
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
        @chmod($this->dbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS llm_cache (
                cache_key TEXT PRIMARY KEY, status INTEGER, content_type TEXT, body TEXT,
                prompt_version TEXT, created_at TEXT, last_served_at TEXT, served_count INTEGER DEFAULT 0
            )'
        );
        $db->exec('CREATE TABLE IF NOT EXISTS llm_inflight (cache_key TEXT PRIMARY KEY, started_at TEXT)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_llm_cache_lru ON llm_cache(last_served_at)');

        return $this->db = $db;
    }
}
