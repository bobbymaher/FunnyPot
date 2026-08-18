<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use PDO;
use Throwable;

/**
 * A tiny SQLite-backed circuit breaker so a dead/slow sidecar does not add timeout-latency to every
 * unmatched request. N consecutive failures open it for a cooldown; while open, the client skips the
 * socket call entirely. SQLite-backed (not in-process) so the state is shared across php-fpm workers.
 * Fails open (allow) if its own store is unreadable — the breaker must never be the thing that breaks.
 */
final class CircuitBreaker
{
    private ?PDO $db = null;

    public function __construct(
        private string $dbPath,
        private int $threshold = 5,
        private int $cooldownSecs = 30,
    ) {
    }

    /** False while the breaker is open (recent failures tripped it). */
    public function allow(): bool
    {
        try {
            $st = $this->db()->prepare("SELECT until FROM breaker WHERE k = 'llm'");
            $st->execute();
            $until = $st->fetchColumn();

            return $until === false || (strtotime((string) $until) ?: 0) <= time();
        } catch (Throwable $e) {
            return true;   // fail open
        }
    }

    public function recordSuccess(): void
    {
        $this->set(0, '');
    }

    public function recordFailure(): void
    {
        try {
            $st = $this->db()->prepare("SELECT failures FROM breaker WHERE k = 'llm'");
            $st->execute();
            $failures = (int) ($st->fetchColumn() ?: 0) + 1;
            if ($failures >= $this->threshold) {
                $this->set(0, gmdate('c', time() + $this->cooldownSecs));   // open the breaker, reset the count
            } else {
                $this->set($failures, '');
            }
        } catch (Throwable $e) {
            // best-effort
        }
    }

    private function set(int $failures, string $until): void
    {
        try {
            $this->db()->prepare("INSERT OR REPLACE INTO breaker (k, failures, until) VALUES ('llm', :f, :u)")
                ->execute([':f' => $failures, ':u' => $until]);
        } catch (Throwable $e) {
            // best-effort
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
        $db->exec('CREATE TABLE IF NOT EXISTS breaker (k TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, until TEXT NOT NULL DEFAULT \'\')');

        return $this->db = $db;
    }
}
