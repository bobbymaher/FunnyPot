<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

/**
 * Per-IP velocity gate (Gate A, see docs/LLM-HONEYPOT-RESEARCH.md) — the load-bearing defence.
 *
 * A content-discovery tool (ffuf, gobuster, feroxbuster) sweeps many distinct paths in seconds; a
 * genuine targeted probe does not. So an IP that has probed too many distinct paths in a short
 * window is flagged bulk-scanning and pinned to the plain 404, regardless of how plausible any
 * single path looks. This is what stops a wordlist full of real-looking words (admin, wp-login)
 * from each getting a rich LLM fake and unmasking the honeypot statistically.
 *
 * It only applies thresholds; the counts come from {@see \Funnypot\App\Storage\HitStore::probeVelocity()}.
 */
final class VelocityTracker
{
    /**
     * @param int $per60s distinct paths in 60s that flags an IP as bulk-scanning
     * @param int $per10m distinct paths in 10min that flags an IP as bulk-scanning
     */
    public function __construct(private int $per60s = 5, private int $per10m = 15)
    {
    }

    /** @param array{recent:int,extended:int} $velocity from HitStore::probeVelocity() */
    public function isBulkScan(array $velocity): bool
    {
        return ($velocity['recent'] ?? 0) >= $this->per60s
            || ($velocity['extended'] ?? 0) >= $this->per10m;
    }
}
