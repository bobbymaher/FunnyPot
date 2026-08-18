<?php

declare(strict_types=1);

/**
 * Periodic retention. Prunes the hit store by age (FUNNYPOT_RETAIN_DAYS) and/or on-disk size
 * (FUNNYPOT_RETAIN_GB). Both unset = unbounded, a no-op. The entrypoint runs this on a timer.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;

$config = AppConfig::fromEnv(__DIR__);

// LLM cache upkeep runs whenever the responder is on: cap the cache by size (0 = unbounded) and
// reap in-flight locks a crashed generation would otherwise leave held. Independent of hit retention.
if ($config->llmEnabled && is_file($config->llmCacheDb)) {
    try {
        $cache = new LlmFakeCache($config->llmCacheDb);
        $stale = $cache->reapInflight();
        $evicted = $config->llmCacheMaxBytes > 0 ? $cache->retainBytes($config->llmCacheMaxBytes) : 0;
        if ($stale > 0 || $evicted > 0) {
            fwrite(STDERR, sprintf("retention: llm cache reaped %d locks, evicted %d entries\n", $stale, $evicted));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'retention (llm): ' . $e->getMessage() . "\n");
    }
}

if ($config->retainDays <= 0 && $config->retainGb <= 0) {
    exit(0); // hit store unbounded: nothing more to do
}

try {
    $store = new SqliteHitStore($config->dbPath);
    $byAge = $config->retainDays > 0 ? $store->retainDays($config->retainDays) : 0;
    $bySize = $config->retainGb > 0 ? $store->retainBytes((int) round($config->retainGb * 1024 * 1024 * 1024)) : 0;
    if ($byAge > 0 || $bySize > 0) {
        fwrite(STDERR, sprintf("retention: pruned %d by age + %d by size\n", $byAge, $bySize));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'retention: ' . $e->getMessage() . "\n");
}
