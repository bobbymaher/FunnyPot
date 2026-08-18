<?php

declare(strict_types=1);

/**
 * Periodic retention. Prunes the hit store by age (FUNNYPOT_RETAIN_DAYS) and/or on-disk size
 * (FUNNYPOT_RETAIN_GB). Both unset = unbounded, a no-op. The entrypoint runs this on a timer.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\SqliteHitStore;

$config = AppConfig::fromEnv(__DIR__);
if ($config->retainDays <= 0 && $config->retainGb <= 0) {
    exit(0); // unbounded: nothing to do
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
