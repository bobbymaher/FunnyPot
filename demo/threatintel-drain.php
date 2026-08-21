<?php

declare(strict_types=1);

/**
 * Send queued Threat Intel reports to our own funnypot-mainnet service (POST /v1/report). The
 * request/connection paths only enqueue (a fast local write); this worker does the actual HTTP POSTs
 * on a timer. No-op unless reporting is enabled + keyed. Fail-silent — a service outage never escapes.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;

$config = AppConfig::fromEnv(__DIR__);
if (!$config->threatIntelReport || $config->threatIntelKey === '') {
    exit(0);
}

try {
    $result = (new ThreatIntelReporter(
        $config->threatIntelUrl,
        $config->threatIntelKey,
        $config->intelDbPath,
        $config->selfIps,
        $config->threatIntelDailyCap,
        $config->threatIntelDedupHours
    ))->drain();
    if ($result['sent'] > 0 || $result['failed'] > 0) {
        fwrite(STDERR, sprintf("threatintel: sent %d, failed %d, pending %d\n", $result['sent'], $result['failed'], $result['pending']));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'threatintel: ' . $e->getMessage() . "\n");
}
