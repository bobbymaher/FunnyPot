<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Funnypot\App\Storage\HitStore;

/**
 * The LLM decision gate: both checks AND'd, default-deny. Invoke the model only when the IP is not
 * bulk-scanning (Gate A) AND the path is positively a plausible app path (Gate B). Everything else
 * gets the existing byte-identical plain 404.
 *
 * Gate A has two layers: a persistent pin (an IP that tripped the velocity window stays blocked for
 * a cooldown even after it goes quiet, so it cannot burst then slow-probe) and the live sliding
 * window that trips the pin.
 */
final class ProbeGate
{
    /**
     * @param int $pinHours how long a tripped IP stays pinned to plain-404 (the bulk-scan cooldown)
     */
    public function __construct(
        private ProbeClassifier $lexical,
        private VelocityTracker $velocity,
        private HitStore $store,
        private int $pinHours = 24,
    ) {
    }

    /**
     * @return array{generate:bool,reason:string} reason is logged so the gate can be tuned on real traffic
     */
    public function decide(string $method, string $path, string $ip): array
    {
        if ($this->store->isBulkFlagged($ip)) {
            return ['generate' => false, 'reason' => 'bulk-scan-pinned'];
        }
        if ($this->velocity->isBulkScan($this->store->probeVelocity($ip))) {
            $this->store->flagBulkScan($ip, $this->pinHours);      // pin so a quiet-then-probe cannot dodge it
            return ['generate' => false, 'reason' => 'bulk-scan'];
        }
        if ($this->lexical->classify($method, $path) !== 'plausible') {
            return ['generate' => false, 'reason' => 'probe'];
        }

        return ['generate' => true, 'reason' => 'plausible'];
    }
}
