<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Normalized view of one nuclei template's FIRST http request, as consumed by the
 * compiler. Only the fields the inverter needs are lifted out of the raw YAML.
 *
 * Nuclei clusters (and we route) on a single request per template. `requestCount`
 * and the raw eligibility signals let Gate A reject multi-step / non-clusterable
 * templates before any matcher work.
 */
final class LoadedTemplate
{
    /**
     * @param string[]              $tags
     * @param string[]              $paths            raw path strings incl. {{BaseURL}} prefix
     * @param array<int,mixed>      $matchers         raw matcher blocks (assoc arrays)
     * @param array<string,mixed>   $eligibilitySignals raw first-request keys used by Gate A
     *                                                 (raw/payloads/body/fuzzing/unsafe/name/req-condition)
     */
    public function __construct(
        public string $id,
        public string $severity,
        public array $tags,
        public string $product,
        public string $name,
        public string $method,
        public array $paths,
        public array $matchers,
        public string $matchersCondition,
        public int $requestCount,
        public bool $hasFlow,
        public array $eligibilitySignals,
        public string $rawText
    ) {
    }
}
