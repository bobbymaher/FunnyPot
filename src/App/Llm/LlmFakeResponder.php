<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\Detection;
use Funnypot\RequestContext;
use Funnypot\Support\PathNormalizer;
use Funnypot\SynthesizedResponse;

/**
 * Orchestrates an LLM-generated fake for a request the engine could not match. Cache first (the
 * common, cheap case), then the gate, then a single-flight generation, sanitize, cache, and build a
 * response. Every decline or failure returns null, which the controller turns into the unchanged
 * plain 404 — the feature is purely additive and can only ever upgrade a 404 into a convincing fake.
 *
 * Status and Content-Type are app-chosen (never model-chosen): no 3xx, so a hallucinated Location
 * can never make the honeypot an open redirect.
 */
final class LlmFakeResponder
{
    public function __construct(
        private ProbeGate $gate,
        private LlmFakeCache $cache,
        private LlmClient $client,
        private LlmOutputSanitizer $sanitizer,
        private HitStore $store,
        private LlmPromptBuilder $prompt,
        private string $grammar,
        private string $promptVersion = 'v1',
        private int $maxConcurrent = 4,
    ) {
    }

    public function respond(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        // Invariant: this feature can only ever upgrade a 404. Any fault anywhere below — a store
        // error in the gate, a bad prepared statement, anything — must degrade to null (the plain
        // 404), never escape as a 500 that a scanner could use to tell the honeypot apart.
        try {
            $response = $this->attempt($context, $clientIp);
        } catch (\Throwable $e) {
            return null;
        }

        // Log every served fake (cache hit or fresh) with the exact body the attacker got, so the
        // operator can see what the model returned. Logging must never suppress a valid response.
        if ($response !== null) {
            try {
                $this->logServed($context, $clientIp, $response);
            } catch (\Throwable $e) {
                // best-effort
            }
        }

        return $response;
    }

    private function attempt(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        $key = PathNormalizer::key($context->method, $context->path);

        // 1. Cache hit — the common case, served byte-identical, no model call, no gate query.
        $hit = $this->cache->get($key, $this->promptVersion);
        if ($hit !== null) {
            return $this->build($hit['status'], $hit['body']);
        }

        // 2. Gate (only paid on a cache miss). Sheds the probe/scan 404s before they can consume a
        //    generation slot, so the cap below is only ever spent on genuinely plausible paths.
        if (!$this->gate->decide($context->method, $context->path, $clientIp)['generate']) {
            return null;
        }

        // 3. Atomic single-flight + concurrency cap. Over the cap (FULL) goes straight to the plain
        //    404 — never queued. A peer already generating this same path (BUSY) waits briefly for
        //    its result, then also falls back. Only the winner (WON) actually calls the model.
        $lock = $this->cache->acquire($key, $this->maxConcurrent);
        if ($lock === LlmFakeCache::ACQUIRE_FULL) {
            return null;
        }
        if ($lock === LlmFakeCache::ACQUIRE_BUSY) {
            $peer = $this->cache->awaitOther($key, $this->promptVersion);

            return $peer !== null ? $this->build($peer['status'], $peer['body']) : null;
        }

        try {
            $raw = $this->client->generate($this->prompt->build($context->method, $context->path), $this->grammar);
            if ($raw === null) {
                return null;                                  // failure is never cached
            }
            $body = $this->sanitizer->sanitize($raw);
            if ($body === null) {
                return null;
            }
            $status = $this->chooseStatus($context->path);
            $this->cache->put($key, $status, 'text/html; charset=utf-8', $body, $this->promptVersion);

            return $this->build($status, $body);
        } finally {
            $this->cache->release($key);
        }
    }

    private function build(int $status, string $body): SynthesizedResponse
    {
        return new SynthesizedResponse($status, ['Content-Type' => 'text/html; charset=utf-8'], $body, Detection::none());
    }

    /** App-chosen status (never the model's). Bias auth-looking paths to 401 so not every plausible
     *  path returns a 200 (that itself is a fingerprint under distributed probing). */
    private function chooseStatus(string $path): int
    {
        $p = strtolower($path);
        foreach (['admin', 'manage', 'console', 'secure', 'private', 'internal', 'dashboard', 'actuator'] as $auth) {
            if (strpos($p, $auth) !== false) {
                return 401;
            }
        }

        return 200;
    }

    private function logServed(RequestContext $context, string $clientIp, SynthesizedResponse $response): void
    {
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => $context->method,
            'path' => substr($context->path, 0, 200),
            'event' => 'llm-fake',
            'matched' => true,
            'severity' => 'info',
            'served' => true,
            'templates' => ['llm-fake'],
            // The exact HTML the attacker received, so the operator can review what the model wrote.
            // The store escapes non-printable bytes; the dashboard must render this as text, not HTML.
            'body' => $response->body,
        ]);
    }
}
