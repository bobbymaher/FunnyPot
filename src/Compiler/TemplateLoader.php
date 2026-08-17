<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Parses a nuclei template YAML file into a {@see LoadedTemplate}.
 *
 * Nuclei's clustering (and our routing) operates on a single request, so only the
 * FIRST http request block is lifted; `requestCount` records the rest so Gate A can
 * reject multi-step templates. symfony/yaml is a compile-time-only dependency.
 */
final class TemplateLoader
{
    /** Some detection megatemplates have thousands of nested nodes. */
    private const YAML_FLAGS = 0;

    public function loadFile(string $path): LoadedTemplate
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new RuntimeException("Cannot read template: {$path}");
        }

        try {
            $doc = Yaml::parse($raw, self::YAML_FLAGS);
        } catch (\Throwable $e) {
            throw new RuntimeException("YAML parse failed for {$path}: " . $e->getMessage(), 0, $e);
        }

        if (!is_array($doc)) {
            throw new RuntimeException("Template is not a mapping: {$path}");
        }

        return $this->fromArray($doc, $raw, $path);
    }

    /**
     * @param array<string,mixed> $doc
     */
    public function fromArray(array $doc, string $rawText, string $path): LoadedTemplate
    {
        $id = (string) ($doc['id'] ?? '');
        if ($id === '') {
            // Fall back to the filename stem so provenance is never empty.
            $id = pathinfo($path, PATHINFO_FILENAME);
        }

        $info = is_array($doc['info'] ?? null) ? $doc['info'] : [];
        $severity = strtolower((string) ($info['severity'] ?? 'unknown'));
        $name = (string) ($info['name'] ?? '');

        $tags = $this->normalizeTags($info['tags'] ?? []);

        $metadata = is_array($info['metadata'] ?? null) ? $info['metadata'] : [];
        $product = strtolower(trim((string) ($metadata['product'] ?? '')));

        // http (current) or requests (legacy) key.
        $http = $doc['http'] ?? $doc['requests'] ?? [];
        if (!is_array($http)) {
            $http = [];
        }
        $requestCount = count($http);

        $req = $http[0] ?? [];
        if (!is_array($req)) {
            $req = [];
        }

        $method = strtoupper((string) ($req['method'] ?? 'GET'));

        $paths = $req['path'] ?? [];
        if (is_string($paths)) {
            $paths = [$paths];
        }
        $paths = array_values(array_filter(
            array_map(static fn ($p): string => (string) $p, (array) $paths),
            static fn (string $p): bool => $p !== ''
        ));

        $matchers = $req['matchers'] ?? [];
        if (!is_array($matchers)) {
            $matchers = [];
        }

        $matchersCondition = strtolower((string) ($req['matchers-condition'] ?? ''));

        $eligibility = [
            'raw' => $req['raw'] ?? null,
            'payloads' => $req['payloads'] ?? null,
            'body' => $req['body'] ?? null,
            'fuzzing' => $req['fuzzing'] ?? null,
            'unsafe' => $req['unsafe'] ?? null,
            'name' => $req['name'] ?? null,
            'req-condition' => $req['req-condition'] ?? null,
        ];

        return new LoadedTemplate(
            $id,
            $severity,
            $tags,
            $product,
            $name,
            $method,
            $paths,
            $matchers,
            $matchersCondition,
            $requestCount,
            isset($doc['flow']),
            $eligibility,
            $rawText
        );
    }

    /**
     * Tags are authored either as a comma-joined string or a YAML list.
     *
     * @param mixed $tags
     * @return string[]
     */
    private function normalizeTags($tags): array
    {
        if (is_string($tags)) {
            $tags = explode(',', $tags);
        }
        if (!is_array($tags)) {
            return [];
        }

        $out = [];
        foreach ($tags as $t) {
            $t = strtolower(trim((string) $t));
            if ($t !== '') {
                $out[] = $t;
            }
        }

        return array_values(array_unique($out));
    }
}
