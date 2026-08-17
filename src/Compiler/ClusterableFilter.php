<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Gate A — request eligibility.
 *
 * Inverts nuclei's own `IsClusterable()` (cluster.go): a request is clusterable iff
 * NOT(payloads || fuzzing || raw || body || unsafe || req-condition || name). Nuclei
 * only clusters simple single-shot path requests with declarative matchers, so that
 * gate doubles as our invertibility pre-filter.
 *
 * We add the exclusions nuclei has no reason to make but we must:
 *   - interactsh/OOB: the scanner waits for a callback to ITS OWN collaborator; we can
 *     never satisfy it, so any interactsh reference is unfakeable.
 *   - xpath-only: matching needs a real DOM/XML query engine at match time; out of scope.
 *   - variable-path: a path with an unresolved {{...}} (other than {{BaseURL}}/{{RootURL}})
 *     is per-target or fuzz-driven and cannot be pinned to a compile-time route key.
 *   - multi-request / flow: only the first request is routed; later-step matchers
 *     (body_2, status_code_2, …) can never be satisfied by our single response.
 *
 * Each rejection returns a stable reason string (for skipped.json); accept() returns null.
 */
final class ClusterableFilter
{
    public function reject(LoadedTemplate $t): ?string
    {
        // --- inverse of IsClusterable() ---
        $sig = $t->eligibilitySignals;
        if (!empty($sig['payloads'])) {
            return 'gateA:payloads';
        }
        if (!empty($sig['fuzzing'])) {
            return 'gateA:fuzzing';
        }
        if (!empty($sig['raw'])) {
            return 'gateA:raw';
        }
        if (!empty($sig['body'])) {
            return 'gateA:body';
        }
        if (!empty($sig['unsafe'])) {
            return 'gateA:unsafe';
        }
        if (isset($sig['req-condition']) && $sig['req-condition'] !== null && $sig['req-condition'] !== false) {
            return 'gateA:req-condition';
        }
        if (!empty($sig['name'])) {
            return 'gateA:request-name';
        }

        // --- our additions ---
        if ($t->hasFlow || $t->requestCount > 1) {
            return 'gateA:multi-request';
        }

        if ($t->paths === []) {
            return 'gateA:no-path';
        }

        if ($t->matchers === []) {
            return 'gateA:no-matchers';
        }

        if ($this->usesInteractsh($t)) {
            return 'gateA:interactsh-oob';
        }

        if ($this->isXpathOnly($t)) {
            return 'gateA:xpath-only';
        }

        // Every path must reduce to a compile-time-fixed request target.
        foreach ($t->paths as $p) {
            $reason = $this->pathReason($p);
            if ($reason !== null) {
                return $reason;
            }
        }

        return null;
    }

    /**
     * Reduce a template path to the request-target after {{BaseURL}}, or null if it
     * is not a fixed BaseURL-relative path. Shared with the compiler so route keys and
     * this gate agree byte-for-byte.
     */
    public static function pathTarget(string $path): ?string
    {
        $p = trim($path);

        // Strip a single leading {{BaseURL}} / {{RootURL}} (case-insensitive, tolerant
        // of inner whitespace) — everything after it is the literal request target.
        if (!preg_match('/^\{\{\s*(?:BaseURL|RootURL)\s*\}\}(.*)$/s', $p, $m)) {
            return null; // absolute URL, {{Host}}/{{Hostname}} relative, or bare literal
        }
        $rest = $m[1];

        // Route key ignores the query string (recorded elsewhere as a discriminator).
        $qpos = strpos($rest, '?');
        if ($qpos !== false) {
            $rest = substr($rest, 0, $qpos);
        }

        // A variable surviving in the PATH portion cannot be pinned at compile time.
        if (strpos($rest, '{{') !== false) {
            return null;
        }

        return $rest;
    }

    private function pathReason(string $path): ?string
    {
        // Distinguish "has a variable in the path" from "not BaseURL-relative" so the
        // audit can tell the two apart.
        $p = trim($path);
        if (!preg_match('/^\{\{\s*(?:BaseURL|RootURL)\s*\}\}/', $p)) {
            return 'gateA:non-baseurl-path';
        }
        if (self::pathTarget($path) === null) {
            return 'gateA:variable-path';
        }

        return null;
    }

    private function usesInteractsh(LoadedTemplate $t): bool
    {
        // Cheap whole-text scan first: covers {{interactsh-url}} in path/body/headers,
        // interactsh_protocol parts, oast dsl, etc.
        if (stripos($t->rawText, 'interactsh') !== false) {
            return true;
        }

        foreach ($t->matchers as $m) {
            if (!is_array($m)) {
                continue;
            }
            $part = strtolower((string) ($m['part'] ?? ''));
            if (strncmp($part, 'interactsh', 10) === 0) {
                return true;
            }
        }

        return false;
    }

    private function isXpathOnly(LoadedTemplate $t): bool
    {
        $any = false;
        foreach ($t->matchers as $m) {
            if (!is_array($m)) {
                continue;
            }
            $any = true;
            if (($m['type'] ?? '') !== 'xpath') {
                return false;
            }
        }

        return $any;
    }
}
