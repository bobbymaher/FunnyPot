<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

/**
 * Treats LLM output as hostile. The GBNF grammar constrains structure, but not semantics, so every
 * generated body is validated here before it can be served. Returns null on ANY violation, which the
 * responder treats identically to a generation failure: fall through to the plain 404. Never
 * truncates (a truncated HTML body is malformed, and malformed is its own tell) and never executes
 * the string — it only ever reaches output as a response body.
 */
final class LlmOutputSanitizer
{
    /** Tags that must never appear (active content / redirect-y / structural injection). */
    private const BAD_TAGS = ['<script', '<iframe', '<object', '<embed', '<link', '<style', '<base', '<meta http-equiv'];

    /** Exploit-shaped substrings that a fake page never legitimately contains. */
    private const BAD_SUBSTRINGS = [
        '<?php', '<?=', '#!/bin/', 'eval(', 'base64_decode(', 'system(', 'exec(', 'passthru(',
        'proc_open(', 'shell_exec(', '-----begin', '../../', '..\\..\\',
    ];

    /** @return string|null the validated body, or null on any violation */
    public function sanitize(string $raw, int $maxBytes = 8192): ?string
    {
        $s = trim($raw);
        $len = strlen($s);

        // Realistic size band: reject a 12-byte "login page" and an oversized dump alike.
        if ($len < 32 || $len > $maxBytes) {
            return null;
        }
        // Must be markup from the first byte: no "Sure! ", no ```html fence, no refusal sentence.
        if ($s[0] !== '<') {
            return null;
        }
        if (!mb_check_encoding($s, 'UTF-8')) {
            return null;
        }
        // No control bytes (a real HTML page has none); tab / newline / carriage-return are allowed.
        if (preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $s) === 1) {
            return null;
        }

        $low = strtolower($s);
        foreach (self::BAD_TAGS as $tag) {
            if (strpos($low, $tag) !== false) {
                return null;
            }
        }
        // Event-handler attributes (onload, onerror, onclick, ...).
        if (preg_match('/\son[a-z]+\s*=/i', $s) === 1) {
            return null;
        }
        // Absolute / external URLs in link-bearing attributes or CSS url() — no off-site beacon/SSRF.
        if (preg_match('#(href|src|action)\s*=\s*["\\\']?\s*(https?:)?//#i', $s) === 1) {
            return null;
        }
        if (preg_match('#url\(\s*["\\\']?\s*(https?:)?//#i', $s) === 1) {
            return null;
        }
        foreach (self::BAD_SUBSTRINGS as $bad) {
            if (strpos($low, $bad) !== false) {
                return null;
            }
        }

        return $s;
    }
}
