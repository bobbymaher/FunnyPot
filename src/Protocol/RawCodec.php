<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * No framing — the whole current buffer is handed to the rules as one request (for bespoke
 * banner/probe services where there is no line/record structure). The buffer is consumed each
 * time so it never grows unbounded.
 */
final class RawCodec implements Codec
{
    public function extract(string &$buffer): array
    {
        if ($buffer === '') {
            return [];
        }
        $req = $buffer;
        $buffer = '';

        return [$req];
    }

    /** @param string|array<string,mixed> $send */
    public function wrap($send): string
    {
        return is_array($send) ? (string) ($send['raw'] ?? '') : (string) $send;
    }
}
