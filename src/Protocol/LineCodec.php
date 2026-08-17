<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * CRLF/LF line framing — telnet, FTP control, SMTP, POP3, memcached (text), redis inline.
 * Each complete line (trailing CR/LF stripped) is one request. The response `send` is written
 * verbatim by the author (including its own line endings).
 */
final class LineCodec implements Codec
{
    public function extract(string &$buffer): array
    {
        $out = [];
        while (($nl = strpos($buffer, "\n")) !== false) {
            $line = substr($buffer, 0, $nl);
            $buffer = substr($buffer, $nl + 1);
            $out[] = rtrim($line, "\r");
        }

        return $out;
    }

    /** @param string|array<string,mixed> $send */
    public function wrap($send): string
    {
        return is_array($send) ? (string) ($send['raw'] ?? '') : (string) $send;
    }
}
