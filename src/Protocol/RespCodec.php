<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Redis RESP framing. A client request is either an inline command (`PING\r\n`) or an array of
 * bulk strings (`*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n`); either way `extract()` yields the command
 * with its arguments joined by a space, so a rule matches on "AUTH foo" / "CONFIG GET dir".
 *
 * `wrap()` frames the author's semantic reply:
 *   "+PONG\r\n" (verbatim) · {simple: s} → +s · {error: s} → -s
 *   {bulk: s} → $len\r\n s \r\n · {bulk_array: [a,b]} → *N\r\n $..\r\n a \r\n ...
 */
final class RespCodec implements Codec
{
    /** Refuse absurd array counts — a malicious `*99999999` must not allocate. */
    private const MAX_ARGS = 1024;

    public function extract(string &$buffer): array
    {
        $out = [];
        while ($buffer !== '') {
            $work = $buffer;
            $req = $this->parseOne($work);
            if ($req === null) {
                break; // incomplete frame — leave $buffer untouched, wait for more bytes
            }
            $buffer = $work;
            $out[] = $req;
        }

        return $out;
    }

    private function parseOne(string &$buffer): ?string
    {
        if ($buffer[0] !== '*') {
            $nl = strpos($buffer, "\n");
            if ($nl === false) {
                return null;
            }
            $line = rtrim(substr($buffer, 0, $nl), "\r");
            $buffer = substr($buffer, $nl + 1);

            return $line;
        }

        $nl = strpos($buffer, "\r\n");
        if ($nl === false) {
            return null;
        }
        $n = (int) substr($buffer, 1, $nl - 1);
        if ($n < 0 || $n > self::MAX_ARGS) {
            // treat the bogus header line as consumed garbage; return it inert
            $buffer = substr($buffer, $nl + 2);

            return '';
        }
        $rest = substr($buffer, $nl + 2);
        $args = [];
        for ($i = 0; $i < $n; $i++) {
            if ($rest === '' || $rest[0] !== '$') {
                return null;
            }
            $nl2 = strpos($rest, "\r\n");
            if ($nl2 === false) {
                return null;
            }
            $len = (int) substr($rest, 1, $nl2 - 1);
            $rest = substr($rest, $nl2 + 2);
            if ($len < 0 || strlen($rest) < $len + 2) {
                return null; // need the payload + its trailing CRLF
            }
            $args[] = substr($rest, 0, $len);
            $rest = substr($rest, $len + 2);
        }
        $buffer = $rest;

        return implode(' ', $args);
    }

    /** @param string|array<string,mixed> $send */
    public function wrap($send): string
    {
        if (!is_array($send)) {
            return (string) $send;
        }
        if (isset($send['simple'])) {
            return '+' . (string) $send['simple'] . "\r\n";
        }
        if (isset($send['error'])) {
            return '-' . (string) $send['error'] . "\r\n";
        }
        if (isset($send['bulk'])) {
            $s = (string) $send['bulk'];

            return '$' . strlen($s) . "\r\n" . $s . "\r\n";
        }
        if (isset($send['bulk_array'])) {
            $items = (array) $send['bulk_array'];
            $out = '*' . count($items) . "\r\n";
            foreach ($items as $item) {
                $s = (string) $item;
                $out .= '$' . strlen($s) . "\r\n" . $s . "\r\n";
            }

            return $out;
        }

        return (string) ($send['raw'] ?? '');
    }
}
