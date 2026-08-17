<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * A wire codec: it owns how a protocol's byte stream is FRAMED, in both directions, so the
 * template author writes the semantic request/response and never the framing. `extract()`
 * pulls complete logical requests out of the inbound buffer (consuming them, leaving partial
 * data buffered); `wrap()` turns a template's `send` spec into the exact response bytes.
 *
 * A codec only frames bytes. It never executes anything and never reflects unbounded input.
 */
interface Codec
{
    /**
     * Consume complete requests from $buffer (passed by reference), returning each as a plain
     * string the rule matcher compares against. Partial trailing data stays in $buffer.
     *
     * @return string[]
     */
    public function extract(string &$buffer): array;

    /**
     * Frame an outbound response. $send is either a raw byte string, or a spec array the codec
     * understands (e.g. ['bulk' => "..."], ['bulk_array' => [...]] for RESP). Text fields are
     * already directive-rendered by the emulator; the codec only adds wire framing.
     *
     * @param string|array<string,mixed> $send
     */
    public function wrap($send): string;
}
