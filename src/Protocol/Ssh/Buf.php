<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * Builder for the SSH binary wire types (RFC 4251 §5): byte, boolean, uint32, string
 * (uint32 length + bytes), mpint (signed multiple-precision integer) and name-list. Fluent;
 * `get()` returns the assembled bytes. Used to compose packet payloads and the exchange-hash
 * input. Read the same types back with {@see Reader}.
 */
final class Buf
{
    private string $b = '';

    public function byte(int $n): self
    {
        $this->b .= chr($n & 0xff);

        return $this;
    }

    public function bool(bool $v): self
    {
        $this->b .= $v ? "\x01" : "\x00";

        return $this;
    }

    public function uint32(int $n): self
    {
        $this->b .= pack('N', $n);

        return $this;
    }

    public function string(string $s): self
    {
        $this->b .= pack('N', strlen($s)) . $s;

        return $this;
    }

    /** @param string[] $names */
    public function nameList(array $names): self
    {
        return $this->string(implode(',', $names));
    }

    /**
     * Encode a big-endian unsigned integer (raw bytes) as an SSH mpint: leading zero bytes are
     * dropped, and a 0x00 is prepended when the top bit is set so the value stays positive.
     */
    public function mpint(string $magnitude): self
    {
        $magnitude = ltrim($magnitude, "\x00");
        if ($magnitude === '') {
            return $this->string('');
        }
        if (ord($magnitude[0]) & 0x80) {
            $magnitude = "\x00" . $magnitude;
        }

        return $this->string($magnitude);
    }

    public function raw(string $s): self
    {
        $this->b .= $s;

        return $this;
    }

    public function get(): string
    {
        return $this->b;
    }

    /** The mpint encoding (length prefix + bytes) of a raw big-endian magnitude, standalone. */
    public static function mpintOf(string $magnitude): string
    {
        return (new self())->mpint($magnitude)->get();
    }

    /** The string encoding (uint32 length + bytes) of a value, standalone. */
    public static function stringOf(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }
}
