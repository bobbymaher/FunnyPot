<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * The SSH binary packet protocol (RFC 4253 §6) for one connection: framing, padding, and — once
 * keys are installed — aes-ctr encryption with an hmac-sha2-256 MAC computed over the sequence
 * number and the plaintext packet ("encrypt-and-MAC"). Send and receive run independently, each
 * with its own cipher, MAC key and monotonic sequence number that spans the plaintext KEX packets
 * and continues into the encrypted stream.
 *
 * `frame()` builds an outbound packet from a payload; `next()` pulls one inbound payload from the
 * running buffer, returning null when more bytes are needed. The MAC length field is encrypted, so
 * a decrypt of the first block (cached) reveals the packet length before the rest has arrived.
 */
final class Transport
{
    private const MAX_PACKET = 35000; // guard against absurd length fields

    private int $outSeq = 0;
    private int $inSeq = 0;

    private bool $sendSecure = false;
    private bool $recvSecure = false;
    private ?Ctr $sendCtr = null;
    private ?Ctr $recvCtr = null;
    private string $macKeyOut = '';
    private string $macKeyIn = '';

    // Cached decrypt of an inbound packet's first block, held until the whole packet arrives.
    private ?int $pktLen = null;
    private ?string $firstBlock = null;

    /** Build the wire bytes for one outbound packet carrying $payload. */
    public function frame(string $payload): string
    {
        $block = $this->sendSecure ? 16 : 8;
        $unpadded = 4 + 1 + strlen($payload);      // length field + padding-length field + payload
        $pad = $block - ($unpadded % $block);
        if ($pad < 4) {
            $pad += $block;
        }
        $packetLen = 1 + strlen($payload) + $pad;
        $plain = pack('N', $packetLen) . chr($pad) . $payload . random_bytes($pad);

        if ($this->sendSecure && $this->sendCtr !== null) {
            $mac = hash_hmac('sha256', pack('N', $this->outSeq) . $plain, $this->macKeyOut, true);
            $wire = $this->sendCtr->crypt($plain) . $mac;
        } else {
            $wire = $plain;
        }
        $this->outSeq = ($this->outSeq + 1) & 0xffffffff;

        return $wire;
    }

    /**
     * Pull one inbound packet payload from $buffer (consuming its bytes), or return null if the
     * buffer does not yet hold a complete packet. Throws on a malformed packet or bad MAC.
     */
    public function next(string &$buffer): ?string
    {
        return $this->recvSecure ? $this->nextSecure($buffer) : $this->nextPlain($buffer);
    }

    private function nextPlain(string &$buffer): ?string
    {
        if (strlen($buffer) < 4) {
            return null;
        }
        /** @var array{1:int} $u */
        $u = unpack('N', substr($buffer, 0, 4));
        $packetLen = $u[1];
        if ($packetLen < 5 || $packetLen > self::MAX_PACKET) {
            throw new \RuntimeException('ssh: bad packet length');
        }
        $total = 4 + $packetLen;
        if (strlen($buffer) < $total) {
            return null;
        }
        $plain = substr($buffer, 0, $total);
        $buffer = substr($buffer, $total);
        $this->inSeq = ($this->inSeq + 1) & 0xffffffff;

        return $this->payloadOf($plain, $packetLen);
    }

    private function nextSecure(string &$buffer): ?string
    {
        if ($this->pktLen === null) {
            if (strlen($buffer) < 16 || $this->recvCtr === null) {
                return null;
            }
            $this->firstBlock = $this->recvCtr->crypt(substr($buffer, 0, 16));
            /** @var array{1:int} $u */
            $u = unpack('N', substr($this->firstBlock, 0, 4));
            $this->pktLen = $u[1];
            if ($this->pktLen < 5 || $this->pktLen > self::MAX_PACKET || (4 + $this->pktLen) % 16 !== 0) {
                throw new \RuntimeException('ssh: bad encrypted packet length');
            }
        }
        $total = 4 + $this->pktLen;          // ciphertext length (block-aligned)
        if (strlen($buffer) < $total + 32) { // + MAC
            return null;
        }
        $rest = substr($buffer, 16, $total - 16);
        /** @var Ctr $ctr */
        $ctr = $this->recvCtr;
        $plain = $this->firstBlock . ($rest === '' ? '' : $ctr->crypt($rest));
        $mac = substr($buffer, $total, 32);
        $calc = hash_hmac('sha256', pack('N', $this->inSeq) . $plain, $this->macKeyIn, true);
        if (!hash_equals($calc, $mac)) {
            throw new \RuntimeException('ssh: MAC verification failed');
        }
        $packetLen = $this->pktLen;
        $buffer = substr($buffer, $total + 32);
        $this->pktLen = null;
        $this->firstBlock = null;
        $this->inSeq = ($this->inSeq + 1) & 0xffffffff;

        return $this->payloadOf($plain, $packetLen);
    }

    private function payloadOf(string $plain, int $packetLen): string
    {
        $pad = ord($plain[4]);
        $payloadLen = $packetLen - 1 - $pad;
        if ($payloadLen < 0) {
            throw new \RuntimeException('ssh: bad padding');
        }

        return substr($plain, 5, $payloadLen);
    }

    /** Install the server→client keys; subsequent frames are encrypted. */
    public function enableSend(string $key, string $iv, string $macKey): void
    {
        $this->sendCtr = new Ctr($key, $iv);
        $this->macKeyOut = $macKey;
        $this->sendSecure = true;
    }

    /** Install the client→server keys; subsequent packets are decrypted. */
    public function enableRecv(string $key, string $iv, string $macKey): void
    {
        $this->recvCtr = new Ctr($key, $iv);
        $this->macKeyIn = $macKey;
        $this->recvSecure = true;
    }
}
