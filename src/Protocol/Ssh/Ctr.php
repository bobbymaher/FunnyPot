<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * Streaming AES-CTR keystream, the transport cipher for aes128-ctr / aes256-ctr. PHP's one-shot
 * openssl_encrypt cannot carry counter state across packets, so CTR is built by hand: the block
 * cipher runs in ECB to encrypt each 128-bit counter block, and the keystream is XORed with the
 * data. The counter persists between calls, so successive SSH packets stay in step. SSH packets
 * are always block-aligned, so no partial keystream block is ever left dangling.
 *
 * Encryption and decryption are the same operation (XOR), so one class serves both directions.
 */
final class Ctr
{
    private string $method;

    public function __construct(private string $key, private string $counter)
    {
        $this->method = strlen($key) === 32 ? 'aes-256-ecb' : 'aes-128-ecb';
    }

    public function crypt(string $data): string
    {
        $out = '';
        $len = strlen($data);
        for ($off = 0; $off < $len; $off += 16) {
            $keystream = openssl_encrypt(
                $this->counter,
                $this->method,
                $this->key,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                ''
            );
            if ($keystream === false) {
                throw new \RuntimeException('ssh: aes-ctr keystream failed');
            }
            $block = substr($data, $off, 16);
            $out .= $block ^ substr($keystream, 0, strlen($block));
            $this->increment();
        }

        return $out;
    }

    /** Increment the 128-bit big-endian counter by one, with carry. */
    private function increment(): void
    {
        for ($i = 15; $i >= 0; $i--) {
            $c = (ord($this->counter[$i]) + 1) & 0xff;
            $this->counter[$i] = chr($c);
            if ($c !== 0) {
                break;
            }
        }
    }
}
