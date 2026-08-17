<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable exposed PEM private key (id_rsa / server key / .pem leak). Matches any
 * bundle whose required body words announce a "PRIVATE KEY" header, so it serves the
 * whole family of key-exposure templates.
 *
 * The key body is deliberately a stub: a handful of deterministic fakeHex lines, far
 * too short to be a real 2048-bit key. It is NOT a valid or usable key — an obviously
 * truncated decoy, never a working credential.
 */
final class SshPrivateKeyEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        foreach ($this->required($bundle) as $word) {
            if (strpos($word, 'PRIVATE KEY') !== false) {
                return true;
            }
        }

        return false;
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        // Reuse whichever "BEGIN ... PRIVATE KEY" header the bundle asked for so the
        // decoy matches its exact key type; default to RSA.
        $header = 'RSA PRIVATE KEY';
        foreach ($this->required($bundle) as $word) {
            if (($pos = strpos($word, 'PRIVATE KEY')) !== false) {
                $start = strpos($word, 'BEGIN ');
                $header = $start !== false
                    ? substr($word, $start + 6, ($pos - $start - 6) + strlen('PRIVATE KEY'))
                    : 'RSA PRIVATE KEY';
                break;
            }
        }

        // A short, obviously-truncated stub — not a real key.
        $stub = [];
        foreach (['a', 'b', 'c', 'd'] as $salt) {
            $stub[] = substr(base64_encode(hex2bin($this->fakeHex($seed, 'pem-' . $salt, 48)) ?: ''), 0, 64);
        }

        $body = "-----BEGIN {$header}-----\n"
            . implode("\n", $stub) . "\n"
            . "-----END {$header}-----\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('#') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'application/x-pem-file']);
    }
}
