<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable exposed .htpasswd. Carries the {SHA} marker the matcher looks for, with
 * deterministic fakeHex hash bodies that are obviously inert — never a crackable or
 * real password hash. Realistic enough that an attacker wastes time feeding it to a
 * cracker.
 */
final class HtpasswdEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['htpasswd']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $users = ['admin', 'deploy', 'backup', 'webmaster'];
        $lines = [];
        foreach ($users as $user) {
            // base64-looking but fakeHex-derived: not a real SHA1 digest.
            $hash = base64_encode(hex2bin($this->fakeHex($seed, 'sha-' . $user, 40)) ?: '');
            $lines[] = "{$user}:{SHA}{$hash}";
        }
        $body = implode("\n", $lines) . "\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('#') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/plain; charset=utf-8']);
    }
}
