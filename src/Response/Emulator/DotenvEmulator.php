<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable exposed .env. Every value is a decoy: localhost/example.com hosts and
 * deterministic dummy secrets that are obviously inert (never a real or working
 * credential). Realistic enough that an attacker wastes time trying them.
 */
final class DotenvEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['dotenv', 'env-', 'exposed-config', 'environment']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $appName = $this->pick(['Acme', 'Platform', 'Portal', 'Service'], $seed, 'app');
        $dbPass = $this->fakeHex($seed, 'dbpass', 24);
        $appKey = $this->fakeHex($seed, 'appkey', 32);
        $mailPass = $this->fakeHex($seed, 'mail', 20);

        $lines = [
            "APP_NAME={$appName}",
            'APP_ENV=production',
            "APP_KEY=base64:{$appKey}==",
            'APP_DEBUG=false',
            'APP_URL=https://app.example.com',
            '',
            'DB_CONNECTION=mysql',
            'DB_HOST=127.0.0.1',
            'DB_PORT=3306',
            'DB_DATABASE=app_production',
            'DB_USERNAME=app_ro',
            "DB_PASSWORD={$dbPass}",
            '',
            'MAIL_MAILER=smtp',
            'MAIL_HOST=smtp.example.com',
            'MAIL_PORT=587',
            'MAIL_USERNAME=no-reply@example.com',
            "MAIL_PASSWORD={$mailPass}",
        ];
        $body = implode("\n", $lines) . "\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('#') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/plain; charset=utf-8']);
    }
}
