<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable package.json (also serves package-lock.json). Carries the name/version
 * keys the matcher wants inside a plausible manifest of common public dependencies.
 * Inert: scoped to an @example package, no private registry tokens or internal paths.
 * Served as application/json to satisfy the header word.
 */
final class PackageJsonEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['package-json']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $project = $this->pick(['web-app', 'dashboard', 'storefront', 'admin-ui'], $seed, 'project');
        $version = $this->pick(['1.4.2', '3.0.1', '2.11.0', '0.9.7'], $seed, 'version');

        $lines = [
            '{',
        ];
        if ($style === Style::TAUNT) {
            $note = str_replace("\n", ' ', $this->tauntBanner(''));
            $note = trim(str_replace('"', "'", $note));
            $lines[] = '  "_comment": "' . $note . '",';
        }
        $lines = array_merge($lines, [
            '  "name": "@example/' . $project . '",',
            '  "version": "' . $version . '",',
            '  "private": true,',
            '  "description": "Internal web frontend.",',
            '  "scripts": {',
            '    "build": "vite build",',
            '    "test": "vitest run"',
            '  },',
            '  "dependencies": {',
            '    "react": "^18.2.0",',
            '    "axios": "^1.6.0"',
            '  },',
            '  "devDependencies": {',
            '    "vite": "^5.0.0"',
            '  }',
            '}',
        ]);
        $body = implode("\n", $lines) . "\n";

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'application/json; charset=utf-8']);
    }
}
