<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable Apache mod_status (/server-status, /server-info) page. Carries the
 * "Apache Server Status" / "Server Version" markers inside a plausible status dump.
 * Inert: client rows use RFC-5737 addresses and an example.com vhost; no real traffic
 * or internal host is disclosed.
 */
final class ApacheServerStatusEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['apache-server-status', 'server-status', 'server-info']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $apache = $this->pick(['2.4.58', '2.4.52', '2.4.41'], $seed, 'apache');
        $uptime = $this->pick(['3 days', '11 hours', '27 days'], $seed, 'uptime');

        $body = "<!DOCTYPE html>\n"
            . "<html><head><title>Apache Status</title></head><body>\n"
            . "<h1>Apache Server Status for status.example.com (via 192.0.2.10)</h1>\n"
            . "<dl>\n"
            . "<dt>Server Version: Apache/{$apache} (Unix) OpenSSL/3.0</dt>\n"
            . "<dt>Server MPM: event</dt>\n"
            . "<dt>Server Built: Jan  1 2024</dt>\n"
            . "<dt>Current Time: Monday, 01-Jan-2024 00:00:00 UTC</dt>\n"
            . "<dt>Server uptime: {$uptime}</dt>\n"
            . "<dt>Total accesses: 10423 - Total Traffic: 84.2 MB</dt>\n"
            . "</dl>\n"
            . "<pre>\n"
            . "Srv  Client          VHost                Request\n"
            . "0-0  198.51.100.24   www.example.com      GET / HTTP/1.1\n"
            . "1-0  203.0.113.7     www.example.com      GET /favicon.ico HTTP/1.1\n"
            . "</pre>\n"
            . "</body></html>\n";

        if ($style === Style::TAUNT) {
            $body = '<!-- ' . str_replace("\n", ' ', $this->tauntBanner('')) . " -->\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/html; charset=utf-8']);
    }
}
