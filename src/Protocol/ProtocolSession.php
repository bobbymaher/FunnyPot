<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Per-connection state for the protocol engine: the inbound byte buffer, a request counter,
 * the per-attacker seed (so {{fake.*}} values are stable-but-distinct per source), and a
 * close flag the listener honours. All bounds are enforced against this by the emulator.
 */
final class ProtocolSession
{
    public string $buffer = '';
    public int $requests = 0;
    public bool $close = false;

    // Shell state (used only by protocols with a `shell` block): login -> password -> shell.
    public string $phase = 'login';
    public string $user = '';
    public string $cwd = '/root';
    public bool $authed = false;
    public int $authTries = 0;

    public function __construct(public int $seed = 0)
    {
    }
}
