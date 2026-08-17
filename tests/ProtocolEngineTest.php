<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolEmulator;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\RespCodec;
use PHPUnit\Framework\TestCase;

final class ProtocolEngineTest extends TestCase
{
    private function emu(string $id): ProtocolEmulator
    {
        $set = ProtocolTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-protocols.php');
        $e = $set->emulator($id);
        self::assertNotNull($e, "protocol {$id} not compiled");

        return $e;
    }

    // --- redis (RESP codec, pure data) ---

    public function test_redis_ping_and_auth_accept_all(): void
    {
        $e = $this->emu('redis');
        $s = new ProtocolSession(7);
        self::assertSame('', $e->banner($s));                    // silent on connect
        self::assertSame("+PONG\r\n", $e->feed("PING\r\n", $s));
        // AUTH as a RESP array is accepted (any password).
        self::assertSame("+OK\r\n", $e->feed("*2\r\n\$4\r\nAUTH\r\n\$3\r\nfoo\r\n", $s));
    }

    public function test_redis_info_is_believable_and_seeded(): void
    {
        $e = $this->emu('redis');
        $a = $e->feed("INFO\r\n", new ProtocolSession(1));
        $b = $e->feed("INFO\r\n", new ProtocolSession(1));
        $c = $e->feed("INFO\r\n", new ProtocolSession(2));
        self::assertStringContainsString('redis_version:7.2.4', $a);
        self::assertMatchesRegularExpression('/run_id:[0-9a-f]{40}/', $a);
        self::assertSame($a, $b);        // deterministic per attacker seed
        self::assertNotSame($a, $c);     // distinct per attacker
        self::assertStringStartsWith('$', $a); // RESP bulk framing
    }

    public function test_redis_config_get_and_unknown_and_quit(): void
    {
        $e = $this->emu('redis');
        self::assertStringContainsString('/var/lib/redis', $e->feed("CONFIG GET dir\r\n", new ProtocolSession(1)));
        self::assertSame("-ERR unknown command\r\n", $e->feed("FROBNICATE x\r\n", new ProtocolSession(1)));
        $s = new ProtocolSession(1);
        self::assertSame("+OK\r\n", $e->feed("QUIT\r\n", $s));
        self::assertTrue($s->close);
    }

    // --- line protocols ---

    public function test_ftp_banner_and_accept_all_login(): void
    {
        $e = $this->emu('ftp');
        $s = new ProtocolSession(1);
        self::assertStringStartsWith('220 ', $e->banner($s));
        self::assertStringContainsString('331', $e->feed("USER root\r\n", $s));
        self::assertStringContainsString('230 Login successful', $e->feed("PASS anything\r\n", $s));
    }

    public function test_smtp_never_relays_but_answers(): void
    {
        $e = $this->emu('smtp');
        $s = new ProtocolSession(1);
        self::assertStringStartsWith('220 ', $e->banner($s));
        self::assertStringContainsString('250-', $e->feed("EHLO evil.example\r\n", $s));
        self::assertStringContainsString('250', $e->feed("MAIL FROM:<a@b>\r\n", $s));
        self::assertStringStartsWith('221', $e->feed("QUIT\r\n", $s));
        self::assertTrue($s->close);
    }

    public function test_ssh_banner_then_close(): void
    {
        $e = $this->emu('ssh');
        $s = new ProtocolSession(1);
        self::assertStringContainsString('SSH-2.0-OpenSSH', $e->banner($s));
        $e->feed("SSH-2.0-libssh_0.9.6\r\n", $s);  // client banner
        self::assertTrue($s->close);                 // no crypto, no shell — logged + closed
    }

    // --- codec framing + bounds + safety ---

    public function test_resp_partial_frame_waits_for_more_bytes(): void
    {
        $e = $this->emu('redis');
        $s = new ProtocolSession(1);
        self::assertSame('', $e->feed("*2\r\n\$4\r\nAUTH\r\n", $s)); // incomplete array — no reply yet
        self::assertSame("+OK\r\n", $e->feed("\$3\r\nfoo\r\n", $s)); // completed on the next chunk
    }

    public function test_resp_codec_rejects_absurd_array_count(): void
    {
        $codec = new RespCodec();
        $buf = "*99999999\r\nrest";
        $reqs = $codec->extract($buf);       // must not allocate 99M args
        self::assertSame([''], $reqs);       // bogus header consumed inert
    }

    public function test_buffer_and_request_caps_close_the_connection(): void
    {
        $e = $this->emu('redis');
        $flood = new ProtocolSession(1);
        $e->feed(str_repeat('A', 70000), $flood);
        self::assertTrue($flood->close);      // buffer cap

        $chatty = new ProtocolSession(1);
        $e->feed(str_repeat("PING\r\n", 600), $chatty);
        self::assertTrue($chatty->close);     // request cap
    }

    public function test_every_command_is_exposed_for_logging(): void
    {
        // The listener logs what attackers send; the emulator emits each decoded command.
        $e = $this->emu('redis');
        $logged = [];
        $e->feed(
            "PING\r\n*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n",
            new ProtocolSession(1),
            function (string $cmd, string $resp) use (&$logged): void {
                $logged[] = $cmd;
            }
        );
        self::assertSame(['PING', 'CONFIG GET dir'], $logged);
    }

    public function test_reflected_directive_never_executes(): void
    {
        // An attacker command carrying a directive is inert — nothing is reflected/executed.
        $e = $this->emu('redis');
        $out = $e->feed("GET {{canned.passwd}}\r\n", new ProtocolSession(1));
        self::assertStringNotContainsString('root:x:0:0', $out);
    }
}
