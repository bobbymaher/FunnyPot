<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\AbuseIpdb;
use PHPUnit\Framework\TestCase;

/**
 * AbuseIPDB reporting guards. The overriding property is the self-exclude invariant: the honeypot
 * must never report its own IP, and must not report at all when its own IP is unknown. A recording
 * sender proves whether an HTTP call would actually have gone out.
 */
final class AbuseIpdbTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_abuse_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @param list<string> $calls */
    private function recorder(array &$calls): callable
    {
        return static function (string $url, array $headers, string $body) use (&$calls): array {
            $calls[] = $body;

            return ['status' => 200, 'body' => '{}'];
        };
    }

    public function test_reports_a_public_attacker(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), ['203.0.113.9'], 1000, 6, $this->recorder($calls));
        $r = $a->report('45.9.148.1', 'attack');

        self::assertTrue($r['reported']);
        self::assertCount(1, $calls);
        self::assertStringContainsString('ip=45.9.148.1', $calls[0]);
    }

    public function test_never_reports_self_no_http_call(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), ['45.9.148.1'], 1000, 6, $this->recorder($calls));
        $r = $a->report('45.9.148.1', 'x');

        self::assertFalse($r['reported']);
        self::assertSame('self', $r['reason']);
        self::assertCount(0, $calls);   // the invariant: no request even attempted
    }

    public function test_inert_without_self_ips(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), [], 1000, 6, $this->recorder($calls));

        self::assertSame('self ips not configured', $a->report('45.9.148.1', 'x')['reason']);
        self::assertCount(0, $calls);   // fail safe: never report when our own IP is unknown
    }

    public function test_skips_private_and_invalid_ips(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), ['203.0.113.9'], 1000, 6, $this->recorder($calls));
        foreach (['192.168.1.5', '10.0.0.1', '127.0.0.1', 'not-an-ip'] as $ip) {
            self::assertFalse($a->report($ip, 'x')['reported']);
        }
        self::assertCount(0, $calls);
    }

    public function test_dedup_within_window(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), ['203.0.113.9'], 1000, 6, $this->recorder($calls));

        self::assertTrue($a->report('45.9.148.1', 'x')['reported']);
        self::assertSame('deduped', $a->report('45.9.148.1', 'x')['reason']);
        self::assertCount(1, $calls);
    }

    public function test_daily_cap(): void
    {
        $calls = [];
        $a = new AbuseIpdb('KEY', $this->dbPath(), ['203.0.113.9'], 2, 6, $this->recorder($calls));

        self::assertTrue($a->report('45.9.148.1', 'x')['reported']);
        self::assertTrue($a->report('45.9.148.2', 'x')['reported']);
        self::assertSame('daily cap', $a->report('45.9.148.3', 'x')['reason']);
        self::assertCount(2, $calls);
    }

    public function test_disabled_without_key(): void
    {
        $calls = [];
        $a = new AbuseIpdb('', $this->dbPath(), ['203.0.113.9'], 1000, 6, $this->recorder($calls));

        self::assertSame('no api key', $a->report('45.9.148.1', 'x')['reason']);
        self::assertCount(0, $calls);
    }
}
