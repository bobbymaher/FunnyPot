<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

/**
 * The composed LLM gate: both checks AND'd, default-deny. A bulk-scanning IP trips and is pinned to
 * plain-404 even on plausible paths and even after it goes quiet; a lone plausible probe generates.
 */
final class ProbeGateTest extends TestCase
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

    private function store(): SqliteHitStore
    {
        $p = sys_get_temp_dir() . '/fp_gate_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return new SqliteHitStore($p);
    }

    private function gate(SqliteHitStore $s): ProbeGate
    {
        return new ProbeGate(new ProbeClassifier(), new VelocityTracker(5, 15), $s, 24);
    }

    public function test_velocity_thresholds(): void
    {
        $v = new VelocityTracker(5, 15);
        self::assertFalse($v->isBulkScan(['recent' => 4, 'extended' => 10]));
        self::assertTrue($v->isBulkScan(['recent' => 5, 'extended' => 0]));
        self::assertTrue($v->isBulkScan(['recent' => 0, 'extended' => 15]));
    }

    public function test_plausible_path_low_velocity_generates(): void
    {
        $s = $this->store();
        $s->append(['ts' => gmdate('c'), 'ip' => '2.2.2.2', 'method' => 'GET', 'path' => '/x']);
        $d = $this->gate($s)->decide('GET', '/super-rare-app/login.asp', '2.2.2.2');
        self::assertTrue($d['generate']);
        self::assertSame('plausible', $d['reason']);
    }

    public function test_probe_path_blocked(): void
    {
        $d = $this->gate($this->store())->decide('GET', '/random9271.php', '2.2.2.2');
        self::assertFalse($d['generate']);
        self::assertSame('probe', $d['reason']);
    }

    public function test_bulk_scan_trips_and_pins_even_after_going_quiet(): void
    {
        $s = $this->store();
        foreach (['/a', '/b', '/c', '/d', '/e', '/f'] as $p) {   // 6 distinct paths/60s > threshold 5
            $s->append(['ts' => gmdate('c'), 'ip' => '6.6.6.6', 'method' => 'GET', 'path' => $p]);
        }
        $g = $this->gate($s);

        $d = $g->decide('GET', '/admin/login.php', '6.6.6.6');   // plausible path, but bulk velocity
        self::assertFalse($d['generate']);
        self::assertSame('bulk-scan', $d['reason']);
        self::assertTrue($s->isBulkFlagged('6.6.6.6'));

        // pinned: even a fresh plausible path from this IP stays blocked (no new velocity needed)
        $d2 = $g->decide('GET', '/portal/dashboard.php', '6.6.6.6');
        self::assertFalse($d2['generate']);
        self::assertSame('bulk-scan-pinned', $d2['reason']);
    }
}
