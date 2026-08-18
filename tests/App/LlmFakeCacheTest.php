<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Storage\LlmFakeCache;
use PHPUnit\Framework\TestCase;

/**
 * The LLM cache's storage behaviour: version-matched get/put, the atomic concurrency cap + single
 * flight (WON/BUSY/FULL), LRU eviction, and stale-lock reaping.
 */
final class LlmFakeCacheTest extends TestCase
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

    private function cache(): LlmFakeCache
    {
        $p = sys_get_temp_dir() . '/fp_cache_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return new LlmFakeCache($p);
    }

    public function test_put_then_get_roundtrips_when_version_matches(): void
    {
        $c = $this->cache();
        $c->put('GET /a', 200, 'text/html', '<!doctype html><body>a</body>', 'v1');

        $hit = $c->get('GET /a', 'v1');
        self::assertNotNull($hit);
        self::assertSame(200, $hit['status']);
        self::assertStringContainsString('body>a', $hit['body']);

        // A prompt-version bump invalidates old entries so stale wording is never served.
        self::assertNull($c->get('GET /a', 'v2'));
    }

    public function test_cap_is_a_hard_ceiling(): void
    {
        $c = $this->cache();
        // Two distinct keys fill a cap of 2...
        self::assertSame(LlmFakeCache::ACQUIRE_WON, $c->acquire('GET /one', 2));
        self::assertSame(LlmFakeCache::ACQUIRE_WON, $c->acquire('GET /two', 2));
        // ...the third distinct key is over capacity.
        self::assertSame(LlmFakeCache::ACQUIRE_FULL, $c->acquire('GET /three', 2));

        // Releasing frees a slot.
        $c->release('GET /one');
        self::assertSame(LlmFakeCache::ACQUIRE_WON, $c->acquire('GET /three', 2));
    }

    public function test_same_key_is_busy_not_full(): void
    {
        $c = $this->cache();
        self::assertSame(LlmFakeCache::ACQUIRE_WON, $c->acquire('GET /dup', 4));
        // The same key held by a peer reports BUSY (wait for its result), distinct from FULL.
        self::assertSame(LlmFakeCache::ACQUIRE_BUSY, $c->acquire('GET /dup', 4));
    }

    public function test_reap_inflight_spares_fresh_and_clears_stale(): void
    {
        $c = $this->cache();
        $c->acquire('GET /stuck', 4);
        self::assertSame(1, $c->inflightCount());

        // A just-taken lock is younger than the window, so the default reap leaves it alone.
        self::assertSame(0, $c->reapInflight());
        self::assertSame(1, $c->inflightCount());

        // A window reaching into the future treats every lock as stale — the delete path fires.
        self::assertSame(1, $c->reapInflight(-1));
        self::assertSame(0, $c->inflightCount());
    }

    public function test_retain_bytes_evicts_least_recently_served(): void
    {
        $c = $this->cache();
        $body = str_repeat('x', 500);
        foreach (['GET /1', 'GET /2', 'GET /3'] as $k) {
            $c->put($k, 200, 'text/html', $body, 'v1');
        }
        // Touch /3 so it is the most-recently served and survives.
        $c->get('GET /3', 'v1');
        $evicted = $c->retainBytes(600);   // room for ~one 500-byte body
        self::assertGreaterThan(0, $evicted);
        self::assertNotNull($c->get('GET /3', 'v1'));
    }
}
