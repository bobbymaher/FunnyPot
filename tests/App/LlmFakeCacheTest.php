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

    public function test_all_lists_entries_with_metadata(): void
    {
        $c = $this->cache();
        $c->put('GET /alpha', 200, 'text/html', str_repeat('a', 120), 'v1');
        $c->put('GET /beta', 401, 'text/html', str_repeat('b', 60), 'v1');
        $c->get('GET /beta', 'v1');   // serve beta so it is most-recently-served

        $all = $c->all();
        self::assertCount(2, $all);
        // Most-recently-served first: beta was just served.
        self::assertSame('GET /beta', $all[0]['key']);
        self::assertSame(401, $all[0]['status']);
        self::assertSame(60, $all[0]['bytes']);
        self::assertSame(1, $all[0]['served_count']);
        self::assertSame(120, $all[1]['bytes']);
        self::assertArrayHasKey('body', $all[0]);
    }

    public function test_stats_counts_entries_bytes_and_serves(): void
    {
        $c = $this->cache();
        $c->put('GET /a', 200, 'text/html', str_repeat('x', 100), 'v1');
        $c->put('GET /b', 200, 'text/html', str_repeat('y', 50), 'v1');
        $c->get('GET /a', 'v1');
        $c->get('GET /a', 'v1');

        $s = $c->stats();
        self::assertSame(2, $s['entries']);
        self::assertSame(150, $s['bytes']);
        self::assertSame(2, $s['served']);
    }

    public function test_delete_removes_one_entry(): void
    {
        $c = $this->cache();
        $c->put('GET /keep', 200, 'text/html', 'body-keep-padding-xxxxxxxx', 'v1');
        $c->put('GET /bad', 200, 'text/html', 'body-bad-padding-xxxxxxxxxx', 'v1');

        self::assertTrue($c->delete('GET /bad'));
        self::assertNull($c->get('GET /bad', 'v1'));
        self::assertNotNull($c->get('GET /keep', 'v1'));
        self::assertFalse($c->delete('GET /bad'));   // already gone
    }

    public function test_clear_all_empties_the_cache(): void
    {
        $c = $this->cache();
        $c->put('GET /a', 200, 'text/html', 'padding-body-aaaaaaaaaa', 'v1');
        $c->put('GET /b', 200, 'text/html', 'padding-body-bbbbbbbbbb', 'v1');
        self::assertSame(2, $c->clearAll());
        self::assertSame([], $c->all());
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
