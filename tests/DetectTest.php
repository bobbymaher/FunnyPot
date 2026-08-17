<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Detection;
use Funnypot\NucleiInverter;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

final class DetectTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function inverter(): NucleiInverter
    {
        // Default config: inert (detect only).
        return new NucleiInverter($this->store());
    }

    private function respondInverter(): NucleiInverter
    {
        return new NucleiInverter($this->store(), new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true
        ));
    }

    public function test_known_probe_is_detected_with_metadata(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/.git/config'));

        self::assertTrue($d->matched);
        self::assertFalse($d->isEmpty());
        self::assertSame(['git-config'], $d->templateIds());
        self::assertSame('medium', $d->highestSeverity);
        self::assertContains('git', $d->tags());
        self::assertSame('GET /.git/config', $d->clusterKey);
    }

    public function test_miss_returns_none(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/totally/legit/page'));

        self::assertFalse($d->matched);
        self::assertTrue($d->isEmpty());
        self::assertSame([], $d->templateIds());
        self::assertSame('', $d->clusterKey);
    }

    public function test_method_mismatch_misses(): void
    {
        // Index only carries GET /.git/config; a POST must not route to it.
        $d = $this->inverter()->detect(new RequestContext('POST', '/.git/config'));

        self::assertFalse($d->matched);
    }

    public function test_query_string_is_ignored_for_routing(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/webpack.config.js', 'v=1'));

        self::assertTrue($d->matched);
        self::assertSame(['webpack-config'], $d->templateIds());
    }

    public function test_full_target_in_path_field_still_routes(): void
    {
        // A caller that shoves the whole request-target into path still resolves.
        $d = $this->inverter()->detect(new RequestContext('GET', '/webpack.config.js?v=1'));

        self::assertTrue($d->matched);
        self::assertSame(['webpack-config'], $d->templateIds());
    }

    public function test_multi_path_template_routes_from_either_path(): void
    {
        $a = $this->inverter()->detect(new RequestContext('GET', '/npm-debug.log'));
        $b = $this->inverter()->detect(new RequestContext('GET', '/assets/npm-debug.log'));

        self::assertSame(['npm-debug-log'], $a->templateIds());
        self::assertSame(['npm-debug-log'], $b->templateIds());
    }

    public function test_trailing_slash_directory_probe(): void
    {
        // /config/ must hit; /config (no slash) must miss — distinct byte keys.
        self::assertTrue($this->inverter()->detect(new RequestContext('GET', '/config/'))->matched);
        self::assertFalse($this->inverter()->detect(new RequestContext('GET', '/config'))->matched);
    }

    public function test_severity_ceiling_helper(): void
    {
        self::assertSame('high', Detection::ceilingSeverity('low', 'high'));
        self::assertSame('critical', Detection::ceilingSeverity('critical', 'medium'));
        self::assertSame('medium', Detection::ceilingSeverity('medium', 'info'));
    }

    public function test_respond_synthesizes_a_satisfying_response(): void
    {
        // In respond mode with an open gate, respond() builds a fake from the chosen
        // bundle: every required body word present, no forbidden substring, the bundle
        // status, and a record of which templates it satisfies.
        $response = $this->respondInverter()->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($response);
        self::assertSame(200, $response->status);
        self::assertStringContainsString('[core]', $response->body);
        self::assertStringNotContainsStringIgnoringCase('<html', $response->body);
        self::assertStringNotContainsStringIgnoringCase('<body', $response->body);
        self::assertArrayHasKey('Content-Type', $response->headers);
        self::assertSame(['git-config'], $response->satisfies->templateIds());
    }

    public function test_respond_returns_null_on_miss(): void
    {
        self::assertNull($this->respondInverter()->respond(new RequestContext('GET', '/totally/legit/page')));
    }

    public function test_respond_is_inert_under_default_config(): void
    {
        // A default install is detect-only: respond serves nothing even on a known path.
        self::assertNull($this->inverter()->respond(new RequestContext('GET', '/.git/config')));
    }

    public function test_respond_requires_an_open_gate(): void
    {
        $inv = new NucleiInverter($this->store(), new Config(mode: 'respond'));

        // Gate defaults closed (no predicate) -> no fake served.
        self::assertNull($inv->respond(new RequestContext('GET', '/.git/config')));
    }

    public function test_trusted_bypass_suppresses_response(): void
    {
        $inv = new NucleiInverter($this->store(), new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            trustedBypass: static fn (RequestContext $r): bool => true
        ));

        self::assertNull($inv->respond(new RequestContext('GET', '/.git/config')));
    }
}
