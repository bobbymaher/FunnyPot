<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The LLM responder pipeline end to end with an injected transport (no network): gate -> generate ->
 * sanitize -> cache -> response, with every decline/failure returning null (the plain 404).
 */
final class LlmFakeResponderTest extends TestCase
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

    private function dbPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fp_{$n}_" . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:LlmFakeResponder,1:SqliteHitStore} */
    private function make(callable $transport): array
    {
        $store = new SqliteHitStore($this->dbPath('hits'));
        $responder = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->dbPath('cache')),
            new LlmClient('http://sidecar/completion', 1500, 320, null, $transport),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"'),
            'v1',
            4,
        );

        return [$responder, $store];
    }

    private const GOOD_HTML =
        '<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1>'
        . '<form method="post" action="/x"><input name="user"><input name="pass" type="password">'
        . '<button>Log in</button></form></body></html>';

    public function test_generates_sanitizes_caches_and_serves(): void
    {
        $calls = 0;
        [$r] = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])];
        });

        $resp = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('Sign in', $resp->body);
        self::assertSame(1, $calls);

        // second request for the same path is a cache hit — no new generation
        $resp2 = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp2);
        self::assertSame(1, $calls);
    }

    public function test_logs_the_served_response_body(): void
    {
        [$r, $store] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])]);
        $resp = $r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9');
        self::assertNotNull($resp);

        // The served fake must be logged with the exact body the attacker got. The request is a
        // bodyless GET, so any logged row carrying HTML is the llm-fake event.
        $rows = $store->delta(0)['rows'];
        $logged = array_filter($rows, static fn (array $row): bool => str_contains((string) ($row['body'] ?? ''), 'Sign in'));
        self::assertNotEmpty($logged, 'the served LLM response body should be logged');
    }

    public function test_gate_declines_probe_path_without_generating(): void
    {
        $calls = 0;
        [$r] = $this->make(function () use (&$calls): array {
            $calls++;

            return ['status' => 200, 'body' => '{}'];
        });

        self::assertNull($r->respond(new RequestContext('GET', '/random9271.php'), '9.9.9.9'));
        self::assertSame(0, $calls);
    }

    public function test_sanitizer_rejection_returns_null(): void
    {
        $bad = '<html><body><script>alert(1)</script> padding to pass the min length check here</body></html>';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $bad])]);
        self::assertNull($r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9'));
    }

    public function test_client_failure_returns_null(): void
    {
        [$r] = $this->make(fn (): array => ['status' => 500, 'body' => '']);
        self::assertNull($r->respond(new RequestContext('GET', '/super-rare-app/login.asp'), '9.9.9.9'));
    }

    public function test_auth_looking_path_gets_401(): void
    {
        $html = '<!doctype html><html><body><h1>Admin</h1><p>Authentication required to view this area.</p></body></html>';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $html])]);
        $resp = $r->respond(new RequestContext('GET', '/admin/settings.php'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame(401, $resp->status);
    }

    public function test_js_path_serves_javascript_not_html(): void
    {
        // The reported bug: a .js request got an HTML page at text/html. It must serve JavaScript.
        $js = 'var APP_CONFIG={"version":"1.0","apiBase":"/api/v1","debug":false,"buildId":"abc123ff"};';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $js])]);
        $resp = $r->respond(new RequestContext('GET', '/static/js/app.js'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame('application/javascript', $resp->headers['Content-Type']);
        self::assertStringNotContainsString('<html', $resp->body);
        self::assertStringContainsString('APP_CONFIG', $resp->body);
    }

    public function test_cache_hit_preserves_content_type(): void
    {
        // The latent bug: build() hardcoded text/html even on a cache hit, discarding the stored type.
        $calls = 0;
        $json = '{"users":[{"id":1,"name":"a.reyes","role":"admin"}],"total":1}';
        [$r] = $this->make(function () use (&$calls, $json): array {
            $calls++;

            return ['status' => 200, 'body' => json_encode(['content' => $json])];
        });

        $first = $r->respond(new RequestContext('GET', '/api/v2/report.json'), '9.9.9.9');
        self::assertNotNull($first);
        self::assertSame('application/json', $first->headers['Content-Type']);

        // Second request is a cache hit (no new generation) and MUST keep application/json.
        $second = $r->respond(new RequestContext('GET', '/api/v2/report.json'), '9.9.9.9');
        self::assertNotNull($second);
        self::assertSame(1, $calls);
        self::assertSame('application/json', $second->headers['Content-Type']);
    }

    public function test_unmapped_extension_falls_back_to_html(): void
    {
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => self::GOOD_HTML])]);
        $resp = $r->respond(new RequestContext('GET', '/backup/keystore.pem'), '9.9.9.9');
        self::assertNotNull($resp);
        self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type']);
    }

    public function test_non_html_sanitizer_rejection_returns_null(): void
    {
        // A .js body carrying a runtime primitive is rejected → the plain 404 (parity with HTML).
        $badJs = 'var x=1; fetch("/y"); var padding_to_reach_the_minimum_length_here=2;';
        [$r] = $this->make(fn (): array => ['status' => 200, 'body' => json_encode(['content' => $badJs])]);
        self::assertNull($r->respond(new RequestContext('GET', '/static/js/app.js'), '9.9.9.9'));
    }
}
