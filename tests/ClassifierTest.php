<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Classifier;
use Funnypot\Compiler\ClusterableFilter;
use Funnypot\Compiler\TemplateLoader;
use PHPUnit\Framework\TestCase;

/**
 * Gate A / Gate B classifier behavior, exercised on hand-built templates that isolate
 * each mandatory review screen (A1/A2/B6) and the eligibility filter.
 */
final class ClassifierTest extends TestCase
{
    private TemplateLoader $loader;
    private ClusterableFilter $gateA;
    private Classifier $gateB;

    protected function setUp(): void
    {
        $this->loader = new TemplateLoader();
        $this->gateA = new ClusterableFilter();
        $this->gateB = new Classifier();
    }

    /** @param array<string,mixed> $doc */
    private function load(array $doc): \Funnypot\Compiler\LoadedTemplate
    {
        // rawText matters for the interactsh scan; serialize a rough approximation.
        return $this->loader->fromArray($doc, json_encode($doc) ?: '', '/virtual/' . ($doc['id'] ?? 'x') . '.yaml');
    }

    /** @param array<string,mixed> $doc */
    private function classify(array $doc)
    {
        return $this->gateB->classify($this->load($doc));
    }

    // ---- A2: dynamic {{...}} literals ----

    public function test_randstr_word_under_and_folds_template_out(): void
    {
        $doc = [
            'id' => 'dyn-randstr',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/probe'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['{{randstr}}']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'A2: an unresolvable {{randstr}} word must fold the AND template OUT');
        self::assertSame('word-dynamic-literal', $c->reason);
    }

    public function test_md5_word_is_unresolvable_and_folds_out(): void
    {
        $doc = [
            'id' => 'dyn-md5',
            'info' => ['severity' => 'info', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['{{md5(123)}}']],
                ],
            ]],
        ];

        self::assertFalse($this->classify($doc)->in);
    }

    public function test_hostname_word_is_resolvable_and_kept(): void
    {
        $doc = [
            'id' => 'dyn-hostname',
            'info' => ['severity' => 'info', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['welcome {{Hostname}}']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, '{{Hostname}} is synth-resolvable and must not fold the template');
        self::assertContains('welcome {{Hostname}}', $c->plan->bodyWords);
    }

    // ---- A1: anchored regex is whole-body-exclusive ----

    public function test_anchored_regex_is_whole_body_exclusive(): void
    {
        $doc = [
            'id' => 'anchored-rx',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'regex', 'part' => 'body', 'regex' => ['^[a-z]+$']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a simple anchored regex should still invert');
        self::assertTrue($c->plan->wholeBodyExclusive, 'A1: ^...$ must flag whole-body-exclusive');
        self::assertNotEmpty($c->plan->regexWitness);
    }

    public function test_unanchored_regex_is_not_exclusive(): void
    {
        $doc = [
            'id' => 'plain-rx',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'regex', 'part' => 'body', 'regex' => ['token=[0-9]{3}']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertFalse($c->plan->wholeBodyExclusive);
    }

    // ---- Gate A exclusions ----

    public function test_payloads_template_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'has-payloads',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/{{path}}'],
                'payloads' => ['path' => ['a', 'b']],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:payloads', $this->gateA->reject($this->load($doc)));
    }

    public function test_raw_template_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'has-raw',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'raw' => ["GET / HTTP/1.1\nHost: {{Hostname}}"],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:raw', $this->gateA->reject($this->load($doc)));
    }

    public function test_interactsh_template_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'has-oob',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x?u={{interactsh-url}}'],
                'matchers' => [
                    ['type' => 'word', 'part' => 'interactsh_protocol', 'words' => ['dns']],
                ],
            ]],
        ];

        self::assertSame('gateA:interactsh-oob', $this->gateA->reject($this->load($doc)));
    }

    public function test_external_host_path_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'osint',
            'info' => ['severity' => 'info', 'tags' => 'osint'],
            'http' => [[
                'method' => 'GET',
                'path' => ['https://example.com/{{user}}'],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:non-baseurl-path', $this->gateA->reject($this->load($doc)));
    }

    // ---- IN: pure status + word(body) ----

    public function test_status_plus_body_word_is_in_with_plan(): void
    {
        // Mirrors git-config: word(body, or) + dsl !contains + status, all under AND.
        $doc = [
            'id' => 'git-config',
            'info' => ['severity' => 'medium', 'tags' => 'config,git,exposure'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/.git/config'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['[credentials]', '[core]'], 'condition' => 'or'],
                    ['type' => 'dsl', 'condition' => 'and', 'dsl' => [
                        "!contains(tolower(body), '<html')",
                        "!contains(tolower(body), '<body')",
                    ]],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a clean status+word(body) template must be IN');
        self::assertSame(200, $c->plan->status);
        // OR word matcher contributes exactly one required body word.
        self::assertContains('[credentials]', $c->plan->bodyWords);
        self::assertCount(1, $c->plan->bodyWords);
        // The dsl !contains clauses become forbidden body substrings.
        self::assertContains('<html', $c->plan->forbidden);
        self::assertContains('<body', $c->plan->forbidden);
        self::assertSame('git', $c->plan->product, 'pid falls back to the git tag');
    }

    public function test_dsl_status_and_contains_conjunction_is_in(): void
    {
        $doc = [
            'id' => 'dsl-conj',
            'info' => ['severity' => 'medium', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/pkg'],
                'matchers' => [
                    ['type' => 'dsl', 'dsl' => [
                        "contains(body, 'packages') && status_code == 200",
                    ]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertSame(200, $c->plan->status);
        self::assertContains('packages', $c->plan->bodyWords);
    }

    // ---- B6: intra-template satisfiability ----

    public function test_contradictory_status_folds_out_b6(): void
    {
        $doc = [
            'id' => 'b6-status',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'status', 'status' => [200]],
                    ['type' => 'dsl', 'dsl' => ['status_code == 404']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'B6: status 200 AND status_code==404 is unsatisfiable');
        self::assertStringContainsString('status-contradiction', $c->reason);
    }

    public function test_required_and_forbidden_same_word_folds_out_b6(): void
    {
        $doc = [
            'id' => 'b6-word',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['ADMIN']],
                    ['type' => 'dsl', 'dsl' => ["!contains(body, 'ADMIN')"]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'B6: a word both required and forbidden is unsatisfiable');
        self::assertStringContainsString('contradiction', $c->reason);
    }

    // ---- unsupported dsl folds out ----

    public function test_compare_versions_dsl_folds_out(): void
    {
        $doc = [
            'id' => 'cmpver',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'dsl', 'dsl' => ["compare_versions(version, '< 2.0.0')"]],
                ],
            ]],
        ];

        self::assertFalse($this->classify($doc)->in);
    }
}
