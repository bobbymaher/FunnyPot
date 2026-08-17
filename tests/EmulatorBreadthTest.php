<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Response\BundleValidator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Emulator\ApacheServerStatusEmulator;
use Funnypot\Response\Emulator\HtpasswdEmulator;
use Funnypot\Response\Emulator\PackageJsonEmulator;
use Funnypot\Response\Emulator\PhpinfoEmulator;
use Funnypot\Response\Emulator\SqlDumpEmulator;
use Funnypot\Response\Emulator\SshPrivateKeyEmulator;
use Funnypot\Response\Emulator\WpConfigEmulator;
use Funnypot\Response\Emulator\WpLoginEmulator;
use Funnypot\Response\EmulatorRegistry;
use Funnypot\Response\Style;

use PHPUnit\Framework\TestCase;

/**
 * Each new endpoint emulator is proven against a REAL compiled bundle: we load the full
 * template index, pick the route/bundle the emulator claims, and assert its REALISTIC
 * and TAUNT bodies satisfy that bundle's own matcher constraints (via BundleValidator —
 * the same checks nuclei applies). The registry is exercised through find() so routing
 * and registration are covered too. This is the guarantee that breadth never breaks the
 * scanner contract.
 */
final class EmulatorBreadthTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static ?array $index = null;

    /**
     * label => [route key, bundle index within that route, expected emulator class].
     * Every route/bundle here is a real entry in resources/compiled/nuclei-index.full.php.
     *
     * @return array<string, array{0:string,1:int,2:class-string}>
     */
    public static function targets(): array
    {
        return [
            'wp-config backup (aws + db keys)' => ['GET /wp-config.php-backup', 0, WpConfigEmulator::class],
            'phpinfo page'                     => ['GET /tool/view/phpinfo.view.php', 0, PhpinfoEmulator::class],
            'htpasswd'                         => ['GET /.htpasswd', 0, HtpasswdEmulator::class],
            'apache server-status'             => ['GET /server-status', 0, ApacheServerStatusEmulator::class],
            'apache server-info'               => ['GET /server-info', 0, ApacheServerStatusEmulator::class],
            'package.json'                     => ['GET /package.json', 0, PackageJsonEmulator::class],
            'package-lock.json'                => ['GET /package-lock.json', 0, PackageJsonEmulator::class],
            'ssh/pem private key'              => ['GET /cgi-bin/privatekey.pem', 0, SshPrivateKeyEmulator::class],
            'sql dump / db backup'             => ['GET /install/froxlor.sql', 0, SqlDumpEmulator::class],
            'wp-login (registration open)'     => ['GET /wp-login.php', 1, WpLoginEmulator::class],
        ];
    }

    /**
     * @dataProvider targets
     */
    public function test_registry_routes_the_real_bundle_to_this_emulator(string $route, int $i, string $class): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = EmulatorRegistry::default()->find($bundle);

        self::assertInstanceOf($class, $emulator, "{$route} #{$i} must be served by {$class}");
    }

    /**
     * @dataProvider targets
     */
    public function test_realistic_body_satisfies_the_real_bundle(string $route, int $i, string $class): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = EmulatorRegistry::default()->find($bundle);
        self::assertInstanceOf($class, $emulator);

        $content = $emulator->render($bundle, Style::REALISTIC, 4242);
        self::assertNotNull($content, "{$route} realistic render must not decline its own bundle");
        self::assertTrue(
            BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
            "{$route} realistic body must satisfy the compiled matcher"
        );
    }

    /**
     * @dataProvider targets
     */
    public function test_taunt_body_satisfies_and_carries_the_marker(string $route, int $i, string $class): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = EmulatorRegistry::default()->find($bundle);
        self::assertInstanceOf($class, $emulator);

        $content = $emulator->render($bundle, Style::TAUNT, 4242);
        self::assertNotNull($content);
        self::assertTrue(
            BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
            "{$route} taunt body must still satisfy the compiled matcher"
        );
        self::assertStringContainsStringIgnoringCase('nice try', $content->body, "{$route} taunt must carry the marker");
    }

    /**
     * @dataProvider targets
     */
    public function test_output_is_byte_identical_per_seed(string $route, int $i, string $class): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = EmulatorRegistry::default()->find($bundle);
        self::assertInstanceOf($class, $emulator);

        $a = $emulator->render($bundle, Style::REALISTIC, 777);
        $b = $emulator->render($bundle, Style::REALISTIC, 777);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, "{$route} must render identically for a fixed seed");
    }

    /**
     * @return array<string,mixed> a single compiled bundle
     */
    private function bundle(string $route, int $i): array
    {
        $routes = self::index()['routes'] ?? [];
        self::assertArrayHasKey($route, $routes, "route {$route} is not in the compiled index");
        self::assertArrayHasKey($i, $routes[$route]['b'] ?? [], "bundle #{$i} is not present at {$route}");

        return $routes[$route]['b'][$i];
    }

    /**
     * Header set the way the synthesizer assembles it: the bundle's base headers with the
     * emulator's overrides on top. BundleValidator builds the header block from this.
     *
     * @param array<string,mixed> $bundle
     * @return array<string,string>
     */
    private function headers(array $bundle, EmulatedContent $content): array
    {
        $headers = [];
        foreach ((array) ($bundle['h'] ?? []) as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }
        foreach ($content->headers as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }

        return $headers;
    }

    /**
     * @return array<string,mixed>
     */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }
}
