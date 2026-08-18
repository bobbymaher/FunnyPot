<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Config\AppConfig;
use PHPUnit\Framework\TestCase;

/**
 * AppConfig::fromEnv resolves every FUNNYPOT_* var once, with sane defaults and path bases.
 */
final class AppConfigTest extends TestCase
{
    /** @var string[] */
    private array $keys = [
        'FUNNYPOT_MODE', 'FUNNYPOT_STYLE', 'FUNNYPOT_DB', 'FUNNYPOT_LOG', 'FUNNYPOT_ATTACK',
        'FUNNYPOT_DECOY_ARCHIVE', 'FUNNYPOT_PROTOCOLS', 'FUNNYPOT_RETAIN_DAYS', 'FUNNYPOT_RETAIN_GB',
        'FUNNYPOT_DASHBOARD_PATH', 'FUNNYPOT_CEILING', 'FUNNYPOT_JITTER_MS',
    ];

    protected function setUp(): void
    {
        foreach ($this->keys as $k) {
            putenv($k);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->keys as $k) {
            putenv($k);
        }
    }

    public function test_defaults(): void
    {
        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('public', $c->mode);
        self::assertSame('realistic', $c->style);
        self::assertSame('/app/demo/storage/funnypot.sqlite', $c->dbPath);
        self::assertSame('/app/demo/storage/hits.log', $c->logPath);
        self::assertSame('critical', $c->severityCeiling);
        self::assertSame(40, $c->jitterMs);
        self::assertTrue($c->attackEmulation);
        self::assertTrue($c->decoyArchive);
        self::assertTrue($c->protocolsEnabled);
        self::assertSame(0, $c->retainDays);
        self::assertSame('/__fp/', $c->dashboardPath);
    }

    public function test_env_overrides(): void
    {
        putenv('FUNNYPOT_MODE=stealth');
        putenv('FUNNYPOT_STYLE=taunt');
        putenv('FUNNYPOT_ATTACK=0');
        putenv('FUNNYPOT_PROTOCOLS=0');
        putenv('FUNNYPOT_RETAIN_DAYS=30');
        putenv('FUNNYPOT_RETAIN_GB=2.5');
        putenv('FUNNYPOT_DASHBOARD_PATH=secretconsole');
        putenv('FUNNYPOT_DB=off');

        $c = AppConfig::fromEnv('/app/demo');

        self::assertSame('stealth', $c->mode);
        self::assertSame('taunt', $c->style);
        self::assertFalse($c->attackEmulation);
        self::assertFalse($c->protocolsEnabled);
        self::assertSame(30, $c->retainDays);
        self::assertSame(2.5, $c->retainGb);
        self::assertSame('/secretconsole/', $c->dashboardPath);   // normalised with slashes
        self::assertSame('/app/demo/storage/funnypot.sqlite', $c->dbPath); // 'off' no longer disables
    }

    public function test_unknown_mode_falls_back_to_public(): void
    {
        putenv('FUNNYPOT_MODE=banana');
        self::assertSame('public', AppConfig::fromEnv('/app/demo')->mode);
    }
}
