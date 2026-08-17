<?php

declare(strict_types=1);

namespace Funnypot\Response;

use Funnypot\Response\Emulator\ApacheServerStatusEmulator;
use Funnypot\Response\Emulator\DotenvEmulator;
use Funnypot\Response\Emulator\GitConfigEmulator;
use Funnypot\Response\Emulator\HtpasswdEmulator;
use Funnypot\Response\Emulator\PackageJsonEmulator;
use Funnypot\Response\Emulator\PhpinfoEmulator;
use Funnypot\Response\Emulator\SqlDumpEmulator;
use Funnypot\Response\Emulator\SshPrivateKeyEmulator;
use Funnypot\Response\Emulator\WpConfigEmulator;
use Funnypot\Response\Emulator\WpLoginEmulator;
use Funnypot\Response\Emulator\XmlRpcEmulator;

/**
 * Ordered set of endpoint emulators. First one that supports a bundle wins. Apps can
 * supply their own set; default() carries the built-ins.
 */
final class EmulatorRegistry
{
    /** @var EndpointEmulator[] */
    private array $emulators;

    /** @param EndpointEmulator[] $emulators */
    public function __construct(array $emulators)
    {
        $this->emulators = $emulators;
    }

    public static function default(): self
    {
        return new self([
            new GitConfigEmulator(),
            new DotenvEmulator(),
            new XmlRpcEmulator(),
            new WpConfigEmulator(),
            new WpLoginEmulator(),
            new PhpinfoEmulator(),
            new HtpasswdEmulator(),
            new ApacheServerStatusEmulator(),
            new PackageJsonEmulator(),
            new SshPrivateKeyEmulator(),
            new SqlDumpEmulator(),
        ]);
    }

    /**
     * @param array<string,mixed> $bundle
     */
    public function find(array $bundle): ?EndpointEmulator
    {
        foreach ($this->emulators as $emulator) {
            if ($emulator->supports($bundle)) {
                return $emulator;
            }
        }

        return null;
    }
}
