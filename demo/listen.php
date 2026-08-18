<?php

declare(strict_types=1);

/**
 * Start one protocol listener, logging into the same store the dashboard reads — so redis /
 * ftp / smtp / ssh connections and every command an attacker sends show up on the dashboard
 * alongside the HTTP probes.
 *
 *   php demo/listen.php redis 0.0.0.0:6379
 *
 * The demo entrypoint launches one of these per protocol. Runs forever (a select loop).
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\Policy\EmulationPolicy;
use Funnypot\Protocol\Listener;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\Ssh\HostKey;
use Funnypot\Protocol\Ssh\SshServer;

$protocol = $argv[1] ?? '';
$bind = $argv[2] ?? '';
if ($protocol === '' || $bind === '') {
    fwrite(STDERR, "usage: php demo/listen.php <protocol> <host:port>\n");
    exit(2);
}

$config = AppConfig::fromEnv(__DIR__);
@mkdir(dirname($config->logPath), 0777, true);
$store = new SqliteHitStore($config->dbPath, $config->logPath);
$log = static fn (array $entry) => $store->append($entry);

// Honour the emulation catalog: a service switched off in funnypot-vulns.json does not bind.
// (Toggling a service needs a listener restart — the entrypoint relaunches on redeploy.)
$policy = EmulationPolicy::fromPackage(is_file($config->vulnsPath) ? $config->vulnsPath : null);
if (!$policy->isEnabled('service-' . $protocol)) {
    fwrite(STDERR, "funnypot-listen {$protocol}: disabled in emulation catalog — not binding {$bind}\n");
    exit(0);
}

// SSH is a full crypto server (pure PHP), not a data-driven emulator: it terminates the
// SSH-2.0 handshake and drops the attacker into the same fake shell telnet uses.
if ($protocol === 'ssh') {
    $keyPath = getenv('FUNNYPOT_SSH_HOSTKEY') ?: __DIR__ . '/storage/ssh_host_ed25519';
    (new SshServer(HostKey::load($keyPath), $log))->run($bind);
    exit(0);
}

$set = ProtocolTemplateSet::fromPackage();
$emulator = $set->emulator($protocol);
if ($emulator === null) {
    fwrite(STDERR, "unknown protocol '{$protocol}' (have: " . implode(', ', $set->ids()) . ")\n");
    exit(2);
}

(new Listener($emulator, $protocol, $log))->run($bind);
