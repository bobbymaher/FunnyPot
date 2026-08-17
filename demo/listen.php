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

require __DIR__ . '/autoload.php';
require __DIR__ . '/lib/store.php';

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

$logFile = getenv('FUNNYPOT_LOG') ?: __DIR__ . '/storage/hits.log';
@mkdir(dirname($logFile), 0777, true);
$store = new Store($logFile, getenv('FUNNYPOT_DB') ?: __DIR__ . '/storage/funnypot.sqlite');
$log = static fn (array $entry) => $store->append($entry);

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
