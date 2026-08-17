<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Zero-dependency TCP listener for one protocol on one bind address. A single-process,
 * non-blocking stream_select loop holds many idle/slow connections; it sends the banner on
 * connect, feeds inbound bytes to the ProtocolEmulator, writes back the framed reply, and
 * LOGS every connection + decoded command through the injected logger (so redis/ftp/ssh
 * commands land in the same hit log the dashboard shows).
 *
 * Runtime is PHP-only (no extension, no composer dep). Everything is bounded: max concurrent
 * connections, per-source-IP cap, idle timeout, and the emulator's own per-connection buffer
 * and request caps — a long-lived TCP surface must never become a self-DoS.
 */
final class Listener
{
    private const MAX_CONNS = 256;
    private const PER_IP_CONNS = 20;
    private const IDLE_TIMEOUT = 90;   // seconds
    private const READ_CHUNK = 8192;

    /** @param callable(array<string,mixed>):void $logger */
    public function __construct(
        private ProtocolEmulator $emulator,
        private string $protocol,
        private $logger
    ) {
    }

    /** Bind and serve forever. $bind is "host:port", e.g. "0.0.0.0:6379". */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-listen {$this->protocol}: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-listen {$this->protocol} on {$bind}\n");

        /** @var array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
            }
            $write = $except = [];
            if (@stream_select($read, $write, $except, 1) === false) {
                continue; // interrupted; loop again
            }
            $now = time();

            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
                    continue;
                }
                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }
                $data = @fread($r, self::READ_CHUNK);
                if ($data === '' || $data === false) {
                    $this->close($conns, $perIp, $id); // EOF / error
                    continue;
                }
                $conns[$id]['last'] = $now;
                $ip = $conns[$id]['ip'];
                $resp = $this->emulator->feed(
                    $data,
                    $conns[$id]['sess'],
                    function (string $cmd) use ($ip, $port): void {
                        $this->log('command', $ip, $port, $cmd);
                    }
                );
                if ($resp !== '') {
                    @fwrite($r, $resp);
                }
                if ($conns[$id]['sess']->close) {
                    $this->close($conns, $perIp, $id);
                }
            }

            // Idle sweep — reclaim connections that went quiet.
            foreach ($conns as $id => $c) {
                if ($now - $c['last'] > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    /**
     * @param resource                                                                   $server
     * @param array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int}>    $conns
     * @param array<string,int>                                                          $perIp
     */
    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0, $peer);
        if ($sock === false) {
            return;
        }
        $ip = self::ipOf((string) $peer);
        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock); // over a cap — refuse rather than exhaust

            return;
        }
        stream_set_blocking($sock, false);
        $sess = new ProtocolSession(crc32($ip)); // per-attacker seed for {{fake.*}}
        $id = get_resource_id($sock);
        $conns[$id] = ['sock' => $sock, 'sess' => $sess, 'ip' => $ip, 'last' => $now];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->log('connect', $ip, $port, '');
        $banner = $this->emulator->banner($sess);
        if ($banner !== '') {
            @fwrite($sock, $banner);
        }
        if ($sess->close) {
            $this->close($conns, $perIp, $id);
        }
    }

    /**
     * @param array<int,array{sock:resource,sess:ProtocolSession,ip:string,last:int}> $conns
     * @param array<string,int>                                                       $perIp
     */
    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        @fclose($conns[$id]['sock']);
        $ip = $conns[$id]['ip'];
        if (isset($perIp[$ip]) && --$perIp[$ip] <= 0) {
            unset($perIp[$ip]);
        }
        unset($conns[$id]);
    }

    private function log(string $event, string $ip, int $port, string $cmd): void
    {
        ($this->logger)([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => strtoupper($this->protocol),
            'path' => substr($cmd, 0, 200),
            'proto' => $this->protocol,
            'port' => $port,
            'event' => $event,
            'matched' => true,
            'severity' => 'medium',
            'served' => $event === 'command',
        ]);
    }

    private static function ipOf(string $peer): string
    {
        $p = strrpos($peer, ':');

        return $p === false ? $peer : substr($peer, 0, $p);
    }

    private static function portOf(string $bind): int
    {
        $p = strrpos($bind, ':');

        return $p === false ? 0 : (int) substr($bind, $p + 1);
    }
}
