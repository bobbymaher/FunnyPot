<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Shell;

use Funnypot\Attack\CannedData;
use Funnypot\Protocol\ProtocolSession;

/**
 * A Cowrie-style medium-interaction fake shell, shared by telnet (after accept-all login) and,
 * later, SSH (behind a crypto sidecar). It is a LOOKUP TABLE, never an interpreter: each command
 * maps to canned output over a static fake filesystem. There is NO proc_open / shell_exec / exec /
 * eval, NO real filesystem access, and NO outbound socket — `wget`/`curl` return canned text and the
 * requested URL is only logged (by the listener), never fetched. Output is bounded per command.
 */
final class FakeShell
{
    private const MAX_OUTPUT = 8192;
    private const HOST = 'web01';

    /** dir path → child entry names */
    private const DIRS = [
        '/' => ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'tmp', 'usr', 'var'],
        '/root' => ['.bash_history', '.bashrc', '.profile', '.ssh', '.cache'],
        '/root/.ssh' => ['authorized_keys', 'id_rsa', 'id_rsa.pub', 'known_hosts'],
        '/etc' => ['passwd', 'shadow', 'hostname', 'hosts', 'os-release', 'crontab', 'ssh'],
        '/home' => ['ubuntu', 'deploy'],
        '/home/ubuntu' => ['.bashrc', '.profile', '.ssh'],
        '/var' => ['backups', 'lib', 'log', 'www'],
        '/var/www' => ['html'],
        '/var/backups' => ['db_backup.sql.gz', 'passwd.bak'],
        '/tmp' => [],
    ];

    /** file path → contents (canned, inert) */
    private const FILES = [
        '/etc/hostname' => "web01\n",
        '/etc/hosts' => "127.0.0.1 localhost\n127.0.1.1 web01\n",
        '/etc/os-release' => "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\n",
        '/root/.bashrc' => "# ~/.bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nalias ll='ls -alF'\n",
        '/root/.profile' => "# ~/.profile\nmesg n 2> /dev/null || true\n",
        '/root/.bash_history' => "ls -la\ncat /etc/passwd\nuname -a\nwget http://example.com/setup.sh\nps aux\nnetstat -tulpn\n",
        '/root/.ssh/authorized_keys' => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakekeyfakekeyfakekey root@web01\n",
        '/root/.ssh/id_rsa' => "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA(fake, truncated)\n-----END OPENSSH PRIVATE KEY-----\n",
        '/root/.ssh/known_hosts' => "",
    ];

    /** Run one command line; append output. Updates cwd / close on exit. */
    public function run(string $line, ProtocolSession $s): string
    {
        $line = trim($line);
        if ($line === '') {
            return '';
        }
        // A leading `sudo` just runs the rest (we are already "root").
        $parts = preg_split('/\s+/', $line) ?: [];
        $cmd = strtolower($parts[0]);
        $args = array_slice($parts, 1);
        if ($cmd === 'sudo' && $args !== []) {
            return $this->run(implode(' ', $args), $s);
        }

        $out = $this->dispatch($cmd, $args, $line, $s);
        if (strlen($out) > self::MAX_OUTPUT) {
            $out = substr($out, 0, self::MAX_OUTPUT);
        }

        return $out;
    }

    /**
     * @param string[] $args
     */
    private function dispatch(string $cmd, array $args, string $line, ProtocolSession $s): string
    {
        switch ($cmd) {
            case 'exit':
            case 'logout':
                $s->close = true;

                return "logout\r\n";
            case 'whoami':
                return $s->user . "\r\n";
            case 'id':
                return $s->user === 'root'
                    ? "uid=0(root) gid=0(root) groups=0(root)\r\n"
                    : "uid=1000({$s->user}) gid=1000({$s->user}) groups=1000({$s->user})\r\n";
            case 'pwd':
                return $s->cwd . "\r\n";
            case 'hostname':
                return self::HOST . "\r\n";
            case 'uname':
                return $this->uname($args);
            case 'echo':
                return implode(' ', $args) . "\r\n";
            case 'cd':
                return $this->cd($args[0] ?? '', $s);
            case 'ls':
            case 'dir':
                return $this->ls($args, $s);
            case 'cat':
            case 'head':
            case 'tail':
            case 'more':
            case 'less':
                return $this->cat($args, $s);
            case 'wget':
            case 'curl':
                // The URL is logged by the listener; we NEVER fetch it — canned output only.
                return $this->fetch($cmd, $args);
            case 'ps':
                return "  PID TTY          TIME CMD\r\n 1001 pts/0    00:00:00 bash\r\n 1042 pts/0    00:00:00 ps\r\n";
            case 'netstat':
            case 'ss':
                return "Active Internet connections\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State\r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n";
            case 'ifconfig':
            case 'ip':
                return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\r\n";
            case 'uptime':
            case 'w':
                return " 12:04:18 up 9 days,  4:41,  1 user,  load average: 0.02, 0.05, 0.00\r\n";
            case 'free':
                return "               total        used        free      shared  buff/cache   available\r\nMem:         2039836      312904      982716        1284      744216     1560492\r\n";
            case 'clear':
                return "\033[H\033[2J";
            case 'history':
            case 'export':
            case 'set':
            case 'unset':
            case ':':
                return '';
            default:
                return "-bash: {$cmd}: command not found\r\n";
        }
    }

    /** @param string[] $args */
    private function uname(array $args): string
    {
        $flags = implode('', $args);
        if (strpos($flags, 'a') !== false) {
            return "Linux " . self::HOST . " 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n";
        }
        if (strpos($flags, 'r') !== false) {
            return "5.15.0-91-generic\r\n";
        }

        return "Linux\r\n";
    }

    /** @param string[] $args */
    private function ls(array $args, ProtocolSession $s): string
    {
        $long = false;
        $path = $s->cwd;
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                $long = $long || strpos($a, 'l') !== false;
            } else {
                $path = $this->resolve($a, $s->cwd);
            }
        }

        $entries = self::DIRS[$path] ?? null;
        if ($entries === null) {
            if (isset(self::FILES[$path])) {
                return basename($path) . "\r\n";
            }

            return "ls: cannot access '" . ($args[0] ?? $path) . "': No such file or directory\r\n";
        }
        if (!$long) {
            return ($entries === [] ? '' : implode('  ', $entries) . "\r\n");
        }

        $out = "total " . (count($entries) * 4) . "\r\n";
        foreach ($entries as $name) {
            $child = rtrim($path, '/') . '/' . $name;
            $isDir = isset(self::DIRS[$child]);
            $perm = $isDir ? 'drwxr-xr-x' : '-rw-r--r--';
            $size = $isDir ? 4096 : strlen(self::FILES[$child] ?? '');
            $out .= sprintf("%s 1 root root %6d Jan  1 12:00 %s\r\n", $perm, $size, $name);
        }

        return $out;
    }

    private function cd(string $path, ProtocolSession $s): string
    {
        $target = $this->resolve($path, $s->cwd);
        if (isset(self::DIRS[$target])) {
            $s->cwd = $target;

            return '';
        }
        if (isset(self::FILES[$target])) {
            return "-bash: cd: {$path}: Not a directory\r\n";
        }

        return "-bash: cd: {$path}: No such file or directory\r\n";
    }

    /** @param string[] $args */
    private function cat(array $args, ProtocolSession $s): string
    {
        if ($args === []) {
            return '';
        }
        $out = '';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                continue;
            }
            $path = $this->resolve($a, $s->cwd);
            if ($path === '/etc/passwd') {
                $out .= self::crlf(CannedData::PASSWD);
            } elseif ($path === '/etc/shadow') {
                $out .= self::crlf(CannedData::SHADOW);
            } elseif (isset(self::FILES[$path])) {
                $out .= self::crlf(self::FILES[$path]);
            } elseif (isset(self::DIRS[$path])) {
                $out .= "cat: {$a}: Is a directory\r\n";
            } else {
                $out .= "cat: {$a}: No such file or directory\r\n";
            }
        }

        return $out;
    }

    /** @param string[] $args */
    private function fetch(string $cmd, array $args): string
    {
        $url = '';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] !== '-') {
                $url = $a;
                break;
            }
        }
        if ($url === '') {
            return "{$cmd}: missing URL\r\n";
        }
        $host = parse_url($url, PHP_URL_HOST) ?: 'host';

        // Plausible progress text — but NOTHING is fetched. The URL is intel, logged upstream.
        if ($cmd === 'curl') {
            return '';
        }

        return "--" . gmdate('Y-m-d H:i:s') . "--  {$url}\r\n"
            . "Resolving {$host}... 93.184.216.34\r\n"
            . "Connecting to {$host}|93.184.216.34|:80... connected.\r\n"
            . "HTTP request sent, awaiting response... 200 OK\r\n"
            . "Length: unspecified [text/html]\r\n"
            . "Saving to: 'index.html'\r\n\r\nindex.html    [ <=> ] 1.42K  --.-KB/s    in 0s\r\n";
    }

    private function resolve(string $path, string $cwd): string
    {
        if ($path === '' || $path === '~') {
            return '/root';
        }
        if ($path[0] !== '/') {
            $path = rtrim($cwd, '/') . '/' . $path;
        }
        $parts = [];
        foreach (explode('/', $path) as $p) {
            if ($p === '' || $p === '.') {
                continue;
            }
            if ($p === '..') {
                array_pop($parts);
            } else {
                $parts[] = $p;
            }
        }

        return '/' . implode('/', $parts);
    }

    private static function crlf(string $s): string
    {
        return str_replace("\n", "\r\n", $s);
    }
}
