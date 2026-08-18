<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

/**
 * One source of truth for the app's runtime configuration. Every FUNNYPOT_* environment variable
 * the app reads is resolved here once, instead of scattered getenv() calls re-deriving the same
 * defaults in the front controller, the listeners and the retention runner.
 *
 * Paths default under <baseDir>/storage. The deploy-only vars (host/user/key/cert domains) are not
 * app config and stay out of this object.
 */
final class AppConfig
{
    public function __construct(
        /** public = today's honeypot-forward behaviour; stealth = fake corporate front, honeypot hidden. */
        public string $mode,
        public string $style,
        public string $dbPath,
        public string $logPath,
        public string $geoDbPath,
        public string $vulnsPath,
        public string $poweredBy,
        public string $honeytokenKey,
        public string $severityCeiling,
        public int $latencyMs,
        public int $jitterMs,
        public bool $attackEmulation,
        public bool $decoyArchive,
        public string $adminPassword,
        public bool $protocolsEnabled,
        public int $retainDays,
        public float $retainGb,
        /** Operator dashboard path in stealth mode (public mode serves it at /). */
        public string $dashboardPath,
        public bool $blocklistEnabled,
        public string $intelDbPath,
        public int $blocklistMinLists,
        public string $abuseIpdbKey,
        public bool $abuseIpdbReport,
        /** Our own public IP(s); AbuseIPDB reporting refuses to report these (and is off if empty). */
        public array $selfIps,
        public int $abuseIpdbDailyCap,
        /** Report each attacker IP at most once per this many hours (AbuseIPDB dislikes duplicates). */
        public int $abuseIpdbDedupHours,
    ) {
    }

    public static function fromEnv(string $baseDir): self
    {
        $store = rtrim($baseDir, '/') . '/storage';

        // getenv() returns false when unset and '' when set empty; treat both as "use the default".
        $str = static function (string $key, string $default): string {
            $v = getenv($key);

            return ($v === false || $v === '') ? $default : $v;
        };
        // A boolean flag that is on by default and only switched off by an explicit "0".
        $onUnless0 = static fn (string $key): bool => getenv($key) !== '0';

        $db = $str('FUNNYPOT_DB', $store . '/funnypot.sqlite');
        if ($db === 'off') {
            $db = $store . '/funnypot.sqlite'; // SQLite is canonical now; 'off' no longer disables it
        }

        return new self(
            mode: getenv('FUNNYPOT_MODE') === 'stealth' ? 'stealth' : 'public',
            style: $str('FUNNYPOT_STYLE', 'realistic'),
            dbPath: $db,
            logPath: $str('FUNNYPOT_LOG', $store . '/hits.log'),
            geoDbPath: $str('FUNNYPOT_GEO_DB', $store . '/dbip-country.csv.gz'),
            vulnsPath: $str('FUNNYPOT_VULNS', $store . '/funnypot-vulns.json'),
            poweredBy: $str('FUNNYPOT_POWERED_BY', 'PHP/8.1.27'),
            honeytokenKey: $str('FUNNYPOT_HONEYTOKEN_KEY', ''),
            severityCeiling: $str('FUNNYPOT_CEILING', 'critical'),
            latencyMs: (int) ($str('FUNNYPOT_LATENCY_MS', '0')),
            jitterMs: (int) ($str('FUNNYPOT_JITTER_MS', '40')),
            attackEmulation: $onUnless0('FUNNYPOT_ATTACK'),
            decoyArchive: $onUnless0('FUNNYPOT_DECOY_ARCHIVE'),
            adminPassword: $str('FUNNYPOT_ADMIN_PASSWORD', ''),
            protocolsEnabled: $onUnless0('FUNNYPOT_PROTOCOLS'),
            retainDays: (int) ($str('FUNNYPOT_RETAIN_DAYS', '0')),
            retainGb: (float) ($str('FUNNYPOT_RETAIN_GB', '0')),
            dashboardPath: '/' . trim($str('FUNNYPOT_DASHBOARD_PATH', '/__fp/'), '/') . '/',
            blocklistEnabled: in_array(strtolower((string) getenv('FUNNYPOT_BLOCKLIST')), ['1', 'on', 'true', 'yes'], true),
            intelDbPath: $str('FUNNYPOT_INTEL_DB', $store . '/intel.sqlite'),
            blocklistMinLists: max(1, (int) $str('FUNNYPOT_BLOCKLIST_MIN_LISTS', '1')),
            abuseIpdbKey: $str('FUNNYPOT_ABUSEIPDB_KEY', ''),
            abuseIpdbReport: in_array(strtolower((string) getenv('FUNNYPOT_ABUSEIPDB_REPORT')), ['1', 'on', 'true', 'yes'], true),
            selfIps: array_values(array_filter(array_map('trim', explode(',', $str('FUNNYPOT_SELF_IPS', ''))))),
            abuseIpdbDailyCap: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DAILY_CAP', '1000')),
            abuseIpdbDedupHours: max(1, (int) $str('FUNNYPOT_ABUSEIPDB_DEDUP_HOURS', '24')),
        );
    }
}
