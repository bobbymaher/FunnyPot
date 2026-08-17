<?php

declare(strict_types=1);

/**
 * GeoIP enrichment for the dashboard. IP → ISO country code via a DB-IP "IP-to-Country Lite"
 * range table loaded into SQLite (free, CC-BY, no account); country → lat/lon via a bundled
 * centroid table for the attacker map. Enrichment is a purely local read at write time.
 *
 * The range CSV is fetched into the storage volume (scripts/fetch-geoip.sh) and imported
 * (dashboard admin "geoip" action) — never committed or baked into the image (attribution:
 * DB-IP.com, CC BY 4.0). With no data loaded, lookup() returns [] and the demo runs fine
 * (no country column, empty map) — geoip is purely additive.
 */
final class Geo
{
    private ?PDO $db = null;
    private bool $ready = false;

    public function __construct(private string $csvPath)
    {
        $dbPath = preg_replace('/\.csv(\.gz)?$/', '', $csvPath) . '.sqlite';
        if (!extension_loaded('pdo_sqlite')) {
            return;
        }
        try {
            $this->db = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $this->db->exec('CREATE TABLE IF NOT EXISTS ranges (lo INTEGER, hi INTEGER, cc TEXT)');
            $this->db->exec('CREATE INDEX IF NOT EXISTS idx_ranges_hi ON ranges(hi)');
            $this->ready = (int) $this->db->query('SELECT COUNT(*) FROM ranges')->fetchColumn() > 0;
        } catch (Throwable $e) {
            $this->db = null;
        }
    }

    /**
     * @return array<string,mixed> {cc,lat,lon} or [] when unresolved (no data, private/reserved
     *   source, IPv6, or country not in the centroid table).
     */
    public function lookup(string $ip): array
    {
        if (!$this->ready || $this->db === null) {
            return [];
        }
        $n = self::ipv4ToInt($ip);
        if ($n === null) {
            return []; // IPv6 / invalid / private handled by ipv4ToInt
        }
        $st = $this->db->prepare('SELECT cc FROM ranges WHERE hi >= :n AND lo <= :n ORDER BY hi ASC LIMIT 1');
        $st->execute([':n' => $n]);
        $cc = (string) ($st->fetchColumn() ?: '');
        if ($cc === '') {
            return [];
        }
        $c = self::CENTROIDS[$cc] ?? null;

        return $c === null ? ['cc' => $cc] : ['cc' => $cc, 'lat' => $c[0], 'lon' => $c[1]];
    }

    /** Build the range table from the DB-IP CSV (idempotent: replaces existing rows). */
    public function import(): int
    {
        if ($this->db === null || !is_file($this->csvPath)) {
            return 0;
        }
        $fh = self::openCsv($this->csvPath);
        if ($fh === null) {
            return 0;
        }
        $this->db->exec('DELETE FROM ranges');
        $ins = $this->db->prepare('INSERT INTO ranges (lo,hi,cc) VALUES (:lo,:hi,:cc)');
        $this->db->beginTransaction();
        $n = 0;
        while (($row = fgetcsv($fh)) !== false) {
            // DB-IP country-lite: start_ip, end_ip, country_code. IPv4 rows only.
            $lo = self::ipv4ToInt((string) ($row[0] ?? ''));
            $hi = self::ipv4ToInt((string) ($row[1] ?? ''));
            $cc = strtoupper(substr((string) ($row[2] ?? ''), 0, 2));
            if ($lo === null || $hi === null || $cc === '') {
                continue; // skip IPv6 + malformed
            }
            $ins->execute([':lo' => $lo, ':hi' => $hi, ':cc' => $cc]);
            $n++;
        }
        $this->db->commit();
        fclose($fh);
        $this->ready = $n > 0;

        return $n;
    }

    /** Public IPv4 → uint32, or null for private/reserved/IPv6/invalid (never geolocate those). */
    private static function ipv4ToInt(string $ip): ?int
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return null;
        }

        return (int) sprintf('%u', ip2long($ip));
    }

    /** @return resource|null */
    private static function openCsv(string $path)
    {
        $fh = substr($path, -3) === '.gz' ? @gzopen($path, 'rb') : @fopen($path, 'rb');

        return $fh === false ? null : $fh;
    }

    /** ISO-3166 alpha-2 → [lat, lon] centroid for the map. Compact set of high-traffic sources. */
    private const CENTROIDS = [
        'US' => [39.8, -98.6], 'CN' => [35.9, 104.2], 'RU' => [61.5, 105.3], 'IN' => [22.0, 79.0],
        'BR' => [-14.2, -51.9], 'DE' => [51.2, 10.4], 'NL' => [52.1, 5.3], 'GB' => [54.0, -2.0],
        'FR' => [46.2, 2.2], 'JP' => [36.2, 138.3], 'KR' => [36.5, 127.8], 'CA' => [56.1, -106.3],
        'VN' => [14.1, 108.3], 'ID' => [-2.5, 118.0], 'IR' => [32.4, 53.7], 'UA' => [48.4, 31.2],
        'PL' => [51.9, 19.1], 'TR' => [38.9, 35.2], 'IT' => [41.9, 12.6], 'ES' => [40.5, -3.7],
        'TW' => [23.7, 121.0], 'HK' => [22.3, 114.2], 'SG' => [1.35, 103.8], 'AU' => [-25.3, 133.8],
        'ZA' => [-30.6, 22.9], 'MX' => [23.6, -102.6], 'AR' => [-38.4, -63.6], 'TH' => [15.9, 100.9],
        'RO' => [45.9, 24.9], 'SE' => [60.1, 18.6], 'FI' => [61.9, 25.7], 'NO' => [60.5, 8.5],
        'CH' => [46.8, 8.2], 'BE' => [50.5, 4.5], 'AT' => [47.5, 14.6], 'CZ' => [49.8, 15.5],
        'BG' => [42.7, 25.5], 'GR' => [39.1, 21.8], 'PT' => [39.4, -8.2], 'IE' => [53.4, -8.2],
        'IL' => [31.0, 34.9], 'AE' => [23.4, 53.8], 'SA' => [23.9, 45.1], 'EG' => [26.8, 30.8],
        'PK' => [30.4, 69.3], 'BD' => [23.7, 90.4], 'PH' => [12.9, 121.8], 'MY' => [4.2, 101.98],
        'NG' => [9.1, 8.7], 'KE' => [-0.02, 37.9], 'CO' => [4.6, -74.3], 'CL' => [-35.7, -71.5],
        'PE' => [-9.2, -75.0], 'KZ' => [48.0, 66.9], 'BY' => [53.7, 27.95], 'RS' => [44.0, 21.0],
        'HU' => [47.2, 19.5], 'DK' => [56.3, 9.5], 'LT' => [55.2, 23.9], 'LV' => [56.9, 24.6],
        'EE' => [58.6, 25.0], 'MD' => [47.4, 28.4], 'HR' => [45.1, 15.2], 'SK' => [48.7, 19.7],
        'MA' => [31.8, -7.1], 'DZ' => [28.0, 1.7], 'IQ' => [33.2, 43.7], 'NZ' => [-40.9, 174.9],
    ];
}
