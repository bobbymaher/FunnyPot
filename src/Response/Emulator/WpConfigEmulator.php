<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable leaked wp-config.php backup that carries both database credentials and
 * AWS keys (the WP Offload Media plugin serialises them as an access-key-id /
 * secret-access-key array — which is exactly what the wpconfig-aws-keys matcher looks
 * for). Every value is a decoy: example.com hosts, RFC-5737 loopback DB host, and
 * deterministic fakeHex secrets that are obviously inert, never a working credential.
 */
final class WpConfigEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['wpconfig-aws-keys', 'aws-credentials', 'wp-config']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $dbName = $this->pick(['wp_prod', 'wordpress', 'wp_live', 'blog'], $seed, 'dbname');
        $dbPass = $this->fakeHex($seed, 'dbpass', 24);
        $accessKeyId = 'AKIA' . strtoupper($this->fakeHex($seed, 'akid', 16));
        $secretKey = $this->fakeHex($seed, 'awssecret', 40);
        $authSalt = $this->fakeHex($seed, 'authsalt', 48);

        $body = "<?php\n"
            . "/**\n"
            . " * The base configuration for WordPress (backup copy).\n"
            . " */\n"
            . "\n"
            . "// ** Database settings ** //\n"
            . "define('DB_NAME', '{$dbName}');\n"
            . "define('DB_USER', 'wp_app');\n"
            . "define('DB_PASSWORD', '{$dbPass}');\n"
            . "define('DB_HOST', '127.0.0.1');\n"
            . "define('DB_CHARSET', 'utf8mb4');\n"
            . "\n"
            . "// ** WP Offload Media (Amazon S3) bucket credentials ** //\n"
            . "define('AS3CF_SETTINGS', serialize(array(\n"
            . "    'provider'          => 'aws',\n"
            . "    'access-key-id'     => '{$accessKeyId}',\n"
            . "    'secret-access-key' => '{$secretKey}',\n"
            . "    'bucket'            => 'media.example.com',\n"
            . "    'region'            => 'us-east-1',\n"
            . ")));\n"
            . "\n"
            . "define('AUTH_SALT', '{$authSalt}');\n"
            . "\$table_prefix = 'wp_';\n"
            . "define('WP_DEBUG', false);\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('#') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/plain; charset=utf-8']);
    }
}
