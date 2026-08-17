<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable WordPress wp-login.php page with open registration — exactly what the
 * wordpress-login / registration-enabled matcher expects (the "Register For This Site"
 * message, the wp-includes asset path, the ?action=register link, the WordPress title).
 * Inert: all links point at an example.com blog; no real site or nonce is disclosed.
 */
final class WpLoginEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['wordpress-login', 'wp-enabled-registration', 'wp-registration-enabled']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $site = $this->pick(['Example Site', 'Acme Blog', 'Company News', 'The Portal'], $seed, 'site');
        $base = 'https://blog.example.com';

        $body = "<!DOCTYPE html>\n"
            . "<html lang=\"en-US\">\n"
            . "<head>\n"
            . "<meta charset=\"UTF-8\" />\n"
            . "<title>Log In &lsaquo; {$site} &#8212; WordPress</title>\n"
            . "<link rel='stylesheet' href='{$base}/wp-includes/css/dist/block-library/style.min.css' />\n"
            . "</head>\n"
            . "<body class=\"login no-js login-action-login wp-core-ui\">\n"
            . "<div id=\"login\">\n"
            . "<h1><a href=\"{$base}/\">{$site}</a></h1>\n"
            . "<p class=\"message register\">Register For This Site</p>\n"
            . "<form name=\"loginform\" id=\"loginform\" action=\"{$base}/wp-login.php\" method=\"post\">\n"
            . "<p><label>Username or Email Address<br />\n"
            . "<input type=\"text\" name=\"log\" class=\"input\" /></label></p>\n"
            . "<p><label>Password<br />\n"
            . "<input type=\"password\" name=\"pwd\" class=\"input\" /></label></p>\n"
            . "<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" value=\"Log In\" /></p>\n"
            . "</form>\n"
            . "<p id=\"nav\">\n"
            . "<a href=\"{$base}/wp-login.php?action=register\">Register</a> |\n"
            . "<a href=\"{$base}/wp-login.php?action=lostpassword\">Lost your password?</a>\n"
            . "</p>\n"
            . "<p id=\"backtoblog\"><a href=\"{$base}/\">&larr; Go to {$site}</a></p>\n"
            . "</div>\n"
            . "</body>\n"
            . "</html>\n";

        if ($style === Style::TAUNT) {
            $body = '<!-- ' . str_replace("\n", ' ', $this->tauntBanner('')) . " -->\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/html; charset=UTF-8']);
    }
}
