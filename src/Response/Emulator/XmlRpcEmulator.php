<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable WordPress xmlrpc.php response — a real XML-RPC methodResponse listing
 * the usual methods, which is exactly what a scanner probing xmlrpc expects to see.
 * Inert: it only describes methods, it does not implement pingback/multicall.
 */
final class XmlRpcEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['xmlrpc', 'xml-rpc']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $methods = [
            'system.multicall', 'system.listMethods', 'system.getCapabilities',
            'wp.getUsersBlogs', 'wp.getPost', 'wp.getPosts', 'wp.getComment',
            'wp.getOptions', 'pingback.ping', 'pingback.extensions.getPingbacks',
        ];
        $items = '';
        foreach ($methods as $m) {
            $items .= "      <value><string>{$m}</string></value>\n";
        }

        $body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<methodResponse>\n"
            . "  <params>\n"
            . "    <param>\n"
            . "      <value>\n"
            . "      <array><data>\n"
            . $items
            . "      </data></array>\n"
            . "      </value>\n"
            . "    </param>\n"
            . "  </params>\n"
            . "</methodResponse>\n";

        if ($style === Style::TAUNT) {
            $body = "<!-- " . str_replace("\n", ' ', $this->tauntBanner('')) . " -->\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/xml; charset=UTF-8']);
    }
}
