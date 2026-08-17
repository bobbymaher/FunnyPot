<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable exposed .git/config. Contains the matcher token ([core]/[credentials])
 * inside a full, realistic-looking git config. The remote URL is deliberately a decoy:
 * an example.com host with no embedded credentials, so the file "looks juicy" without
 * leaking anything and without tripping the credential extractor.
 */
final class GitConfigEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['git-config', 'git']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $branch = $this->pick(['main', 'master', 'develop', 'release'], $seed, 'branch');
        $repo = $this->pick(['app', 'platform', 'api', 'web', 'core'], $seed, 'repo');

        $body = "[core]\n"
            . "\trepositoryformatversion = 0\n"
            . "\tfilemode = true\n"
            . "\tbare = false\n"
            . "\tlogallrefupdates = true\n"
            . "[remote \"origin\"]\n"
            . "\turl = https://git.example.com/internal/{$repo}.git\n"
            . "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            . "[branch \"{$branch}\"]\n"
            . "\tremote = origin\n"
            . "\tmerge = refs/heads/{$branch}\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('#') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'text/plain; charset=utf-8']);
    }
}
