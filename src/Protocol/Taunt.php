<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Taunt MOTD for the interactive socket honeypots (SSH / telnet). In taunt style
 * (FUNNYPOT_STYLE=taunt) a successful login lands on a trollface banner before the shell prompt;
 * in any other style nothing extra is shown so the shell stays believable. The braille face
 * matches the HTTP taunt banner in funnypot-core, so a scanner that hits both surfaces sees one
 * consistent persona.
 */
final class Taunt
{
    /** Braille trollface. The blanks are U+2800 (braille blank), not spaces, so it stays aligned. */
    private const ART = [
        '⠀⠀⠀⠀⠀⣀⣠⠤⠶⠶⣖⡛⠛⠿⠿⠯⠭⠍⠉⣉⠛⠚⠛⠲⣄⠀⠀⠀⠀⠀',
        '⠀⠀⢀⡴⠋⠁⠀⡉⠁⢐⣒⠒⠈⠁⠀⠀⠀⠈⠁⢂⢅⡂⠀⠀⠘⣧⠀⠀⠀⠀',
        '⠀⠀⣼⠀⠀⠀⠁⠀⠀⠀⠂⠀⠀⠀⠀⢀⣀⣤⣤⣄⡈⠈⠀⠀⠀⠘⣇⠀⠀⠀',
        '⢠⡾⠡⠄⠀⠀⠾⠿⠿⣷⣦⣤⠀⠀⣾⣋⡤⠿⠿⠿⠿⠆⠠⢀⣀⡒⠼⢷⣄⠀',
        '⣿⠊⠊⠶⠶⢦⣄⡄⠀⢀⣿⠀⠀⠀⠈⠁⠀⠀⠙⠳⠦⠶⠞⢋⣍⠉⢳⡄⠈⣧',
        '⢹⣆⡂⢀⣿⠀⠀⡀⢴⣟⠁⠀⢀⣠⣘⢳⡖⠀⠀⣀⣠⡴⠞⠋⣽⠷⢠⠇⠀⣼',
        '⠀⢻⡀⢸⣿⣷⢦⣄⣀⣈⣳⣆⣀⣀⣤⣭⣴⠚⠛⠉⣹⣧⡴⣾⠋⠀⠀⣘⡼⠃',
        '⠀⢸⡇⢸⣷⣿⣤⣏⣉⣙⣏⣉⣹⣁⣀⣠⣼⣶⡾⠟⢻⣇⡼⠁⠀⠀⣰⠋⠀⠀',
        '⠀⢸⡇⠸⣿⡿⣿⢿⡿⢿⣿⠿⠿⣿⠛⠉⠉⢧⠀⣠⡴⠋⠀⠀⠀⣠⠇⠀⠀⠀',
        '⠀⢸⠀⠀⠹⢯⣽⣆⣷⣀⣻⣀⣀⣿⣄⣤⣴⠾⢛⡉⢄⡢⢔⣠⠞⠁⠀⠀⠀⠀',
        '⠀⢸⠀⠀⠀⠢⣀⠀⠈⠉⠉⠉⠉⣉⣀⠠⣐⠦⠑⣊⡥⠞⠋⠀⠀⠀⠀⠀⠀⠀',
        '⠀⢸⡀⠀⠁⠂⠀⠀⠀⠀⠀⠀⠒⠈⠁⣀⡤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀',
        '⠀⠀⠙⠶⢤⣤⣤⣤⣤⡤⠴⠖⠚⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀',
    ];

    public static function enabled(): bool
    {
        return (getenv('FUNNYPOT_STYLE') ?: '') === 'taunt';
    }

    /**
     * The trollface MOTD for a login banner, or '' when not in taunt style. Lines are joined with
     * $eol (CRLF for SSH/telnet) and the block ends with a blank line so the prompt follows cleanly.
     */
    public static function motd(string $eol = "\r\n"): string
    {
        if (!self::enabled()) {
            return '';
        }

        $lines = array_merge(self::ART, [
            '',
            'nice try. this host is a honeypot. nothing here is real.',
            'every command you type is logged.',
            '',
        ]);

        return $eol . implode($eol, $lines) . $eol;
    }
}
