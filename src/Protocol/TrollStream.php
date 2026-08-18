<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * The taunt-mode troll animation for the interactive socket honeypots (SSH / telnet). In taunt
 * style (FUNNYPOT_STYLE=taunt) a successful login is answered not with a shell but with an endless
 * full-screen animation: ASCII art on a black background, its colour rotating matrix-green / blue /
 * red every frame, over a fake "installing reverse shell" progress bar that fills and restarts. The
 * server loops push one frame() every tick and ignore the attacker's keystrokes, so the session is
 * a pure time-sink. Any other style shows nothing extra and the shell stays believable.
 */
final class TrollStream
{
    /** Frames per full progress-bar cycle; the art flips between the two faces each cycle. */
    private const STEPS = 24;

    private const BAR_WIDTH = 32;

    /** Bright green / blue / red on a black background (matrix palette), rotated per frame. */
    private const COLORS = ["\e[40;92m", "\e[40;94m", "\e[40;91m"];

    private const SKULL = <<<'ART'
                          ud$$$**$$$$$$$bc.
                       u@**"        4$$$$$$$Nu
                     J                ""#$$$$$$r
                    @                       $$$$b
                  .F                        ^*3$$$
                 :% 4                         J$$$N
                 $  :F                       :$$$$$
                4F  9                       J$$$$$$$
                4$   k             4$$$$bed$$$$$$$$$
                $$r  'F            $$$$$$$$$$$$$$$$$r
                $$$   b.           $$$$$$$$$$$$$$$$$N
                $$$$$k 3eeed$$b    $$$Euec."$$$$$$$$$
 .@$**N.        $$$$$" $$$$$$F'L $$$$$$$$$$$  $$$$$$$
 :$$L  'L       $$$$$ 4$$$$$$  * $$$$$$$$$$F  $$$$$$F         edNc
@$$$$N  ^k      $$$$$  3$$$$*%   $F4$$$$$$$   $$$$$"        d"  z$N
$$$$$$   ^k     '$$$"   #$$$F   .$  $$$$$c.u@$$$          J"  @$$$$r
$$$$$$$b   *u    ^$L            $$  $$$$$$$$$$$$u@       $$  d$$$$$$
 ^$$$$$$.    "NL   "N. z@*     $$$  $$$$$$$$$$$$$P      $P  d$$$$$$$
    ^"*$$$$b   '*L   9$E      4$$$  d$$$$$$$$$$$"     d*   J$$$$$r
         ^$$$$u  '$.  $$$L     "#" d$$$$$$".@$$    .@$"  z$$$$*"
           ^$$$$. ^$N.3$$$       4u$$$$$$$ 4$$$  u$*" z$$$"
             '*$$$$$$$$ *$b      J$$$$$$$b u$$P $"  d$$P
                #$$$$$$ 4$ 3*$"$*$ $"$'c@@$$$$ .u@$$$P
                  "$$$$  ""F~$ $uNr$$$^&J$$$$F $$$$#
                    "$$    "$$$bd$.$W$$$$$$$$F $$"
                      ?k         ?$$$$$$$$$$$F'*
                       9$$bL     z$$$$$$$$$$$F
                        $$$$    $$$$$$$$$$$$$
                         '#$$c  '$$$$$$$$$"
                          .@"#$$$$$$$$$$$$b
                        z*      $$$$$$$$$$$$N.
                      e"      z$$"  #$$$k  '*$$.
                  .u*      u@$P"      '#$$c   "$$c
           u@$*"""       d$$"            "$$$u  ^*$$b.
         :$F           J$P"                ^$$$c   '"$$$$$$bL
        d$$  ..      @$#                      #$$b         '#$
        9$$$$$$b   4$$                          ^$$k         '$
         "$$6""$b u$$                             '$    d$$$$$P
           '$F $$$$$"                              ^b  ^$$$$b$
            '$W$$$$"                                'b@$$$$"
                                                     ^$$$*
ART;

    private const TROLL = <<<'ART'
⠀⠀⠀⠀⠀⣀⣠⠤⠶⠶⣖⡛⠛⠿⠿⠯⠭⠍⠉⣉⠛⠚⠛⠲⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⠋⠁⠀⡉⠁⢐⣒⠒⠈⠁⠀⠀⠀⠈⠁⢂⢅⡂⠀⠀⠘⣧⠀⠀⠀⠀
⠀⠀⣼⠀⠀⠀⠁⠀⠀⠀⠂⠀⠀⠀⠀⢀⣀⣤⣤⣄⡈⠈⠀⠀⠀⠘⣇⠀⠀⠀
⢠⡾⠡⠄⠀⠀⠾⠿⠿⣷⣦⣤⠀⠀⣾⣋⡤⠿⠿⠿⠿⠆⠠⢀⣀⡒⠼⢷⣄⠀
⣿⠊⠊⠶⠶⢦⣄⡄⠀⢀⣿⠀⠀⠀⠈⠁⠀⠀⠙⠳⠦⠶⠞⢋⣍⠉⢳⡄⠈⣧
⢹⣆⡂⢀⣿⠀⠀⡀⢴⣟⠁⠀⢀⣠⣘⢳⡖⠀⠀⣀⣠⡴⠞⠋⣽⠷⢠⠇⠀⣼
⠀⢻⡀⢸⣿⣷⢦⣄⣀⣈⣳⣆⣀⣀⣤⣭⣴⠚⠛⠉⣹⣧⡴⣾⠋⠀⠀⣘⡼⠃
⠀⢸⡇⢸⣷⣿⣤⣏⣉⣙⣏⣉⣹⣁⣀⣠⣼⣶⡾⠟⢻⣇⡼⠁⠀⠀⣰⠋⠀⠀
⠀⢸⡇⠸⣿⡿⣿⢿⡿⢿⣿⠿⠿⣿⠛⠉⠉⢧⠀⣠⡴⠋⠀⠀⠀⣠⠇⠀⠀⠀
⠀⢸⠀⠀⠹⢯⣽⣆⣷⣀⣻⣀⣀⣿⣄⣤⣴⠾⢛⡉⢄⡢⢔⣠⠞⠁⠀⠀⠀⠀
⠀⢸⠀⠀⠀⠢⣀⠀⠈⠉⠉⠉⠉⣉⣀⠠⣐⠦⠑⣊⡥⠞⠋⠀⠀⠀⠀⠀⠀⠀
⠀⢸⡀⠀⠁⠂⠀⠀⠀⠀⠀⠀⠒⠈⠁⣀⡤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠶⢤⣤⣤⣤⣤⡤⠴⠖⠚⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
ART;

    public static function enabled(): bool
    {
        return (getenv('FUNNYPOT_STYLE') ?: '') === 'taunt';
    }

    /**
     * One animation frame (a full-screen redraw), CRLF-terminated for a raw terminal. Frame N picks
     * the colour (rotates per frame), the art (flips per progress cycle) and the bar position, so
     * the caller only has to keep a monotonic counter and push frames on a timer.
     */
    public static function frame(int $n): string
    {
        $color = self::COLORS[$n % 3];
        $art = intdiv($n, self::STEPS) % 2 === 0 ? self::SKULL : self::TROLL;
        $pct = (int) round(($n % self::STEPS) / (self::STEPS - 1) * 100);
        $filled = (int) round($pct / 100 * self::BAR_WIDTH);
        $bar = str_repeat('#', $filled) . str_repeat('.', self::BAR_WIDTH - $filled);
        $dots = str_repeat('.', 1 + ($n % 3));

        $out = "\e[2J\e[H" . $color;                       // clear screen, home cursor, colour on black
        foreach (explode("\n", $art) as $line) {
            $out .= $line . "\r\n";
        }
        $out .= "\e[40;97m\r\n";                            // white on black for the label
        $out .= 'installing reverse shell' . $dots . "\r\n";
        $out .= $color . '[' . $bar . "]\e[40;97m " . $pct . "%\e[0m\r\n";

        return $out;
    }
}
