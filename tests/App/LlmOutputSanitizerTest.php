<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmOutputSanitizer;
use PHPUnit\Framework\TestCase;

/**
 * The sanitizer treats model output as hostile: a clean HTML body passes, every dangerous or
 * malformed shape returns null (which the responder turns into the plain 404).
 */
final class LlmOutputSanitizerTest extends TestCase
{
    private LlmOutputSanitizer $s;

    protected function setUp(): void
    {
        $this->s = new LlmOutputSanitizer();
    }

    public function test_clean_html_passes(): void
    {
        $html = '<!doctype html><html><head><title>Sign in</title></head><body>'
            . '<h1>Sign in</h1><form method="post" action="/login"><input name="user">'
            . '<input name="pass" type="password"><button>Log in</button></form></body></html>';
        self::assertSame($html, $this->s->sanitize($html));
    }

    public function test_trims_but_keeps_body(): void
    {
        $html = "  <html><body><p>ok, this is a plausible enough page body</p></body></html>  ";
        self::assertSame(trim($html), $this->s->sanitize($html));
    }

    /**
     * @dataProvider rejected
     */
    public function test_rejects(string $label, string $raw): void
    {
        self::assertNull($this->s->sanitize($raw), $label);
    }

    /** @return array<int,array{0:string,1:string}> */
    public static function rejected(): array
    {
        $pad = str_repeat('x', 60);   // enough length so short-circuit isn't the size rule

        return [
            ['too short', '<p>hi</p>'],
            ['preamble / not markup', "Sure! Here is the HTML:\n<html><body>$pad</body></html>"],
            ['markdown fence', "```html\n<html><body>$pad</body></html>\n```"],
            ['script tag', "<html><body><script>alert(1)</script>$pad</body></html>"],
            ['iframe', "<html><body><iframe src=\"/x\"></iframe>$pad</body></html>"],
            ['link tag', "<html><head><link rel=stylesheet href=\"x.css\">$pad</head></html>"],
            ['style block', "<html><head><style>body{color:red}</style>$pad</head></html>"],
            ['meta refresh', "<html><head><meta http-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['meta refresh extra spaces', "<html><head><meta   http-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['meta refresh tab sep', "<html><head><meta\thttp-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['event handler', "<html><body><img src=x onerror=\"alert(1)\">$pad</body></html>"],
            ['event handler slash sep', "<html><body><div/onload=\"alert(1)\">$pad</div></body></html>"],
            ['javascript href', "<html><body><a href=\"javascript:alert(document.domain)\">go</a>$pad</body></html>"],
            ['vbscript href', "<html><body><a href=\"vbscript:msgbox(1)\">go</a>$pad</body></html>"],
            ['data uri action', "<html><body><form action=\"data:text/html;base64,PHg+\">$pad</form></body></html>"],
            ['absolute href', "<html><body><a href=\"https://evil.example/x\">go</a>$pad</body></html>"],
            ['protocol-relative src', "<html><body><img src=\"//evil.example/x.png\">$pad</body></html>"],
            ['css url external', "<html><body><div style=\"background:url(http://evil/x)\">$pad</div></body></html>"],
            ['php tag', "<html><body><?php system('id'); ?>$pad</body></html>"],
            ['eval', "<html><body>text eval(atob('x')) more $pad</body></html>"],
            ['base64_decode', "<html><body>base64_decode('...') $pad here</body></html>"],
            ['private key', "<html><body>-----BEGIN RSA PRIVATE KEY----- $pad</body></html>"],
            ['path traversal', "<html><body><a href=\"../../etc/passwd\">x</a>$pad</body></html>"],
            ['control bytes', "<html><body>\x07\x00 bad bytes $pad</body></html>"],
            ['invalid utf-8', "<html><body>\xff\xfe not utf8 $pad</body></html>"],
        ];
    }

    public function test_rejects_oversize(): void
    {
        $huge = '<html><body>' . str_repeat('a', 9000) . '</body></html>';
        self::assertNull($this->s->sanitize($huge, 8192));
    }
}
