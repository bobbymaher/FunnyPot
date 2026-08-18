<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

/**
 * Builds the completion prompt for the sidecar. Qwen ChatML format: a fixed system instruction, a
 * one-shot exemplar turn (a fake request answered with bare HTML — stabilises the output format far
 * better than instructions alone), then the real request. Only the method + path are
 * attacker-influenced; they are stripped to printable ASCII and length-capped before interpolation.
 * The final assistant turn is left open for the model to complete, constrained by the GBNF grammar.
 */
final class LlmPromptBuilder
{
    private const SYSTEM =
        "You generate a short, plausible fake web page for the HTTP request below, as if that "
        . "software really existed, for a defensive security-research honeypot. Output only the raw "
        . "HTML document, nothing else. Keep it under about 1500 characters. Never include real "
        . "credentials, secrets, API keys, scripts, or links to other sites. If you are unsure what "
        . "the application is, produce a generic sign-in, 'not authorized', or 'under construction' "
        . "page that matches the product name in the path.";

    private const EXEMPLAR_REQUEST = "Method: GET\nPath: /acme-portal/signin.aspx";

    private const EXEMPLAR_ANSWER =
        '<!doctype html><html><head><title>ACME Portal - Sign in</title></head><body>'
        . '<h1>ACME Portal</h1><form method="post" action="/acme-portal/signin.aspx">'
        . '<label>Username</label><input name="username">'
        . '<label>Password</label><input name="password" type="password">'
        . '<button>Sign in</button></form></body></html>';

    public function build(string $method, string $path): string
    {
        $m = $this->clean($method, 10);
        $p = $this->clean($path, 200);

        return "<|im_start|>system\n" . self::SYSTEM . "<|im_end|>\n"
            . "<|im_start|>user\n" . self::EXEMPLAR_REQUEST . "<|im_end|>\n"
            . "<|im_start|>assistant\n" . self::EXEMPLAR_ANSWER . "<|im_end|>\n"
            . "<|im_start|>user\nMethod: {$m}\nPath: {$p}<|im_end|>\n"
            . "<|im_start|>assistant\n";
    }

    /** Strip to printable ASCII and cap length. The grammar + sanitizer are the real guards; this
     *  just keeps attacker bytes from corrupting the prompt structure. */
    private function clean(string $s, int $max): string
    {
        $s = substr($s, 0, $max);

        return (string) preg_replace('/[^\x20-\x7e]/', '', $s);
    }
}
