<?php

declare(strict_types=1);

/**
 * funnypot LLM honeypot — tiny-model eval harness.
 *
 * Sends the honeypot fake-page prompt for a fixed set of test URLs to an
 * OpenAI-compatible chat endpoint (LM Studio by default) and scores each reply
 * for the two behaviours that decide whether a tiny model is usable here:
 * does it refuse, and does it emit clean HTML with no preamble/markdown fences.
 *
 * Self-contained: needs only PHP with ext-curl (falls back to streams).
 * No composer deps.
 *
 * Usage:
 *   1. Load a model in LM Studio and start its local server (Developer tab).
 *   2. php scripts/llm-eval/eval.php <model-name>
 *
 *   <model-name> is the model id LM Studio reports (e.g. "qwen2.5-0.5b-instruct").
 *   Pass "-" or omit to let the server pick its loaded model.
 *
 * Override endpoint / model via env or argv:
 *   LLM_EVAL_URL   (default http://localhost:1234/v1/chat/completions)
 *   LLM_EVAL_MODEL (default from argv[1], else "local-model")
 *   e.g. LLM_EVAL_URL=http://localhost:1234/v1/chat/completions \
 *        php scripts/llm-eval/eval.php phi-4-mini-instruct
 *
 * Read the table by column, not by score total:
 *   refused? must be "no"; preamble/fence? must be "no"; validHTML? should be
 *   "yes". A model that is clean here needs grammar only as a guardrail; one
 *   that refuses or fences is leaning entirely on grammar in production, which
 *   is more fragile. See docs/LLM-MODEL-EVAL.md.
 */

$endpoint = getenv('LLM_EVAL_URL') ?: 'http://localhost:1234/v1/chat/completions';
$argModel = $argv[1] ?? '';
$model = getenv('LLM_EVAL_MODEL')
    ?: (($argModel !== '' && $argModel !== '-') ? $argModel : 'local-model');

// Fixed test set. Three paths the deterministic gate would plausibly ADMIT
// (a rare app path, an app dir, an api path) plus one calibration-probe CONTROL
// that the real gate would 404 before the model is ever called. We send the
// control anyway to see how a model behaves on garbage if the gate ever missed.
$tests = [
    ['method' => 'GET',  'path' => '/super-rare-app/login.asp', 'note' => 'plausible rare app path'],
    ['method' => 'GET',  'path' => '/admin/',                   'note' => 'app dir'],
    ['method' => 'GET',  'path' => '/api/v2/users',             'note' => 'api path'],
    ['method' => 'GET',  'path' => '/intentional_404_page.php', 'note' => 'garbage control (gate would 404 this)'],
];

$maxChars = 4000;

/**
 * The production system prompt (docs/LLM-HONEYPOT-RESEARCH.md, section 4).
 * Only method + path are interpolated; everything else is fixed instruction.
 */
function systemPrompt(int $maxChars): string
{
    return <<<TXT
You are generating a fake web page for a security-research honeypot. Produce a
short, plausible response for the request below, as if this exact software existed.
Rules (must follow exactly):
- Output ONLY the raw HTML body (or plain text) — no explanation, no markdown fences.
- Under {$maxChars} characters.
- No <script>, <iframe>, <object>, <embed>, or <link> tags.
- No absolute URLs (no http:// or https://) anywhere.
- No real or realistic credentials, API keys, tokens, private keys, or secrets.
- No working exploit code, shell commands, or SQL.
- If unsure what this app is, produce a generic login / "not authorized" /
  "under construction" page consistent with the product name in the path.
TXT;
}

function userPrompt(string $method, string $path): string
{
    return "Method: {$method}\nPath: {$path}";
}

/**
 * POST an OpenAI-style chat completion. Returns [content|null, error|null].
 * Uses curl when available, else a stream context. No external deps.
 */
function chat(string $endpoint, string $model, string $system, string $user): array
{
    $payload = json_encode([
        'model' => $model,
        'messages' => [
            ['role' => 'system', 'content' => $system],
            ['role' => 'user',   'content' => $user],
        ],
        'temperature' => 0.3,
        'max_tokens' => 1024,
        'stream' => false,
    ], JSON_UNESCAPED_SLASHES);

    if ($payload === false) {
        return [null, 'failed to encode request'];
    }

    $raw = null;
    $err = null;

    if (function_exists('curl_init')) {
        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT => 5,
        ]);
        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = 'curl: ' . curl_error($ch);
        }
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $payload,
            'timeout' => 120,
            'ignore_errors' => true,
        ]]);
        $raw = @file_get_contents($endpoint, false, $ctx);
        if ($raw === false) {
            $err = 'stream request failed (is the LM Studio server running?)';
        }
    }

    if ($raw === null || $raw === false) {
        return [null, $err ?? 'no response'];
    }

    $decoded = json_decode((string) $raw, true);
    if (!is_array($decoded)) {
        return [null, 'non-JSON response: ' . substr((string) $raw, 0, 200)];
    }
    if (isset($decoded['error'])) {
        $msg = is_array($decoded['error'])
            ? ($decoded['error']['message'] ?? json_encode($decoded['error']))
            : (string) $decoded['error'];
        return [null, 'endpoint error: ' . $msg];
    }
    $content = $decoded['choices'][0]['message']['content'] ?? null;
    if (!is_string($content)) {
        return [null, 'no choices[0].message.content in response'];
    }

    return [$content, null];
}

/** Did the model refuse / apologise instead of producing a page? */
function looksRefused(string $text): bool
{
    $needles = [
        "i can't", "i cannot", "i can not", "i won't", "i will not",
        "i'm sorry", "i am sorry", "i apologize", "i apologise",
        "i'm not able", "i am not able", "i'm unable", "i am unable",
        "as an ai", "cannot assist", "can't assist", "cannot help with",
        "can't help with", "cannot create", "can't create", "against my",
        "not appropriate", "i must decline", "i'd rather not",
    ];
    $hay = strtolower($text);
    foreach ($needles as $n) {
        if (str_contains($hay, $n)) {
            return true;
        }
    }
    return false;
}

/**
 * Preamble or markdown fence: a servable page must start with '<'. Anything
 * else (chat prose, a ``` fence, a leaked <think> block, whitespace-then-text)
 * fails the output-only-HTML contract.
 */
function hasPreambleOrFence(string $text): bool
{
    $t = ltrim($text);
    if ($t === '') {
        return true;
    }
    if (str_starts_with($t, '```')) {
        return true;
    }
    // Reasoning-model leak (e.g. Qwen3 thinking mode not disabled).
    if (stripos($t, '<think>') === 0) {
        return true;
    }
    return $t[0] !== '<';
}

/** Very loose "is there HTML in here at all" check. */
function looksLikeHtml(string $text): bool
{
    $t = strtolower($text);
    if (str_contains($t, '<html') || str_contains($t, '<!doctype')) {
        return true;
    }
    // Any common tag pair as a fallback signal.
    return (bool) preg_match('/<(body|head|div|form|title|h1|p|input|table|span|a)\b/i', $text);
}

function yn(bool $b): string
{
    return $b ? 'yes' : 'no';
}

function pad(string $s, int $w): string
{
    $len = mb_strlen($s);
    if ($len >= $w) {
        return mb_substr($s, 0, $w);
    }
    return $s . str_repeat(' ', $w - $len);
}

// ---- run ----

fwrite(STDERR, "endpoint : {$endpoint}\n");
fwrite(STDERR, "model    : {$model}\n\n");

$cols = [
    ['url', 34],
    ['refused?', 9],
    ['preamble/fence?', 16],
    ['validHTML?', 11],
    ['bytes', 7],
];

$header = '';
$rule = '';
foreach ($cols as [$name, $w]) {
    $header .= pad($name, $w) . '  ';
    $rule .= str_repeat('-', $w) . '  ';
}
echo $header . "\n" . $rule . "\n";

$system = systemPrompt($maxChars);

foreach ($tests as $t) {
    $user = userPrompt($t['method'], $t['path']);
    [$content, $err] = chat($endpoint, $model, $system, $user);

    if ($err !== null) {
        echo pad($t['path'], 34) . '  '
            . pad('ERR', 9) . '  '
            . pad('-', 16) . '  '
            . pad('-', 11) . '  '
            . pad('-', 7) . "\n";
        fwrite(STDERR, "  ! {$t['path']}: {$err}\n");
        continue;
    }

    $refused = looksRefused($content);
    $preamble = hasPreambleOrFence($content);
    $html = looksLikeHtml($content);
    $bytes = strlen($content);

    echo pad($t['path'], 34) . '  '
        . pad(yn($refused), 9) . '  '
        . pad(yn($preamble), 16) . '  '
        . pad(yn($html), 11) . '  '
        . pad((string) $bytes, 7) . "\n";
}

echo "\n";
echo "Legend: refused? and preamble/fence? must be 'no'; validHTML? should be 'yes'.\n";
echo "The garbage control row is informational — the real gate 404s that path\n";
echo "before the model is ever called (see docs/LLM-HONEYPOT-RESEARCH.md).\n";
