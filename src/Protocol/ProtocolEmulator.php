<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

use Funnypot\Template\DirectiveRenderer;

/**
 * Interprets one compiled protocol against a connection's bytes: send the banner on connect,
 * then for each framed request, first-match-wins over the rule list → render the reply through
 * the bounded DirectiveRenderer → frame it via the codec. Pure lookup + template: it never
 * executes input, never reflects unbounded bytes, and caps buffer + request count per session.
 *
 * Stateless across connections (one shared emulator per protocol); per-connection state lives
 * in ProtocolSession.
 */
final class ProtocolEmulator
{
    /** Hard per-connection bounds — a hostile client can't grow memory or loop us forever. */
    private const MAX_BUFFER = 65536;
    private const MAX_REQUESTS = 500;

    private DirectiveRenderer $renderer;
    private Codec $codec;

    /** @param array<string,mixed> $protocol compiled protocol rules */
    public function __construct(
        private array $protocol,
        ?DirectiveRenderer $renderer = null
    ) {
        $this->renderer = $renderer ?? new DirectiveRenderer();
        $this->codec = self::codecFor((string) ($protocol['framing'] ?? 'line'));
    }

    /** Bytes to send the moment a connection opens (before any input), or '' for silent. */
    public function banner(ProtocolSession $s): string
    {
        return $this->renderer->render((string) ($this->protocol['banner'] ?? ''), [], $s->seed);
    }

    /**
     * Feed inbound bytes; return the bytes to write back (may be ''). Sets $s->close when done.
     *
     * $onRequest, if given, is called once per decoded request as $onRequest(string $command,
     * string $response) — the seam the listener uses to LOG every command an attacker sends
     * (redis/ftp/smtp/ssh…) into the same hit log the dashboard shows. The emulator itself does
     * no I/O; the callback owns logging.
     */
    public function feed(string $bytes, ProtocolSession $s, ?callable $onRequest = null): string
    {
        $s->buffer .= $bytes;
        if (strlen($s->buffer) > self::MAX_BUFFER) {
            $s->buffer = '';
            $s->close = true; // drop a flooding client rather than buffer it

            return '';
        }

        $out = '';
        foreach ($this->codec->extract($s->buffer) as $request) {
            $s->requests++;
            $response = $this->respond($request, $s);
            $out .= $response;
            if ($onRequest !== null) {
                $onRequest($request, $response);
            }
            if ($s->close || $s->requests >= self::MAX_REQUESTS) {
                $s->close = true;
                break;
            }
        }

        return $out;
    }

    private function respond(string $request, ProtocolSession $s): string
    {
        foreach ((array) ($this->protocol['rules'] ?? []) as $rule) {
            $caps = $this->match((array) ($rule['match'] ?? []), $request);
            if ($caps !== null) {
                if (!empty($rule['close'])) {
                    $s->close = true;
                }

                return $this->codec->wrap($this->renderSend($rule['send'] ?? '', $caps, $s->seed));
            }
        }

        $default = $this->protocol['default']['send'] ?? null;

        return $default === null ? '' : $this->codec->wrap($this->renderSend($default, [], $s->seed));
    }

    /**
     * @param array<string,mixed> $cond
     * @return array<int|string,string>|null capture groups on match, null on no match
     */
    private function match(array $cond, string $request): ?array
    {
        if (isset($cond['equals'])) {
            return strcasecmp($request, (string) $cond['equals']) === 0 ? [] : null;
        }
        if (isset($cond['prefix'])) {
            return stripos($request, (string) $cond['prefix']) === 0 ? [] : null;
        }
        if (isset($cond['contains'])) {
            return stripos($request, (string) $cond['contains']) !== false ? [] : null;
        }
        if (isset($cond['regex'])) {
            return preg_match('~' . $cond['regex'] . '~i', $request, $m) === 1 ? $m : null;
        }

        return null;
    }

    /**
     * Render the directive markers in a send spec (string, or a codec spec whose text fields
     * carry directives). Captures come from a regex match; seed is per-attacker.
     *
     * @param string|array<string,mixed> $send
     * @param array<int|string,string>   $caps
     * @return string|array<string,mixed>
     */
    private function renderSend($send, array $caps, int $seed)
    {
        if (!is_array($send)) {
            return $this->renderer->render((string) $send, $caps, $seed);
        }
        $out = [];
        foreach ($send as $k => $v) {
            if (is_string($v)) {
                $out[$k] = $this->renderer->render($v, $caps, $seed);
            } elseif (is_array($v)) {
                $out[$k] = array_map(fn ($x) => $this->renderer->render((string) $x, $caps, $seed), $v);
            } else {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    private static function codecFor(string $framing): Codec
    {
        switch ($framing) {
            case 'resp':
                return new RespCodec();
            case 'raw':
                return new RawCodec();
            case 'line':
            default:
                return new LineCodec();
        }
    }
}
