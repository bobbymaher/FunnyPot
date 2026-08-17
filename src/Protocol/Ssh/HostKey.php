<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * The server's ssh-ed25519 host key. Generated once with libsodium and persisted so the key is
 * stable across restarts (a changing host key trips client warnings and is itself a tell). Only
 * two operations are ever needed: expose the public key blob and sign the exchange hash — a
 * honeypot never verifies client signatures.
 */
final class HostKey
{
    /** @param string $secret 64-byte ed25519 secret key @param string $public 32-byte public key */
    public function __construct(private string $secret, private string $public)
    {
    }

    /** Load the host key from $path, generating and persisting one on first use. */
    public static function load(string $path): self
    {
        $raw = @file_get_contents($path);
        if ($raw !== false && strlen($raw) === 96) {
            return new self(substr($raw, 0, 64), substr($raw, 64, 32));
        }

        $pair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($pair);
        $public = sodium_crypto_sign_publickey($pair);
        @mkdir(dirname($path), 0700, true);
        if (@file_put_contents($path, $secret . $public) !== false) {
            @chmod($path, 0600);
        }

        return new self($secret, $public);
    }

    /** The "ssh-ed25519" public key blob (string algo + string key), as sent in KEX_ECDH_REPLY. */
    public function publicBlob(): string
    {
        return (new Buf())->string('ssh-ed25519')->string($this->public)->get();
    }

    /** Sign the exchange hash; returns the "ssh-ed25519" signature blob (string algo + string sig). */
    public function sign(string $data): string
    {
        $sig = sodium_crypto_sign_detached($data, $this->secret);

        return (new Buf())->string('ssh-ed25519')->string($sig)->get();
    }
}
