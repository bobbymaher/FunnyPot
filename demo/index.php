<?php

/**
 * funnypot — standalone honeypot front controller.
 *
 * Bootstraps the app services and hands the request to the router. Every request is logged and,
 * unless it is the operator dashboard, run through the funnypot-core engine: detect the scanner
 * probe, serve a fake if matched, and record it. Routing, views and honeypot logic live in
 * Funnypot\App\Http\*; storage in Funnypot\App\Storage\*; config in Funnypot\App\Config\AppConfig.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/lib/geo.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\Honeytoken;
use Funnypot\RequestContext;

$config = AppConfig::fromEnv(__DIR__);
@mkdir(dirname($config->logPath), 0777, true);

$store = new SqliteHitStore($config->dbPath, $config->logPath);
$geo = new Geo($config->geoDbPath);

// Coherent chrome: one consistent X-Powered-By on every response (nginx owns Server), so header
// recon can't catch a version mismatch between the fake bodies and the server banner.
header('X-Powered-By: ' . $config->poweredBy);

$context = RequestContext::fromGlobals();
$clientIp = HoneypotController::clientIp();

// Anti-fingerprint tripwire: plant a signed bait cookie and classify what comes back — a client
// that returns it tampered is a high-signal probe. Off unless FUNNYPOT_HONEYTOKEN_KEY is set.
$tokenVerdict = 'off';
if ($config->honeytokenKey !== '') {
    $token = new Honeytoken($config->honeytokenKey);
    $tokenVerdict = $token->inspect($_COOKIE['sess'] ?? null);
    header('Set-Cookie: ' . $token->cookie('sess', 'r=user'), false);
}

// Threat-intel blocklist: flag hits from known attackers at write time (opt-in, FUNNYPOT_BLOCKLIST).
$blocklist = $config->blocklistEnabled ? new Blocklist($config->intelDbPath, $config->blocklistMinLists) : null;

// AbuseIPDB reporting: opt-in, and only armed when an API key is set. The service self-excludes our
// own IP (and is inert without FUNNYPOT_SELF_IPS) so our own tests can never report us.
$abuse = ($config->abuseIpdbReport && $config->abuseIpdbKey !== '')
    ? new AbuseIpdb($config->abuseIpdbKey, $config->intelDbPath, $config->selfIps, $config->abuseIpdbDailyCap, $config->abuseIpdbDedupHours)
    : null;

$honeypot = new HoneypotController($store, $geo, $config, __DIR__ . '/decoys', $blocklist, $abuse);
$dashboard = new DashboardController($store, $geo, $config, __DIR__ . '/assets');
$corporate = new CorporateController($store, $geo, $config, __DIR__ . '/assets', $blocklist);
(new Router($config, $honeypot, $dashboard, $corporate))->dispatch($context, $clientIp, $tokenVerdict);
