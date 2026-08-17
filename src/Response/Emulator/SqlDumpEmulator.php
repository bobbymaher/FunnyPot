<?php

declare(strict_types=1);

namespace Funnypot\Response\Emulator;

use Funnypot\Response\AbstractEmulator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\Style;

/**
 * A believable exposed SQL dump / database backup. Carries the DDL markers a scanner
 * looks for (DROP TABLE / CREATE TABLE / PRIMARY KEY) inside a plausible schema plus a
 * couple of seed rows. Inert: the admin row's password is a deterministic fakeHex stub,
 * not a real or crackable hash, and all emails are @example.com.
 */
final class SqlDumpEmulator extends AbstractEmulator
{
    public function supports(array $bundle): bool
    {
        return $this->matches($bundle, ['database-backup', 'sql-dump', 'sql-backup', 'mysql-dump', 'db-dump']);
    }

    public function render(array $bundle, string $style, int $seed): ?EmulatedContent
    {
        $db = $this->pick(['froxlor', 'app_prod', 'cms', 'billing'], $seed, 'db');
        $pwHash = '$2y$10$' . $this->fakeHex($seed, 'adminpw', 53);

        $body = "-- MySQL dump 10.13  Distrib 8.0.36\n"
            . "--\n"
            . "-- Host: localhost    Database: {$db}\n"
            . "-- ------------------------------------------------------\n"
            . "\n"
            . "DROP TABLE IF EXISTS `panel_admins`;\n"
            . "CREATE TABLE `panel_admins` (\n"
            . "  `adminid` int(11) NOT NULL AUTO_INCREMENT,\n"
            . "  `loginname` varchar(50) NOT NULL DEFAULT '',\n"
            . "  `password` varchar(255) NOT NULL DEFAULT '',\n"
            . "  `email` varchar(255) NOT NULL DEFAULT '',\n"
            . "  PRIMARY KEY (`adminid`)\n"
            . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
            . "\n"
            . "INSERT INTO `panel_admins` VALUES "
            . "(1,'admin','{$pwHash}','admin@example.com');\n";

        if ($style === Style::TAUNT) {
            $body = $this->tauntBanner('--') . "\n" . $body;
        }

        $body = $this->appendMissingTokens($body, $bundle);

        return new EmulatedContent($body, ['Content-Type' => 'application/sql']);
    }
}
