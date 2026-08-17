<?php

/**
 * Minimal PSR-4 autoloader for the standalone demo, so the Docker image needs no
 * composer — just PHP + the src/ tree. (Library consumers use composer instead.)
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Funnypot\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
