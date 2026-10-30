<?php

declare(strict_types=1);

/**
 * Integration bootstrap. Requires WordPress test lib from wp-phpunit.
 *
 * Set SC_WP_TESTS_DIR or WP_TESTS_DIR to the wordpress-tests-lib directory
 * produced by bin/install-wp-tests.sh. When missing, Pest skips the suite.
 */

$testsDir = getenv('SC_WP_TESTS_DIR') ?: getenv('WP_TESTS_DIR') ?: '';
if ('' === $testsDir) {
    $testsDir = dirname(__DIR__) . '/tests/.wordpress/wordpress-tests-lib';
}

if (! is_readable($testsDir . '/includes/functions.php')) {
    fwrite(STDERR, "Signclave integration tests skipped: WordPress test lib not found.\n");
    fwrite(STDERR, "Install with bin/install-wp-tests.sh or set SC_WP_TESTS_DIR.\n");
    exit(0);
}

require dirname(__DIR__) . '/vendor/autoload.php';

require $testsDir . '/includes/functions.php';

tests_add_filter('muplugins_loaded', static function (): void {
    require dirname(__DIR__) . '/signclave-sso.php';
});

require $testsDir . '/includes/bootstrap.php';
