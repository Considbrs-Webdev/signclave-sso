<?php
/**
 * Plugin Name: Signclave – SSO for SAML and LDAP
 * Plugin URI: https://github.com/Considbrs-Webdev/saml-ldap-sso
 * Description: Secure SAML SSO + LDAP authentication for WordPress.
 * Version: 0.1.21
 * Author: Consid Borås
 * Author URI: https://profiles.wordpress.org/considboras/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.0
 * Requires PHP: 8.2
 * Text Domain: signclave-sso
 * Domain Path: /resources/languages
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

define( 'SIGNCLAVE_SSO_VERSION', '0.1.21' );
define( 'SIGNCLAVE_SSO_PLUGIN_FILE', __FILE__ );

use Signclave\Activator;
use Signclave\Application;
use Signclave\Providers\AdminServiceProvider;
use Signclave\Providers\LdapServiceProvider;
use Signclave\Providers\PluginServiceProvider;
use Signclave\Providers\SamlServiceProvider;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$pluginAutoloader = __DIR__ . '/vendor/autoload.php';

if ( file_exists( $pluginAutoloader ) ) {
	$autoloader = $pluginAutoloader;
} else {
	$currentDir = realpath( __DIR__ );
	$maxDepth   = 10;
	$depth      = 0;
	$autoloader = null;

	while ( $depth < $maxDepth && false !== $currentDir ) {
		$parentDir = dirname( $currentDir );
		if ( $parentDir === $currentDir ) {
			break;
		}

		$vendorAutoloader = $parentDir . '/vendor/autoload.php';
		if ( file_exists( $vendorAutoloader ) ) {
			$autoloader = $vendorAutoloader;
			break;
		}

		$currentDir = $parentDir;
		++$depth;
	}

	if ( ! $autoloader || ! file_exists( $autoloader ) ) {
		wp_die(
			'Signclave: Could not find Composer autoloader. ' .
			'Run "composer install --no-dev" in the plugin directory.'
		);
	}
}

require_once $autoloader;

$prefixedAutoloader = __DIR__ . '/vendor-prefixed/autoload.php';
if (file_exists($prefixedAutoloader)) {
	require_once $prefixedAutoloader;
}

require_once __DIR__ . '/helpers.php';

// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

register_activation_hook( __FILE__, array( Activator::class, 'activate' ) );

Application::configure()
	->withProviders(
		array(
			PluginServiceProvider::class,
			SamlServiceProvider::class,
			LdapServiceProvider::class,
			AdminServiceProvider::class,
		)
	)
	->boot();
