<?php
/**
 * Uninstall: delete plugin options and upload log files.
 *
 * @package Signclave
 */

defined( 'ABSPATH' ) || exit;
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

( static function (): void {
	wp_clear_scheduled_hook( 'signclave_sso_prune_logs' );
	wp_clear_scheduled_hook( 'sc_prune_logs' );
	wp_clear_scheduled_hook( 'sls_prune_logs' );

	$generals = array();
	foreach ( array( 'signclave_sso_options', 'sls_options', 'sc_options' ) as $option_key ) {
		$stored = get_option( $option_key, array() );
		if ( is_array( $stored ) && isset( $stored['general'] ) && is_array( $stored['general'] ) ) {
			$generals[] = $stored['general'];
		}
		delete_option( $option_key );
	}

	global $wpdb;
	if ( $wpdb instanceof wpdb ) {
		$like_transient = $wpdb->esc_like( '_transient_signclave_sso_' ) . '%';
		$like_timeout   = $wpdb->esc_like( '_transient_timeout_signclave_sso_' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall must drop this plugin's transients.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$like_transient,
				$like_timeout
			)
		);
	}

	$upload = wp_upload_dir();
	if ( empty( $upload['basedir'] ) ) {
		return;
	}

	$dir = trailingslashit( $upload['basedir'] ) . 'signclave-sso';
	if ( ! is_dir( $dir ) ) {
		return;
	}

	$files = array( 'sc.log', 'sc-audit.log', 'index.php', '.htaccess' );
	foreach ( $generals as $general ) {
		foreach ( array( 'log_file', 'audit_log_file' ) as $key ) {
			$name = isset( $general[ $key ] ) ? basename( (string) $general[ $key ] ) : '';
			if ( '' !== $name && preg_match( '/^sc[a-z0-9._-]*\.log$/i', $name ) ) {
				$files[] = $name;
			}
		}
	}

	$stale = glob( trailingslashit( $dir ) . 'sc*.log' );
	if ( is_array( $stale ) ) {
		foreach ( $stale as $path ) {
			$files[] = basename( $path );
		}
	}

	foreach ( array_unique( $files ) as $file ) {
		$path = trailingslashit( $dir ) . $file;
		if ( is_file( $path ) ) {
			wp_delete_file( $path );
		}
	}

	if ( function_exists( 'rmdir' ) ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- empty log directory after wp_delete_file().
		rmdir( $dir );
	}
} )();
