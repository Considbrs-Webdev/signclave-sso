<?php

declare(strict_types=1);

namespace Signclave;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Settings\Options;
use Signclave\Support\Logger;

/**
 * Plugin activation: log directory, log filenames, and emergency bypass key.
 */
final class Activator
{
    /**
     * Run activation tasks: secure log directory and ensure secrets exist.
     */
    public static function activate(): void
    {
        self::prepareLogDirectory();
        self::prepareOptions();
        self::scheduleLogPrune();
    }

    /**
     * Schedule daily log retention if it is not already scheduled.
     */
    public static function scheduleLogPrune(): void
    {
        wp_clear_scheduled_hook('sls_prune_logs');
        wp_clear_scheduled_hook('sc_prune_logs');
        if (!wp_next_scheduled('signclave_sso_prune_logs')) {
            wp_schedule_event(time(), 'daily', 'signclave_sso_prune_logs');
        }
    }

    /**
     * Create the uploads log directory and block direct web access to it.
     */
    private static function prepareLogDirectory(): void
    {
        $upload = wp_upload_dir();
        if (empty($upload['basedir'])) {
            return;
        }

        $dir = trailingslashit((string) $upload['basedir']) . 'signclave-sso';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }

        self::writeFile(trailingslashit($dir) . 'index.php', "<?php\n// Silence is golden.\n");
        self::writeFile(trailingslashit($dir) . '.htaccess', "Require all denied\n");
    }

    /**
     * Ensure the bypass key and randomized log filenames are present.
     */
    private static function prepareOptions(): void
    {
        $optionsService = new Options();
        $options = $optionsService->getAll();
        $changed = false;

        if ('' === (string) ($options['general']['password_bypass_key'] ?? '')) {
            $options['general']['password_bypass_key'] = wp_generate_password(32, false, false);
            $changed = true;
        }
        if ('' === (string) ($options['general']['log_file'] ?? '')) {
            $options['general']['log_file'] = Logger::randomLogFilename('sc');
            $changed = true;
        }
        if ('' === (string) ($options['general']['audit_log_file'] ?? '')) {
            $options['general']['audit_log_file'] = Logger::randomLogFilename('sc-audit');
            $changed = true;
        }

        if ($changed) {
            $optionsService->update($options);
        }
    }

    /**
     * Write a protective file via WP_Filesystem, falling back to a direct write.
     *
     * @param string $path     Absolute target path.
     * @param string $contents File contents.
     */
    private static function writeFile(string $path, string $contents): void
    {
        if (file_exists($path)) {
            return;
        }

        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        if ($wp_filesystem instanceof \WP_Filesystem_Base) {
            $wp_filesystem->put_contents($path, $contents, FS_CHMOD_FILE);

            return;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- fallback when WP_Filesystem is unavailable.
        file_put_contents($path, $contents);
    }
}
