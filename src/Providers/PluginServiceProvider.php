<?php

declare(strict_types=1);

namespace Signclave\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Auth\PasswordBypass;
use Signclave\Cli\Commands;
use Signclave\Container;
use Signclave\Ldap\ClientInterface;
use Signclave\Ldap\Connection;
use Signclave\Ldap\UserLookup;
use Signclave\Plugin;
use Signclave\Saml\SignatureVerifier;
use Signclave\Settings\Options;
use Signclave\Support\Clock;
use Signclave\Support\Config;
use Signclave\Support\Logger;
use Signclave\Support\RateLimiter;
use Signclave\Support\SystemClock;
use Signclave\Support\View;
use Signclave\Users\RoleMapper;
use Signclave\Users\UserManager;
use WP_CLI;
use WP_Error;
use WP_User;

/**
 * Core plugin services, lifecycle hooks, and security logging.
 */
final class PluginServiceProvider implements ServiceProvider
{
    /**
     * @inheritDoc
     */
    public function register(Container $container): void
    {
        $container->singleton(Config::class, static fn () => new Config());
        $container->singleton(View::class, static fn () => new View());
        $container->singleton(Options::class, static fn () => new Options());
        $container->singleton(Clock::class, static fn () => new SystemClock());
        $container->singleton(
            Logger::class,
            static fn (Container $c) => new Logger($c->make(Options::class))
        );
        $container->singleton(
            RateLimiter::class,
            static fn (Container $c) => new RateLimiter($c->make(Options::class))
        );
        $container->singleton(
            RoleMapper::class,
            static fn (Container $c) => new RoleMapper($c->make(Options::class))
        );
        $container->singleton(
            UserManager::class,
            static fn (Container $c) => new UserManager(
                $c->make(RoleMapper::class),
                $c->make(Logger::class),
                $c->make(Options::class),
                $c->make(Clock::class)
            )
        );
        $container->singleton(
            PasswordBypass::class,
            static fn (Container $c) => new PasswordBypass(
                $c->make(Options::class),
                $c->make(RateLimiter::class)
            )
        );
        $container->singleton(
            Plugin::class,
            static fn (Container $c) => new Plugin(
                $c->make(Options::class)
            )
        );
    }

    /**
     * @inheritDoc
     */
    public function boot(Container $container): void
    {
        $plugin = $container->make(Plugin::class);
        assert($plugin instanceof Plugin);

        add_action('plugins_loaded', [$plugin, 'loadTextdomain'], 0);
        add_action('plugins_loaded', [$plugin, 'maybeUpgrade'], 0);
        add_action('plugins_loaded', [$plugin, 'trustProxySsl'], 1);

        $logger = $container->make(Logger::class);
        $bypass = $container->make(PasswordBypass::class);
        assert($logger instanceof Logger);
        assert($bypass instanceof PasswordBypass);

        $bypass->registerHooks();

        add_filter(
            'authenticate',
            static function (mixed $user, mixed $username) use ($bypass, $logger): mixed {
                $out = $bypass->enforceLocalAccountOnly($user, (string) $username);
                if ($bypass->isPasswordBypassRequest()) {
                    $logger->security(
                        'Password bypass authentication attempt.',
                        [
                            'user' => (string) $username,
                            'result' => $out instanceof WP_Error ? 'failed' : ($out instanceof WP_User ? 'passed' : 'deferred'),
                            'ip' => sanitize_text_field(wp_unslash((string) ($_SERVER['REMOTE_ADDR'] ?? ''))),
                        ]
                    );
                }

                return $out;
            },
            99,
            2
        );

        add_action(
            'wp_login',
            static function (mixed $user_login, mixed $user) use ($logger): void {
                $logger->security(
                    'Login success.',
                    [
                        'user' => (string) $user_login,
                        'userId' => $user instanceof WP_User ? (int) $user->ID : 0,
                        'ip' => sanitize_text_field(wp_unslash((string) ($_SERVER['REMOTE_ADDR'] ?? ''))),
                    ]
                );
            },
            10,
            2
        );

        add_action(
            'wp_logout',
            static function () use ($logger) {
                $logger->security(
                    'Logout.',
                    [
                        'ip' => sanitize_text_field(wp_unslash((string) ($_SERVER['REMOTE_ADDR'] ?? ''))),
                    ]
                );
            }
        );

        add_filter(
            'login_errors',
            static function () {
                return __('Invalid credentials.', 'signclave-sso');
            }
        );

        add_action(
            'signclave_sso_prune_logs',
            static function () use ($logger, $container): void {
                $options = $container->make(Options::class);
                assert($options instanceof Options);
                $logger->prune((int) $options->get('general', 'log_retention_days', 90));
            }
        );
        wp_clear_scheduled_hook('sls_prune_logs');
        wp_clear_scheduled_hook('sc_prune_logs');
        if (!wp_next_scheduled('signclave_sso_prune_logs')) {
            wp_schedule_event(time(), 'daily', 'signclave_sso_prune_logs');
        }

        if (defined('WP_CLI') && WP_CLI) {
            WP_CLI::add_command(
                'signclave',
                new Commands(
                    $container->make(Options::class),
                    $logger,
                    $bypass,
                    $container->make(Connection::class),
                    $container->make(ClientInterface::class),
                    $container->make(UserLookup::class),
                    $container->make(SignatureVerifier::class)
                )
            );
        }
    }
}
