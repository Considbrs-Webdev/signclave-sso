<?php

declare(strict_types=1);

namespace Signclave\Support;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Settings\Options;

/**
 * Transient-based lockout for emergency password bypass.
 */
final class RateLimiter
{
    /**
     * @param Options $options Plugin options service.
     */
    public function __construct(
        private readonly Options $options
    ) {
    }

    /**
     * Return whether the scope/username/IP combination is currently locked out.
     *
     * @param string $scope    Rate limit scope identifier.
     * @param string $username Attempted username.
     * @param string $ip       Client IP address.
     */
    public function isLocked(string $scope, string $username, string $ip): bool
    {
        $lock = get_transient($this->key('lock', $scope, $username, $ip));

        return !empty($lock);
    }

    /**
     * Record a failed attempt and apply lockout when the limit is exceeded.
     *
     * @param string $scope    Rate limit scope identifier.
     * @param string $username Attempted username.
     * @param string $ip       Client IP address.
     */
    public function recordFailure(string $scope, string $username, string $ip): void
    {
        $limit = (int) $this->options->get('general', 'bypass_limit', 10);
        $window = (int) $this->options->get('general', 'bypass_window_seconds', 900);
        $lockout = (int) $this->options->get('general', 'bypass_lockout_seconds', 1800);
        $countKey = $this->key('count', $scope, $username, $ip);
        $lockKey = $this->key('lock', $scope, $username, $ip);
        $failCount = (int) get_transient($countKey);
        ++$failCount;
        set_transient($countKey, $failCount, $window);
        if ($failCount >= $limit) {
            set_transient($lockKey, 1, $lockout);
        }
    }

    /**
     * Clear failure counters after a successful attempt.
     *
     * @param string $scope    Rate limit scope identifier.
     * @param string $username Attempted username.
     * @param string $ip       Client IP address.
     */
    public function clearFailures(string $scope, string $username, string $ip): void
    {
        delete_transient($this->key('count', $scope, $username, $ip));
        delete_transient($this->key('lock', $scope, $username, $ip));
    }

    /**
     * Build a deterministic transient key for a rate limit bucket.
     *
     * @param string $kind     Key kind ("count" or "lock").
     * @param string $scope    Rate limit scope identifier.
     * @param string $username Attempted username.
     * @param string $ip       Client IP address.
     */
    private function key(string $kind, string $scope, string $username, string $ip): string
    {
        $fingerprint = hash('sha256', strtolower($scope . '|' . $username . '|' . $ip));

        return 'signclave_sso_' . $kind . '_' . substr($fingerprint, 0, 32);
    }
}
