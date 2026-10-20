<?php

declare(strict_types=1);

namespace Signclave\Users;

if (! defined('ABSPATH')) {
    exit;
}

use Signclave\Auth\AuthFailureReason;
use Signclave\Settings\Options;
use Signclave\Support\Clock;
use Signclave\Support\Logger;
use WP_Error;
use WP_User;

/**
 * Create or update WordPress users after SAML or LDAP success.
 */
final class UserManager
{
    /**
     * @param RoleMapper $roleMapper Role mapping from IdP/LDAP groups.
     * @param Logger     $logger     Audit logger.
     * @param Options    $options    Plugin options.
     * @param Clock      $clock      Clock for user meta timestamps.
     */
    public function __construct(
        private readonly RoleMapper $roleMapper,
        private readonly Logger $logger,
        private readonly Options $options,
        private readonly Clock $clock
    ) {
    }

    /**
     * Find an existing WordPress user by login or optionally by email.
     */
    public function findExisting(string $username, string $email = ''): ?WP_User
    {
        $strict = ! str_contains($username, '@');
        $username = sanitize_user($username, $strict);
        if ('' === $username) {
            return null;
        }

        $user = get_user_by('login', $username);
        if (! $user && '' !== $email && $this->options->get('general', 'allow_email_account_linking', false)) {
            $user = get_user_by('email', sanitize_email($email));
        }

        return $user instanceof WP_User ? $user : null;
    }

    /**
     * Find a WordPress user by the IdP NameID stored at first login.
     *
     * @param string $nameId Persistent IdP subject identifier.
     */
    public function findByNameId(string $nameId): ?WP_User
    {
        $nameId = trim($nameId);
        if ('' === $nameId) {
            return null;
        }

        return $this->usersByMeta('signclave_sso_nameid', $nameId);
    }

    /**
     * Resolve the WordPress user for a SAML login, keyed on the IdP NameID.
     *
     * First login may bind to an existing user_login (local or previously
     * plugin-managed). After that, identity is the stored NameID. Username and
     * email are synchronised onto the profile but never decide who the user is.
     *
     * @param string $nameId       Subject NameID from the signed assertion.
     * @param string $nameIdFormat NameID Format attribute, if present.
     * @param string $idpEntity    Issuer entity ID of the asserting IdP.
     * @param string $username     Username candidate from assertion attributes.
     * @param string $email        Email from the assertion or directory.
     * @param string $firstName    Given name from the assertion or directory.
     * @param string $lastName     Surname from the assertion or directory.
     *
     * @return WP_User|WP_Error
     */
    public function findOrCreateFromSaml(
        string $nameId,
        string $nameIdFormat,
        string $idpEntity,
        string $username,
        string $email,
        string $firstName,
        string $lastName
    ): WP_User|WP_Error {
        $nameId = trim($nameId);
        if ('' === $nameId) {
            return AuthFailureReason::NameIdMissing->toWpError();
        }

        $known = $this->findByNameId($nameId);
        if ($known instanceof WP_User) {
            $this->syncProfile($known, $email, $firstName, $lastName);
            $this->storeIdentity($known, $nameId, $nameIdFormat, $idpEntity);

            return $known;
        }

        $login = sanitize_user($username, ! str_contains($username, '@'));
        if ('' === $login) {
            return AuthFailureReason::InvalidUser->toWpError();
        }

        $byLogin = get_user_by('login', $login);
        if ($byLogin instanceof WP_User) {
            if (! $this->isAdoptableAccount($byLogin)) {
                $this->logger->security(
                    'SAML NameID collision with an existing WordPress account.',
                    [
                        'user' => $login,
                        'idp' => $idpEntity,
                    ]
                );

                return AuthFailureReason::NameIdCollision->toWpError();
            }

            $this->syncProfile($byLogin, $email, $firstName, $lastName);
            $this->storeIdentity($byLogin, $nameId, $nameIdFormat, $idpEntity);
            $this->logger->security(
                'Bound IdP NameID to an existing WordPress account.',
                [
                    'user' => $login,
                    'idp' => $idpEntity,
                ]
            );

            return $byLogin;
        }

        $userId = wp_insert_user(
            [
                'user_login' => $login,
                'user_pass' => wp_generate_password(32, true, true),
                'user_email' => sanitize_email($email),
                'first_name' => sanitize_text_field($firstName),
                'last_name' => sanitize_text_field($lastName),
                'role' => $this->options->get('general', 'default_role', 'subscriber'),
            ]
        );
        if (is_wp_error($userId)) {
            return $userId;
        }

        $user = get_user_by('id', $userId);
        if (! $user instanceof WP_User) {
            return AuthFailureReason::InvalidUser->toWpError();
        }
        $this->storeIdentity($user, $nameId, $nameIdFormat, $idpEntity);

        return $user;
    }

    /**
     * @return WP_User|WP_Error
     */
    public function findOrCreate(string $username, string $email, string $firstName, string $lastName, string $source): WP_User|WP_Error
    {
        $strict = ! str_contains($username, '@');
        $username = sanitize_user($username, $strict);
        if ('' === $username) {
            return AuthFailureReason::InvalidUser->toWpError();
        }

        $user = $this->findExisting($username, $email);

        if (! $user) {
            $role = $this->options->get('general', 'default_role', 'subscriber');
            $userId = wp_insert_user(
                [
                    'user_login' => $username,
                    'user_pass' => wp_generate_password(32, true, true),
                    'user_email' => sanitize_email($email),
                    'first_name' => sanitize_text_field($firstName),
                    'last_name' => sanitize_text_field($lastName),
                    'role' => $role,
                ]
            );
            if (is_wp_error($userId)) {
                return $userId;
            }
            $user = get_user_by('id', $userId);
        } else {
            $update = [
                'ID' => $user->ID,
                'first_name' => sanitize_text_field($firstName),
                'last_name' => sanitize_text_field($lastName),
            ];
            if ('' !== $email) {
                $update['user_email'] = sanitize_email($email);
            }
            wp_update_user($update);
        }

        if (! $user instanceof WP_User) {
            return AuthFailureReason::InvalidUser->toWpError();
        }

        $this->writeUserMeta($user->ID, 'source', $source);
        $this->writeUserMeta($user->ID, 'last_login', $this->clock->now());

        return $user;
    }

    /**
     * Apply group-to-role mappings, optionally revoking roles that no longer match.
     *
     * Only roles this plugin granted (tracked in `signclave_sso_managed_roles`) are ever
     * revoked, and never in a way that leaves the site without an administrator.
     *
     * @param WP_User      $user   User to update.
     * @param list<string> $groups Directory or assertion groups.
     * @param string       $source Mapping source ("saml" or "ldap").
     *
     * @return WP_User|WP_Error
     */
    public function applyRoleMapping(WP_User $user, array $groups, string $source): WP_User|WP_Error
    {
        $roles = $this->roleMapper->resolveRoles($groups, $source);
        $filtered = apply_filters('signclave_sso_user_roles', $roles, $user, $groups, $source);
        if (is_array($filtered)) {
            $roles = array_values(array_filter(array_map('strval', $filtered), static fn (string $role): bool => '' !== $role));
        }
        $downgrade = (bool) $this->options->get('general', 'role_downgrade', true);
        $denyWithoutMatch = (bool) $this->options->get('general', 'deny_if_no_group_match', false);
        $hasMappings = ! empty($this->options->get('roles', 'mappings', []));

        if (empty($roles)) {
            if ($downgrade) {
                $revoked = $this->revokeManagedRoles($user, []);
                if ($revoked instanceof WP_Error) {
                    return $revoked;
                }
            }
            if ($denyWithoutMatch && $hasMappings) {
                return AuthFailureReason::NoGroup->toWpError();
            }

            return $user;
        }

        $strategy = $this->options->get('general', 'role_strategy', 'highest');
        if ('all' === $strategy) {
            $target = $roles;
        } else {
            $target = ['first' === $strategy ? $roles[0] : $this->highestRole($roles)];
        }

        if ($downgrade) {
            $revoked = $this->revokeManagedRoles($user, $target);
            if ($revoked instanceof WP_Error) {
                return $revoked;
            }
        }

        foreach ($target as $role) {
            $user->add_role($role);
        }
        $this->writeUserMeta($user->ID, 'managed_roles', array_values($target));

        return $user;
    }

    /**
     * Remove previously mapped roles that are no longer granted.
     *
     * @param WP_User      $user User to update.
     * @param list<string> $keep Roles that must be preserved.
     *
     * @return WP_Error|null Error when the removal would drop the last administrator.
     */
    private function revokeManagedRoles(WP_User $user, array $keep): ?WP_Error
    {
        $managed = $this->readUserMeta($user->ID, 'managed_roles');
        $managed = is_array($managed) ? $managed : [];
        if ([] === $managed) {
            return null;
        }

        $protected = $this->isProtectedLogin((string) $user->user_login);
        $remaining = [];
        foreach ($managed as $role) {
            $role = (string) $role;
            if ('' === $role) {
                continue;
            }
            if (in_array($role, $keep, true)) {
                $remaining[] = $role;
                continue;
            }
            if ('administrator' === $role) {
                if ($protected) {
                    $this->logger->security(
                        'Kept administrator role for a protected login.',
                        ['user' => (string) $user->user_login]
                    );
                    $remaining[] = $role;
                    continue;
                }
                if ($this->isLastAdministrator($user)) {
                    $this->logger->security(
                        'Refused to remove the last administrator via role mapping.',
                        ['user' => (string) $user->user_login]
                    );

                    return AuthFailureReason::LastAdminProtected->toWpError();
                }
            }
            $user->remove_role($role);
        }

        $this->writeUserMeta($user->ID, 'managed_roles', array_values(array_unique($remaining)));

        return null;
    }

    /**
     * Whether removing the administrator role from this user would leave none.
     */
    private function isLastAdministrator(WP_User $user): bool
    {
        if (! in_array('administrator', (array) $user->roles, true)) {
            return false;
        }

        $admins = get_users(
            [
                'role' => 'administrator',
                'fields' => 'ID',
                'number' => 2,
                'count_total' => false,
            ]
        );
        $others = array_filter(
            array_map('intval', is_array($admins) ? $admins : []),
            static function (int $id) use ($user): bool {
                return $id !== (int) $user->ID;
            }
        );

        return [] === $others;
    }

    /**
     * Whether a login is listed as protected from automatic role removal.
     */
    private function isProtectedLogin(string $login): bool
    {
        $login = strtolower(trim($login));
        if ('' === $login) {
            return false;
        }

        return in_array($login, $this->protectedLogins(), true);
    }

    /**
     * Configured logins that never lose the administrator role.
     *
     * @return list<string>
     */
    private function protectedLogins(): array
    {
        $raw = (string) $this->options->get('general', 'protected_logins', '');
        $lines = preg_split('/\R/', $raw);
        $logins = [];
        foreach (is_array($lines) ? $lines : [] as $line) {
            $line = strtolower(trim((string) $line));
            if ('' !== $line) {
                $logins[] = $line;
            }
        }

        return array_values(array_unique($logins));
    }

    /**
     * Pick the highest-priority role according to the configured order.
     *
     * @param list<string> $roles Candidate roles.
     */
    private function highestRole(array $roles): string
    {
        $order = $this->rolePriorityOrder();
        $best = $roles[0];
        $score = $this->roleScore($best, $order);
        foreach ($roles as $role) {
            $roleScore = $this->roleScore($role, $order);
            if ($roleScore > $score) {
                $score = $roleScore;
                $best = $role;
            }
        }

        return $best;
    }

    /**
     * Score a role by its position in the priority order (higher wins).
     *
     * @param string       $role  Role slug.
     * @param list<string> $order Priority order, most privileged first.
     */
    private function roleScore(string $role, array $order): int
    {
        $index = array_search($role, $order, true);
        if (false === $index) {
            return 0;
        }

        return count($order) - (int) $index;
    }

    /**
     * Build the role priority order from settings, then any remaining site roles.
     *
     * @return list<string>
     */
    private function rolePriorityOrder(): array
    {
        $order = [];
        foreach (explode(',', (string) $this->options->get('general', 'role_priority', '')) as $role) {
            $role = sanitize_key(trim((string) $role));
            if ('' !== $role) {
                $order[] = $role;
            }
        }

        $siteRoles = function_exists('wp_roles') ? array_keys(wp_roles()->role_names) : [];
        foreach ($siteRoles as $role) {
            $role = (string) $role;
            if ('' !== $role && ! in_array($role, $order, true)) {
                $order[] = $role;
            }
        }

        return array_values(array_unique($order));
    }

    /**
     * Whether an existing account may be bound to an incoming NameID.
     *
     * First SAML login may bind to a matching user_login, including a local
     * WordPress account that predates SSO (LDAP is not required). A login that
     * already stores a different NameID is a collision. After bind, NameID is
     * the identity key — username and email never decide who the user is.
     */
    private function isAdoptableAccount(WP_User $user): bool
    {
        return ! $this->userMetaPresent($this->readUserMeta($user->ID, 'nameid'));
    }

    /**
     * Persist the IdP identity keys for a user.
     *
     * @param WP_User $user         User to update.
     * @param string  $nameId       Subject NameID.
     * @param string  $nameIdFormat NameID Format attribute.
     * @param string  $idpEntity    Issuer entity ID.
     */
    private function storeIdentity(WP_User $user, string $nameId, string $nameIdFormat, string $idpEntity): void
    {
        $this->writeUserMeta($user->ID, 'nameid', $nameId);
        $this->writeUserMeta($user->ID, 'nameid_format', sanitize_text_field($nameIdFormat));
        $this->writeUserMeta($user->ID, 'idp_entity', sanitize_text_field($idpEntity));
        $this->writeUserMeta($user->ID, 'source', 'saml');
        $this->writeUserMeta($user->ID, 'last_login', $this->clock->now());
    }

    /**
     * Update mutable profile fields from the assertion. Never changes user_login.
     */
    private function syncProfile(WP_User $user, string $email, string $firstName, string $lastName): void
    {
        $update = [
            'ID' => $user->ID,
            'first_name' => sanitize_text_field($firstName),
            'last_name' => sanitize_text_field($lastName),
        ];
        $email = sanitize_email($email);
        if ('' !== $email && $email !== $user->user_email) {
            $update['user_email'] = $email;
        }
        wp_update_user($update);
    }

    /**
     * Find one user stored under a NameID meta key.
     */
    private function usersByMeta(string $metaKey, string $nameId): ?WP_User
    {
        $users = get_users(
            [
                'meta_key' => $metaKey, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- unique NameID usermeta lookup, number=1.
                'meta_value' => $nameId, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- unique NameID usermeta lookup, number=1.
                'number' => 1,
                'count_total' => false,
            ]
        );
        $user = is_array($users) ? ($users[0] ?? null) : null;

        return $user instanceof WP_User ? $user : null;
    }

    /**
     * Read plugin user meta.
     */
    private function readUserMeta(int $userId, string $suffix): mixed
    {
        return get_user_meta($userId, 'signclave_sso_' . $suffix, true);
    }

    /**
     * Write plugin user meta.
     */
    private function writeUserMeta(int $userId, string $suffix, mixed $value): void
    {
        update_user_meta($userId, 'signclave_sso_' . $suffix, $value);
    }

    /**
     * Whether a meta value was actually stored.
     */
    private function userMetaPresent(mixed $value): bool
    {
        if (is_array($value)) {
            return [] !== $value;
        }
        if (is_int($value)) {
            return true;
        }

        return is_string($value) && '' !== $value;
    }
}
