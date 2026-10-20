<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Settings\Options;
use Signclave\Support\FrozenClock;
use Signclave\Support\Logger;
use Signclave\Tests\Support\OptionStore;
use Signclave\Tests\Support\UserStore;
use Signclave\Users\RoleMapper;
use Signclave\Users\UserManager;

function scRoleManager(array $general = [], array $mappings = []): UserManager
{
    $options = new Options();
    $stored = $options->defaults();
    $stored['general'] = array_merge($stored['general'], $general);
    $stored['roles']['mappings'] = $mappings;
    OptionStore::seed(['signclave_sso_options' => $stored]);
    $options = new Options();

    return new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));
}

it('assigns the highest mapped role', function () {
    $user = new WP_User();
    $user->user_login = 'alice';
    UserStore::put($user);
    $manager = scRoleManager(
        ['role_strategy' => 'highest', 'role_priority' => 'administrator,editor,subscriber'],
        [
            ['source' => 'any', 'group' => 'editors', 'role' => 'editor'],
            ['source' => 'any', 'group' => 'subs', 'role' => 'subscriber'],
        ]
    );

    $manager->applyRoleMapping($user, ['editors', 'subs'], 'saml');

    expect($user->roles)->toBe(['editor']);
});

it('does not implicitly escalate beyond the mapping', function () {
    $user = new WP_User();
    $user->user_login = 'alice';
    $user->roles = ['subscriber'];
    UserStore::put($user);
    $manager = scRoleManager([], [
        ['source' => 'any', 'group' => 'subs', 'role' => 'subscriber'],
    ]);

    $manager->applyRoleMapping($user, ['subs'], 'saml');

    expect($user->roles)->not->toContain('administrator');
});

it('downgrades a managed role when the group is gone', function () {
    $user = new WP_User();
    $user->user_login = 'alice';
    $user->roles = ['editor'];
    UserStore::put($user);
    UserStore::setMeta($user->ID, 'signclave_sso_managed_roles', ['editor']);
    $manager = scRoleManager(['role_downgrade' => true], [
        ['source' => 'any', 'group' => 'editors', 'role' => 'editor'],
    ]);

    $manager->applyRoleMapping($user, [], 'saml');

    expect($user->roles)->not->toContain('editor');
});

it('keeps the administrator role for a protected login', function () {
    $user = new WP_User();
    $user->user_login = 'admin';
    $user->roles = ['administrator'];
    UserStore::put($user);
    UserStore::setMeta($user->ID, 'signclave_sso_managed_roles', ['administrator']);
    $manager = scRoleManager(
        ['role_downgrade' => true, 'protected_logins' => "admin\n"],
        [['source' => 'any', 'group' => 'editors', 'role' => 'editor']]
    );

    $manager->applyRoleMapping($user, [], 'saml');

    expect($user->roles)->toContain('administrator');
});

it('refuses to drop the last administrator', function () {
    $user = new WP_User();
    $user->user_login = 'only-admin';
    $user->roles = ['administrator'];
    UserStore::put($user);
    UserStore::setMeta($user->ID, 'signclave_sso_managed_roles', ['administrator']);
    $manager = scRoleManager(['role_downgrade' => true], []);

    $result = $manager->applyRoleMapping($user, [], 'saml');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(AuthFailureReason::LastAdminProtected->value);
});

it('denies login when no group matches and deny_if_no_group_match is on', function () {
    $user = new WP_User();
    $user->user_login = 'alice';
    UserStore::put($user);
    $manager = scRoleManager(
        ['deny_if_no_group_match' => true, 'role_downgrade' => false],
        [['source' => 'any', 'group' => 'editors', 'role' => 'editor']]
    );

    $result = $manager->applyRoleMapping($user, ['unknown'], 'saml');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(AuthFailureReason::NoGroup->value);
});
