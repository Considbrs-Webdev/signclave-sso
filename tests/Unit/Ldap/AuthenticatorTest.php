<?php

declare(strict_types=1);

use Signclave\Auth\PasswordBypass;
use Signclave\Ldap\Authenticator;
use Signclave\Ldap\Connection;
use Signclave\Ldap\UserLookup;
use Signclave\Settings\Options;
use Signclave\Support\FrozenClock;
use Signclave\Support\Logger;
use Signclave\Support\RateLimiter;
use Signclave\Tests\Support\FakeLdapClient;
use Signclave\Tests\Support\OptionStore;
use Signclave\Users\RoleMapper;
use Signclave\Users\UserManager;

it('never treats an empty password as a successful bind', function () {
    $ldap = new FakeLdapClient();
    $ldap->seedDirectory([
        'alice' => [
            'dn' => 'cn=alice,ou=users,o=example',
            'password' => 'alice-secret',
            'attrs' => [
                'mail' => ['count' => 1, 0 => 'alice@example.test'],
                'givenname' => ['count' => 1, 0 => 'Alice'],
                'sn' => ['count' => 1, 0 => 'Example'],
                'cn' => ['count' => 1, 0 => 'alice'],
                'groupmembership' => ['count' => 0],
            ],
        ],
    ]);
    $options = new Options();
    $stored = $options->defaults();
    $stored['ldap']['enabled'] = true;
    $stored['ldap']['hosts'] = 'ldaps://ldap.example.test:636';
    $stored['ldap']['base_dn'] = 'ou=users,o=example';
    $stored['ldap']['bind_user'] = 'cn=ldap-service,ou=ldap,ou=system,o=example';
    $stored['ldap']['bind_password_encrypted'] = $options->encryptSecret('bind-secret');
    OptionStore::seed(['signclave_sso_options' => $stored]);
    $options = new Options();
    $users = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));
    $auth = new Authenticator(
        $ldap,
        new Logger($options),
        $users,
        new UserLookup($ldap, new Logger($options), new Connection($ldap), $options),
        new Connection($ldap),
        $options,
        new PasswordBypass($options, new RateLimiter($options))
    );

    expect($auth->authenticate(null, 'alice', ''))->toBeNull();
    expect($auth->authenticate(null, 'alice', 'wrong'))->toBeNull();

    $user = $auth->authenticate(null, 'alice', 'alice-secret');
    expect($user)->toBeInstanceOf(WP_User::class)
        ->and($user->user_login)->toBe('alice');
});
