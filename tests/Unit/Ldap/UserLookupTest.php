<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Ldap\Connection;
use Signclave\Ldap\UserLookup;
use Signclave\Settings\Options;
use Signclave\Support\Logger;
use Signclave\Tests\Support\FakeLdapClient;
use Signclave\Tests\Support\OptionStore;

function scLdapOptions(array $ldapOverrides = []): Options
{
    $options = new Options();
    $stored = $options->defaults();
    $stored['ldap']['enabled'] = true;
    $stored['ldap']['hosts'] = 'ldaps://ldap.example.test:636';
    $stored['ldap']['base_dn'] = 'ou=users,o=example';
    $stored['ldap']['bind_user'] = 'cn=ldap-service,ou=ldap,ou=system,o=example';
    $stored['ldap']['bind_password_encrypted'] = $options->encryptSecret('bind-secret');
    $stored['ldap']['allow_insecure_ldap'] = false;
    $stored['ldap'] = array_merge($stored['ldap'], $ldapOverrides);
    OptionStore::seed(['signclave_sso_options' => $stored]);

    return new Options();
}

function scFakeAlice(FakeLdapClient $ldap): void
{
    $ldap->seedDirectory([
        'alice' => [
            'dn' => 'cn=alice,ou=users,o=example',
            'password' => 'alice-secret',
            'attrs' => [
                'mail' => ['count' => 1, 0 => 'alice@example.test'],
                'givenname' => ['count' => 1, 0 => 'Alice'],
                'sn' => ['count' => 1, 0 => 'Example'],
                'cn' => ['count' => 1, 0 => 'alice'],
                'groupmembership' => [
                    'count' => 1,
                    0 => 'cn=editors,ou=groups,o=example',
                ],
            ],
        ],
    ]);
}

it('finds a user after service bind over ldaps without StartTLS', function () {
    $ldap = new FakeLdapClient();
    scFakeAlice($ldap);
    $options = scLdapOptions();
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    $user = $lookup->findUser('alice');

    expect($user)->not->toBeInstanceOf(AuthFailureReason::class)
        ->and($ldap->startTlsCalled)->toBeFalse()
        ->and($user->username)->toBe('alice')
        ->and($user->groups)->toContain('cn=editors,ou=groups,o=example');
});

it('returns user not found for an unknown cn', function () {
    $ldap = new FakeLdapClient();
    scFakeAlice($ldap);
    $options = scLdapOptions();
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    expect($lookup->findUser('bob'))->toBe(AuthFailureReason::LdapUserNotFound);
});

it('rejects LDAP injection characters in the username', function () {
    $ldap = new FakeLdapClient();
    $options = scLdapOptions();
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    expect($lookup->findUser('alice)'))->toBe(AuthFailureReason::LdapInvalidUsername)
        ->and($lookup->findUser('al*ice'))->toBe(AuthFailureReason::LdapInvalidUsername);
});

it('escapes backslashes in the LDAP filter', function () {
    $ldap = new FakeLdapClient();
    scFakeAlice($ldap);
    $options = scLdapOptions();
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);
    $lookup->findUser('alice\\x');

    expect($ldap->lastFilter)->toContain('\\5c');
});

it('fails closed when the service bind fails', function () {
    $ldap = new FakeLdapClient();
    $ldap->serviceBindSucceeds = false;
    scFakeAlice($ldap);
    $options = scLdapOptions();
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    expect($lookup->findUser('alice'))->toBe(AuthFailureReason::LdapBindFailed);
});

it('fails closed when StartTLS fails on ldap://', function () {
    $ldap = new FakeLdapClient();
    $ldap->startTlsSucceeds = false;
    scFakeAlice($ldap);
    $options = scLdapOptions([
        'hosts' => 'ldap://ldap.example.test:389',
        'allow_insecure_ldap' => false,
    ]);
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    expect($lookup->findUser('alice'))->toBe(AuthFailureReason::LdapStartTlsFailed)
        ->and($ldap->startTlsCalled)->toBeTrue();
});

it('skips StartTLS for ldaps://', function () {
    $ldap = new FakeLdapClient();
    scFakeAlice($ldap);
    $options = scLdapOptions(['hosts' => 'ldaps://ldap.example.test:636']);
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);
    $lookup->findUser('alice');

    expect($ldap->startTlsCalled)->toBeFalse();
});

it('allows plaintext ldap:// when allow_insecure is on', function () {
    $ldap = new FakeLdapClient();
    scFakeAlice($ldap);
    $options = scLdapOptions([
        'hosts' => 'ldap://ldap.example.test:389',
        'allow_insecure_ldap' => true,
    ]);
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);
    $user = $lookup->findUser('alice');

    expect($user)->not->toBeInstanceOf(AuthFailureReason::class)
        ->and($ldap->startTlsCalled)->toBeFalse();
});

it('fails over to the second host', function () {
    $ldap = new FakeLdapClient();
    $ldap->failHost('ldaps://ldap-down.example.test:636');
    scFakeAlice($ldap);
    $options = scLdapOptions([
        'hosts' => 'ldaps://ldap-down.example.test:636,ldaps://ldap.example.test:636',
    ]);
    $lookup = new UserLookup($ldap, new Logger($options), new Connection($ldap), $options);

    expect($lookup->findUser('alice'))->not->toBeInstanceOf(AuthFailureReason::class)
        ->and($ldap->connectHosts)->toBe([
            'ldaps://ldap-down.example.test:636',
            'ldaps://ldap.example.test:636',
        ]);
});
