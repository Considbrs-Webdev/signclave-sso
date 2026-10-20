<?php

declare(strict_types=1);

use Signclave\Settings\Options;
use Signclave\Tests\Support\OptionStore;
use Signclave\Users\RoleMapper;

function scMapper(array $mappings, string $strategy = 'highest'): RoleMapper
{
    $options = new Options();
    $stored = $options->defaults();
    $stored['roles']['mappings'] = $mappings;
    $stored['general']['role_strategy'] = $strategy;
    OptionStore::seed(['signclave_sso_options' => $stored]);

    return new RoleMapper(new Options());
}

it('parses source group and role mappings including DN CN extraction', function () {
    $mapper = scMapper([
        ['source' => 'saml', 'group' => 'editors', 'role' => 'editor'],
        ['source' => 'ldap', 'group' => 'admins', 'role' => 'administrator'],
    ]);

    expect($mapper->resolveRoles(['cn=editors,ou=groups,o=example'], 'saml'))->toBe(['editor'])
        ->and($mapper->resolveRoles(['editors'], 'ldap'))->toBe([]);
});

it('maps nothing for an unknown group', function () {
    $mapper = scMapper([
        ['source' => 'any', 'group' => 'editors', 'role' => 'editor'],
    ]);

    expect($mapper->resolveRoles(['unknown'], 'saml'))->toBe([]);
});

it('does not map a role missing from wp_roles', function () {
    $mapper = scMapper([
        ['source' => 'any', 'group' => 'vip', 'role' => 'not_a_real_role'],
        ['source' => 'any', 'group' => 'vip', 'role' => 'editor'],
    ]);

    expect($mapper->resolveRoles(['vip'], 'saml'))->toBe(['editor']);
});

it('respects Municipio custom roles that exist on the site', function () {
    $mapper = scMapper([
        ['source' => 'any', 'group' => 'muni', 'role' => 'municipio_admin'],
    ]);

    expect($mapper->resolveRoles(['muni'], 'saml'))->toBe(['municipio_admin']);
});

it('stops at the first match when strategy is first', function () {
    $mapper = scMapper([
        ['source' => 'any', 'group' => 'a', 'role' => 'subscriber'],
        ['source' => 'any', 'group' => 'b', 'role' => 'administrator'],
    ], 'first');

    expect($mapper->resolveRoles(['a', 'b'], 'saml'))->toBe(['subscriber']);
});
