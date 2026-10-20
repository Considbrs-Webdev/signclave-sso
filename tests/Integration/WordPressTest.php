<?php

declare(strict_types=1);

use Signclave\Admin\SettingsPage;
use Signclave\Auth\PasswordBypass;
use Signclave\Saml\Handler;
use Signclave\Saml\Metadata;
use Signclave\Settings\Options;
use Signclave\Support\Logger;
use Signclave\Support\RateLimiter;
use Signclave\Support\View;
use Signclave\Tests\Support\HandlerFactory;
use Signclave\Tests\Support\RedirectException;
use Signclave\Users\UserManager;

function scWpTests(): bool
{
    return defined('WP_TESTS_DOMAIN');
}

it('round-trips settings through Options::sanitize', function () {
    if (! scWpTests()) {
        skip('WordPress test library is not installed.');
    }
    $options = new Options();
    $page = new SettingsPage(
        new Logger($options),
        $options,
        new Metadata($options),
        new PasswordBypass($options, new RateLimiter($options)),
        new View()
    );
    $_POST['option_page'] = 'signclave_sso';
    $saved = $page->sanitizeOptions([
        'general' => [
            'auto_sso' => true,
            'default_role' => 'subscriber',
            'saml_clock_skew_seconds' => 90,
        ],
        'ldap' => [
            'hosts' => 'ldaps://ldap.example.test:636',
            'enabled' => true,
        ],
    ]);
    update_option('signclave_sso_options', $saved);
    $read = (new Options())->getAll();
    expect($read['general']['saml_clock_skew_seconds'])->toBe(90)
        ->and($read['ldap']['hosts'])->toBe('ldaps://ldap.example.test:636');
});

it('creates a WordPress user from SAML NameID via UserManager', function () {
    if (! scWpTests()) {
        skip('WordPress test library is not installed.');
    }
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $user = $factory->users->findOrCreateFromSaml(
        'nid-integration',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'https://idp.example.test/realms/test',
        'intuser',
        'intuser@example.test',
        'Int',
        'User'
    );
    expect($user)->toBeInstanceOf(WP_User::class);
    $again = $factory->users->findOrCreateFromSaml(
        'nid-integration',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'https://idp.example.test/realms/test',
        'intuser',
        'intuser-new@example.test',
        'Integer',
        'User'
    );
    expect($again->ID)->toBe($user->ID);
});

it('honours signclave_sso_allow_login veto', function () {
    if (! scWpTests()) {
        skip('WordPress test library is not installed.');
    }
    add_filter('signclave_sso_allow_login', static fn () => new WP_Error('nope', 'denied'));
    $factory = new HandlerFactory();
    $factory->seedOptions(['general' => ['allow_idp_initiated' => true]]);
    update_option('siteurl', 'https://sp.example.test');
    $_POST['SAMLResponse'] = base64_encode((string) file_get_contents(dirname(__DIR__) . '/fixtures/saml/no-inresponseto.xml'));
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected login denied');
    } catch (\Signclave\Exception\InvalidAssertion $e) {
        expect($e->reason->value)->toBe('login_denied');
    } catch (RedirectException) {
        expect(false)->toBeTrue('Veto should prevent redirect');
    }
});
