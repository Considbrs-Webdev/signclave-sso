<?php

declare(strict_types=1);

namespace Signclave\Tests\Support;

use Signclave\Auth\PasswordBypass;
use Signclave\Ldap\Connection;
use Signclave\Ldap\UserLookup;
use Signclave\Saml\Handler;
use Signclave\Saml\Metadata;
use Signclave\Saml\SignatureVerifier;
use Signclave\Settings\Options;
use Signclave\Support\Clock;
use Signclave\Support\FrozenClock;
use Signclave\Support\Logger;
use Signclave\Support\RateLimiter;
use Signclave\Users\RoleMapper;
use Signclave\Users\UserManager;

/**
 * Build a Handler with FrozenClock, FakeLdap, and in-memory options.
 */
final class HandlerFactory
{
    public const FIXTURE_NOW = 1718452800;

    public Options $options;

    public FrozenClock $clock;

    public FakeLdapClient $ldap;

    public Logger $logger;

    public UserManager $users;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock instanceof FrozenClock ? $clock : new FrozenClock(self::FIXTURE_NOW);
        $this->ldap = new FakeLdapClient();
        $this->options = new Options();
        $this->logger = new Logger($this->options);
        $this->users = new UserManager(new RoleMapper($this->options), $this->logger, $this->options, $this->clock);
    }

    /**
     * @param array<string, mixed> $overrides Nested option overrides.
     */
    public function seedOptions(array $overrides = []): void
    {
        $stored = $this->options->defaults();
        $stored['saml']['sp_entity_id'] = 'https://sp.example.test/';
        $stored['saml']['primary_entity_id'] = 'https://idp.example.test/realms/test';
        $stored['saml']['primary_sso_url'] = 'https://idp.example.test/realms/test/protocol/saml';
        $stored['saml']['primary_x509_cert'] = (string) file_get_contents(dirname(__DIR__) . '/fixtures/saml/idp.crt');
        $stored['general']['saml_strict_validation'] = true;
        $stored['general']['allow_idp_initiated'] = false;
        $stored['general']['saml_clock_skew_seconds'] = 60;
        foreach ($overrides as $section => $values) {
            if (is_array($values) && isset($stored[$section]) && is_array($stored[$section])) {
                $stored[$section] = array_merge($stored[$section], $values);
            }
        }
        OptionStore::seed(['signclave_sso_options' => $stored]);
        update_option('signclave_sso_options', $stored);
    }

    public function make(): Handler
    {
        $lookup = new UserLookup($this->ldap, $this->logger, new Connection($this->ldap), $this->options);

        return new Handler(
            new SignatureVerifier(),
            $this->users,
            $this->logger,
            $lookup,
            $this->options,
            new PasswordBypass($this->options, new RateLimiter($this->options)),
            new Metadata($this->options),
            $this->clock
        );
    }

    /**
     * @return mixed
     */
    public function processAcs(Handler $handler): mixed
    {
        $method = new \ReflectionMethod(Handler::class, 'processSamlAcs');

        return $method->invoke($handler);
    }

    /**
     * @return mixed
     */
    public function invoke(Handler $handler, string $method, mixed ...$args): mixed
    {
        $ref = new \ReflectionMethod(Handler::class, $method);

        return $ref->invoke($handler, ...$args);
    }
}
