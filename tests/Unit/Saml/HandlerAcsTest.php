<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Exception\InvalidAssertion;
use Signclave\Support\FrozenClock;
use Signclave\Tests\Support\HandlerFactory;
use Signclave\Tests\Support\RedirectException;
use Signclave\Tests\Support\TransientStore;

function scFixture(string $name): string
{
    return (string) file_get_contents(dirname(__DIR__, 2) . '/fixtures/saml/' . $name);
}

function scPostFixture(string $name): void
{
    $_POST['SAMLResponse'] = base64_encode(scFixture($name));
}

function scSeedRequest(string $id = '_req1'): void
{
    set_transient('signclave_sso_req_' . md5($id), 1, 300);
}

function scExpectReason(callable $run, AuthFailureReason $reason): void
{
    try {
        $run();
        expect(false)->toBeTrue('Expected InvalidAssertion ' . $reason->value);
    } catch (InvalidAssertion $e) {
        expect($e->reason)->toBe($reason);
    }
}

beforeEach(function () {
    TransientStore::reset();
});

it('accepts a valid unspecified NameID assertion and sets an auth cookie', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('valid-assertion.xml');

    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException $e) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt()
            ->and($e->location)->toContain('wp-admin');
    }
});

it('rejects a transient NameID format', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('transient-nameid.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::TransientNameId);
});

it('rejects two assertions in the same response', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('dual-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AssertionCountInvalid);
});

it('rejects a response-only signature', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scPostFixture('response-only.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::UnsignedAssertion);
});

it('accepts a response that also signs the assertion', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('both-signed.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
});

it('rejects a missing signature', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scPostFixture('unsigned-response.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SignatureValidationFailed);
});

it('rejects a tampered issuer after signing', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scPostFixture('tampered-issuer.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SignatureValidationFailed);
});

it('rejects a non-success status and keeps the status message in context', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('status-responder.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected InvalidAssertion');
    } catch (InvalidAssertion $e) {
        expect($e->reason)->toBe(AuthFailureReason::SamlStatusNotSuccess)
            ->and($e->context['status_message'] ?? '')->toBe('IdP denied the request');
    }
});

it('rejects the wrong audience', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('wrong-audience.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AudienceMismatch);
});

it('rejects the wrong destination', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('wrong-destination.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::DestinationMismatch);
});

it('rejects an unknown InResponseTo', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scPostFixture('valid-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SubjectConfirmationInvalid);
});

it('rejects an unsolicited response when IdP-initiated SSO is off', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions(['general' => ['allow_idp_initiated' => false]]);
    scPostFixture('no-inresponseto.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SubjectConfirmationInvalid);
});

it('accepts an unsolicited response when IdP-initiated SSO is on', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions(['general' => ['allow_idp_initiated' => true]]);
    scPostFixture('no-inresponseto.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
});

it('rejects a replayed response ID', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected first ACS to redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
    scSeedRequest();
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::ReplayBlocked);
});

it('rejects a pending request after its transient is gone', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    delete_transient('signclave_sso_req_' . md5('_req1'));
    scPostFixture('valid-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SubjectConfirmationInvalid);
});

it('rejects an expired assertion using FrozenClock', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW));
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('expired-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AssertionExpired);
});

it('rejects NotBefore 90 seconds in the future with 60s skew', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW));
    $factory->seedOptions(['general' => ['saml_clock_skew_seconds' => 60]]);
    scSeedRequest();
    scPostFixture('future-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AssertionNotYetValid);
});

it('accepts NotBefore 90 seconds in the future when skew is 180s', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW));
    $factory->seedOptions(['general' => ['saml_clock_skew_seconds' => 180]]);
    scSeedRequest();
    scPostFixture('future-assertion.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
});

it('accepts an assertion 30 seconds past NotOnOrAfter with 60s skew', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW + 3600 + 30));
    $factory->seedOptions(['general' => ['saml_clock_skew_seconds' => 60]]);
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
});

it('rejects an assertion 90 seconds past NotOnOrAfter with 60s skew', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW + 3600 + 90));
    $factory->seedOptions(['general' => ['saml_clock_skew_seconds' => 60]]);
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AssertionExpired);
});

it('clamps configured clock skew above 300 seconds', function () {
    $factory = new HandlerFactory(new FrozenClock(HandlerFactory::FIXTURE_NOW - 600));
    $factory->seedOptions(['general' => ['saml_clock_skew_seconds' => 999]]);
    scSeedRequest();
    scPostFixture('future-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::AssertionNotYetValid);
});

it('rejects invalid base64', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_POST['SAMLResponse'] = '%%%not-base64%%%';
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::InvalidSamlResponseEncoding);
});

it('rejects valid base64 that is not XML', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_POST['SAMLResponse'] = base64_encode('not xml at all');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SignatureValidationFailed);
});

it('rejects an empty SAMLResponse', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_POST['SAMLResponse'] = '';
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::MissingSamlResponse);
});

it('rejects XXE payloads before signature work', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_POST['SAMLResponse'] = base64_encode(scFixture('xxe.xml'));
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SignatureValidationFailed);
});

it('rejects billion-laughs entity expansion', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_POST['SAMLResponse'] = base64_encode(scFixture('billion-laughs.xml'));
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::SignatureValidationFailed);
});

it('rejects comment injection in NameID during ACS', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('comment-nameid.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::CommentInNameId);
});

it('rejects comment injection in uid AttributeValue during ACS', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('comment-uid.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::CommentInNameId);
});

it('accepts an assertion with empty NotOnOrAfter', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('empty-notonorafter.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException $e) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt()
            ->and($e->location)->toContain('wp-admin');
    }
});

it('rejects a new SAML user when LDAP is configured and down', function () {
    $factory = new HandlerFactory();
    $secret = $factory->options->encryptSecret('bind-secret');
    $factory->seedOptions([
        'ldap' => [
            'enabled' => true,
            'hosts' => 'ldaps://ldap.example.test:636',
            'base_dn' => 'ou=users,o=example',
            'bind_user' => 'cn=ldap-service,ou=ldap,ou=system,o=example',
            'bind_password_encrypted' => $secret,
        ],
    ]);
    $factory->ldap->serviceBindSucceeds = false;
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    scExpectReason(fn () => $factory->processAcs($factory->make()), AuthFailureReason::LdapVerificationFailed);
});

it('allows an existing SAML user when LDAP is configured and down', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $factory->users->findOrCreateFromSaml(
        'alice',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'https://idp.example.test/realms/test',
        'alice',
        'alice@example.test',
        'Alice',
        'Example'
    );
    $secret = $factory->options->encryptSecret('bind-secret');
    $factory->seedOptions([
        'ldap' => [
            'enabled' => true,
            'hosts' => 'ldaps://ldap.example.test:636',
            'base_dn' => 'ou=users,o=example',
            'bind_user' => 'cn=ldap-service,ou=ldap,ou=system,o=example',
            'bind_password_encrypted' => $secret,
        ],
    ]);
    $factory->ldap->serviceBindSucceeds = false;
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException) {
        expect($GLOBALS['sc_test_auth_user'])->toBeInt();
    }
});

it('redirects ACS RelayState to the signed destination', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    scSeedRequest();
    scPostFixture('valid-assertion.xml');
    $_REQUEST['redirect_to'] = 'https://sp.example.test/wp-admin/profile.php';
    $handler = $factory->make();
    $_POST['RelayState'] = $factory->invoke($handler, 'createRelayState');
    try {
        $factory->processAcs($handler);
        expect(false)->toBeTrue('Expected redirect');
    } catch (RedirectException $e) {
        expect($e->location)->toContain('profile.php');
    }
});

it('returns 405 when ACS is not POST', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    $_GET['signclave_sso_saml'] = 'acs';
    $_SERVER['REQUEST_METHOD'] = 'GET';
    try {
        $factory->make()->handleSamlRoutes();
        expect(false)->toBeTrue('Expected 405');
    } catch (RuntimeException $e) {
        expect($e->getMessage())->toBe('status_header:405')
            ->and($GLOBALS['sc_test_status'])->toBe(405);
    }
});
