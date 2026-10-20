<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Saml\SignatureVerifier;
use Signclave\Tests\Support\HandlerFactory;

function scSecurityFixture(string $name): string
{
    return (string) file_get_contents(dirname(__DIR__) . '/fixtures/saml/' . $name);
}

it('records wrapping as a signed assertion plus an unsigned sibling', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('dual-assertion.xml'), scSecurityFixture('idp.crt'));
    expect($result->ok)->toBeTrue()
        ->and($result->signedId)->toBe('_assertion1');

    $xp = new DOMXPath($result->dom);
    $assertions = $xp->query('//*[local-name()="Assertion"]');
    expect($assertions->length)->toBe(2);
});

it('rejects wrapping at ACS even when the signed assertion verifies', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    set_transient('signclave_sso_req_' . md5('_req1'), 1, 300);
    $_POST['SAMLResponse'] = base64_encode(scSecurityFixture('dual-assertion.xml'));
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected InvalidAssertion');
    } catch (Signclave\Exception\InvalidAssertion $e) {
        expect($e->reason)->toBe(AuthFailureReason::AssertionCountInvalid);
    }
});

it('does not collapse NameID across XML comments after verification', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('comment-nameid.xml'), scSecurityFixture('idp.crt'));
    expect($result->ok)->toBeTrue();
    $xp = new DOMXPath($result->dom);
    $nameId = $xp->query('//*[local-name()="NameID"]')->item(0);
    expect($nameId->textContent)->not->toBe('admin');
});

it('rejects comment injection in uid AttributeValue at ACS', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions();
    set_transient('signclave_sso_req_' . md5('_req1'), 1, 300);
    $_POST['SAMLResponse'] = base64_encode(scSecurityFixture('comment-uid.xml'));
    try {
        $factory->processAcs($factory->make());
        expect(false)->toBeTrue('Expected InvalidAssertion');
    } catch (Signclave\Exception\InvalidAssertion $e) {
        expect($e->reason)->toBe(AuthFailureReason::CommentInNameId);
    }
});

it('rejects a certificate swap', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('valid-assertion.xml'), scSecurityFixture('other.crt'));
    expect($result->ok)->toBeFalse();
});

it('rejects SHA-1 algorithm downgrade', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('sha1-assertion.xml'), scSecurityFixture('idp.crt'));
    expect($result->ok)->toBeFalse()->and($result->error)->toBe('sha1_rejected');
});

it('rejects XXE', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('xxe.xml'), scSecurityFixture('idp.crt'));
    expect($result->ok)->toBeFalse();
});

it('rejects entity expansion', function () {
    $result = (new SignatureVerifier())->verifySignedXml(scSecurityFixture('billion-laughs.xml'), scSecurityFixture('idp.crt'));
    expect($result->ok)->toBeFalse();
});

it('rejects oversized SAMLResponse before decode in the Handler', function () {
    $factory = new HandlerFactory();
    $factory->seedOptions(['general' => ['saml_response_max_bytes' => 100]]);
    $_POST['SAMLResponse'] = str_repeat('A', 101);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET['signclave_sso_saml'] = 'acs';
    try {
        $factory->make()->handleSamlRoutes();
        expect(false)->toBeTrue('Expected ACS rejection');
    } catch (RuntimeException $e) {
        expect($e->getMessage())->toBe('Invalid credentials.');
    }
});
