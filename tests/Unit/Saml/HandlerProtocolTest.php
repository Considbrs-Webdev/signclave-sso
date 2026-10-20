<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Exception\InvalidAssertion;
use Signclave\Saml\Handler;
use Signclave\Settings\Options;
use Signclave\Tests\Support\OptionStore;

if (!function_exists('nocache_headers')) {
    function nocache_headers(): void
    {
    }
}

beforeEach(function () {
    OptionStore::reset();
    if (!function_exists('get_option')) {
        function get_option(string $key, mixed $default = false): mixed
        {
            return OptionStore::get($key, $default);
        }
    }
    if (!function_exists('site_url')) {
        function site_url(string $path = ''): string
        {
            return 'https://example.test/' . ltrim($path, '/');
        }
    }
});

it('rejects NameID elements that contain XML comments', function () {
    $xml = '<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin<!--x-->@evil.example</saml:NameID>';

    $dom = new DOMDocument();
    $dom->loadXML($xml);
    $el = $dom->documentElement;
    expect($el)->toBeInstanceOf(DOMElement::class);

    $handler = (new ReflectionClass(Handler::class))->newInstanceWithoutConstructor();
    $method = new ReflectionMethod(Handler::class, 'signedTextValue');
    $method->setAccessible(true);

    try {
        $method->invoke($handler, $el);
        expect(false)->toBeTrue('Expected InvalidAssertion');
    } catch (InvalidAssertion $e) {
        expect($e->reason)->toBe(AuthFailureReason::CommentInNameId);
    }
});

it('rejects oversized SAMLResponse before decoding', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => ['saml_response_max_bytes' => 100],
        ],
    ]);

    $handler = (new ReflectionClass(Handler::class))->newInstanceWithoutConstructor();
    $prop = new ReflectionProperty(Handler::class, 'options');
    $prop->setAccessible(true);
    $prop->setValue($handler, new Options());

    $_POST['SAMLResponse'] = str_repeat('A', 101);

    $method = new ReflectionMethod(Handler::class, 'processSamlAcs');
    $method->setAccessible(true);

    try {
        $method->invoke($handler);
        expect(false)->toBeTrue('Expected InvalidAssertion');
    } catch (InvalidAssertion $e) {
        expect($e->reason)->toBe(AuthFailureReason::SamlResponseTooLarge);
    }

    unset($_POST['SAMLResponse']);
});
