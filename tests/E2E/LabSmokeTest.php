<?php

declare(strict_types=1);

function scE2eUrl(): string
{
    return rtrim(getenv('SC_E2E_URL') ?: 'https://saml-ldap-sso.test', '/');
}

function scE2eFetch(string $path): string|false
{
    $context = stream_context_create([
        'http' => [
            'timeout' => 8,
            'ignore_errors' => true,
            'follow_location' => 1,
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);

    return @file_get_contents(scE2eUrl() . $path, false, $context);
}

it('skips the Keycloak lab round-trip unless SC_E2E=1', function () {
    if (getenv('SC_E2E') !== '1') {
        skip('Set SC_E2E=1 after starting saml-dev and the WordPress lab.');
    }

    expect(scE2eFetch('/'))->not->toBeFalse();
});

it('serves well-formed SP metadata from the lab', function () {
    if (getenv('SC_E2E') !== '1') {
        skip('Set SC_E2E=1 after starting saml-dev and the WordPress lab.');
    }

    $xml = scE2eFetch('/?signclave_sso_saml=metadata');
    expect($xml)->not->toBeFalse()
        ->and($xml)->toContain('EntityDescriptor')
        ->and($xml)->toContain('AssertionConsumerService')
        ->and($xml)->toContain('WantAssertionsSigned="true"');
});

it('starts SSO with an HTTP-POST AuthnRequest form', function () {
    if (getenv('SC_E2E') !== '1') {
        skip('Set SC_E2E=1 after starting saml-dev and the WordPress lab.');
    }

    $html = scE2eFetch('/?signclave_sso_saml=login');
    expect($html)->not->toBeFalse()
        ->and(strtolower((string) $html))->toContain('samlrequest')
        ->and(strtolower((string) $html))->toContain('method="post"');
});
