<?php

declare(strict_types=1);

use Signclave\Vendor\ParagonIE\ConstantTime\Base64;
use Signclave\Vendor\phpseclib3\Crypt\PublicKeyLoader;
use Signclave\Vendor\phpseclib3\Crypt\RSA;
use Signclave\Vendor\phpseclib3\Crypt\RSA\PublicKey;
use Signclave\Vendor\RobRichards\XMLSecLibs\XMLSecurityDSig;

it('does not autoload unprefixed runtime dependencies', function (string $unprefixed) {
    expect(class_exists($unprefixed, true))->toBeFalse();
})->with([
    'xmlseclibs' => 'RobRichards\\XMLSecLibs\\XMLSecurityDSig',
    'phpseclib' => 'phpseclib3\\Crypt\\RSA',
    'constant_time_encoding' => 'ParagonIE\\ConstantTime\\Base64',
]);

it('autoloads prefixed runtime dependencies', function (string $prefixed) {
    expect(class_exists($prefixed, true))->toBeTrue();
})->with([
    'xmlseclibs' => XMLSecurityDSig::class,
    'phpseclib' => RSA::class,
    'constant_time_encoding' => Base64::class,
]);

it('loads an RSA public key from an X.509 certificate through prefixed phpseclib', function () {
    $cert = (string) file_get_contents(dirname(__DIR__) . '/fixtures/saml/idp.crt');

    expect(PublicKeyLoader::load($cert))->toBeInstanceOf(PublicKey::class);
});
