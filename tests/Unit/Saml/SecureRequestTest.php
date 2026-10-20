<?php

declare(strict_types=1);

use Signclave\Saml\Handler;
use Signclave\Settings\Options;
use Signclave\Tests\Support\OptionStore;

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
    if (!function_exists('is_ssl')) {
        function is_ssl(): bool
        {
            return false;
        }
    }
});

it('ignores X-Forwarded-Proto when trust_proxy_headers is off', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => ['trust_proxy_headers' => false],
        ],
    ]);

    $handler = (new ReflectionClass(Handler::class))->newInstanceWithoutConstructor();
    $prop = new ReflectionProperty(Handler::class, 'options');
    $prop->setAccessible(true);
    $prop->setValue($handler, new Options());

    $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';

    $method = new ReflectionMethod(Handler::class, 'isSecureRequest');
    $method->setAccessible(true);

    expect($method->invoke($handler))->toBeFalse();

    unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
});

it('honours X-Forwarded-Proto when trust_proxy_headers is on', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => ['trust_proxy_headers' => true],
        ],
    ]);

    $handler = (new ReflectionClass(Handler::class))->newInstanceWithoutConstructor();
    $prop = new ReflectionProperty(Handler::class, 'options');
    $prop->setAccessible(true);
    $prop->setValue($handler, new Options());

    $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';

    $method = new ReflectionMethod(Handler::class, 'isSecureRequest');
    $method->setAccessible(true);

    expect($method->invoke($handler))->toBeTrue();

    unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
});
