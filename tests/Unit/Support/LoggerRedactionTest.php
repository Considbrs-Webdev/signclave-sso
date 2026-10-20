<?php

declare(strict_types=1);

use Signclave\Settings\Options;
use Signclave\Support\Logger;
use Signclave\Tests\Support\OptionStore;

it('redacts passwords assertions and secrets from log context', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $logger = new Logger(new Options());
    $method = new ReflectionMethod(Logger::class, 'sanitizeContext');

    $clean = $method->invoke($logger, [
        'user' => 'alice',
        'bind_password' => 'super-secret',
        'saml_response' => 'PHNhbWw+',
        'assertion' => '<Assertion/>',
        'token' => 'abc',
        'note' => str_repeat('x', 2500),
    ]);

    expect($clean['user'])->toBe('alice')
        ->and($clean['bind_password'])->toBe('[REDACTED]')
        ->and($clean['saml_response'])->toBe('[REDACTED]')
        ->and($clean['assertion'])->toBe('[REDACTED]')
        ->and($clean['token'])->toBe('[REDACTED]')
        ->and($clean['note'])->toEndWith('…[truncated]');
});
