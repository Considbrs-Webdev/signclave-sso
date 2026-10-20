<?php

declare(strict_types=1);

use Signclave\Settings\Options;
use Signclave\Tests\Support\OptionStore;

it('reads sls_options until the first update writes signclave_sso_options', function () {
    $options = new Options();
    $cipher = $options->encryptSecret('bind-secret');
    OptionStore::seed([
        'sls_options' => [
            'general' => [
                'auto_sso' => false,
                'log_file' => 'sls-old.log',
            ],
            'ldap' => [
                'bind_password_encrypted' => $cipher,
            ],
        ],
    ]);

    expect($options->get('general', 'auto_sso'))->toBeFalse()
        ->and($options->get('general', 'log_file'))->toBe('sls-old.log')
        ->and($options->decryptSecret($cipher))->toBe('bind-secret')
        ->and(get_option('signclave_sso_options', false))->toBeFalse();

    $options->update($options->getAll());

    $stored = get_option('signclave_sso_options', false);
    expect($stored)->toBeArray()
        ->and(get_option('sls_options', false))->toBeFalse()
        ->and($stored['general']['auto_sso'])->toBeFalse()
        ->and($stored['general']['log_file'])->toBe('')
        ->and($options->decryptSecret((string) $stored['ldap']['bind_password_encrypted']))->toBe('bind-secret');
});
