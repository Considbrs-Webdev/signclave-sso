<?php

declare(strict_types=1);

use Signclave\Settings\Options;
use Signclave\Support\RateLimiter;
use Signclave\Tests\Support\OptionStore;
use Signclave\Tests\Support\TransientStore;

it('locks after N failures and clears on success', function () {
    TransientStore::reset();
    $options = new Options();
    $stored = $options->defaults();
    $stored['general']['bypass_limit'] = 2;
    $stored['general']['bypass_window_seconds'] = 900;
    $stored['general']['bypass_lockout_seconds'] = 1800;
    OptionStore::seed(['signclave_sso_options' => $stored]);
    $limiter = new RateLimiter(new Options());

    expect($limiter->isLocked('password_bypass', 'alice', '1.1.1.1'))->toBeFalse();
    $limiter->recordFailure('password_bypass', 'alice', '1.1.1.1');
    expect($limiter->isLocked('password_bypass', 'alice', '1.1.1.1'))->toBeFalse();
    $limiter->recordFailure('password_bypass', 'alice', '1.1.1.1');
    expect($limiter->isLocked('password_bypass', 'alice', '1.1.1.1'))->toBeTrue();

    $limiter->clearFailures('password_bypass', 'alice', '1.1.1.1');
    expect($limiter->isLocked('password_bypass', 'alice', '1.1.1.1'))->toBeFalse();
});
