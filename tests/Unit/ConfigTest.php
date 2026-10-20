<?php

declare(strict_types=1);

use function Signclave\config;

it( 'reads app.name from config', function () {
	expect( config( 'app.name' ) )->toBe( 'signclave-sso' );
} );

it( 'returns default for unknown keys', function () {
	expect( config( 'app.missing_key', 'fallback' ) )->toBe( 'fallback' );
} );

it( 'reads option_key', function () {
	expect( config( 'app.option_key' ) )->toBe( 'signclave_sso_options' );
} );
