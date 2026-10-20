<?php

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'name'       => 'signclave-sso',
	'textdomain' => 'signclave-sso',
	'version'    => defined( 'SIGNCLAVE_SSO_VERSION' ) ? SIGNCLAVE_SSO_VERSION : '0.0.0',
	'option_key' => 'signclave_sso_options',
);
