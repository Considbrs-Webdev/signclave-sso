<?php

declare(strict_types=1);

namespace Signclave\Saml;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Settings\Options;

/**
 * SP metadata and ACS/Entity ID helpers.
 */
final class Metadata
{
    /**
     * @param Options $options Plugin options service.
     */
    public function __construct(
        private readonly Options $options
    ) {
    }

    /**
     * Return the configured service provider entity ID.
     */
    public function spEntityId(): string
    {
        return (string) $this->options->get('saml', 'sp_entity_id', site_url('/'));
    }

    /**
     * Return the assertion consumer service URL.
     */
    public function spAcsUrl(): string
    {
        return add_query_arg('signclave_sso_saml', 'acs', site_url('/'));
    }

    /**
     * Return the SP metadata endpoint URL.
     */
    public function spMetadataUrl(): string
    {
        return add_query_arg('signclave_sso_saml', 'metadata', site_url('/'));
    }

    /**
     * Build minimal SAML 2.0 SP metadata XML for IdP federation.
     */
    public function buildSpMetadataXml(): string
    {
        $entity = esc_attr($this->spEntityId());
        $acs = esc_url($this->spAcsUrl());
        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        $xml .= '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' . $entity . '">' . "\n";
        $xml .= '  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">' . "\n";
        $xml .= '    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>' . "\n";
        $xml .= '    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' . $acs . '" index="0" isDefault="true"/>' . "\n";
        $xml .= '  </SPSSODescriptor>' . "\n";
        $xml .= '</EntityDescriptor>';

        return $xml;
    }
}
