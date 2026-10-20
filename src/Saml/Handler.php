<?php

declare(strict_types=1);

namespace Signclave\Saml;

if (! defined('ABSPATH')) {
    exit;
}

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Assertion failures are logged; the browser only sees a fixed escaped message.

use DOMAttr;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMNodeList;
use DOMXPath;
use Signclave\Auth\AuthFailureReason;
use Signclave\Auth\PasswordBypass;
use Signclave\Exception\InvalidAssertion;
use Signclave\Ldap\UserLookup;
use Signclave\Settings\Options;
use Signclave\Support\Clock;
use Signclave\Support\Logger;
use Signclave\Users\UserManager;
use Throwable;
use WP_Error;
use WP_User;

use function Signclave\config;

// phpcs:disable WordPress.Security.NonceVerification -- SAML ACS/login and wp-login query routing are not WordPress forms.

/**
 * SAML SP: login redirect, ACS, and metadata.
 */
final class Handler
{
    /**
     * @param SignatureVerifier $crypto         XML-DSig verifier.
     * @param UserManager       $users          WordPress user provisioning.
     * @param Logger            $logger         Audit/security logger.
     * @param UserLookup        $ldapLookup     Optional LDAP attribute enrichment.
     * @param Options           $options        Plugin options.
     * @param PasswordBypass    $passwordBypass Emergency password login gate.
     * @param Metadata          $metadata       SP metadata helper.
     * @param Clock             $clock          Clock for IssueInstant timestamps.
     */
    public function __construct(
        private readonly SignatureVerifier $crypto,
        private readonly UserManager $users,
        private readonly Logger $logger,
        private readonly UserLookup $ldapLookup,
        private readonly Options $options,
        private readonly PasswordBypass $passwordBypass,
        private readonly Metadata $metadata,
        private readonly Clock $clock
    ) {
    }

    /**
     * Register WordPress hooks for SAML routes and auto-redirect.
     */
    public function registerHooks(): void
    {
        add_action('init', [$this, 'handleSamlRoutes'], 1);
        add_action('login_init', [$this, 'autoRedirectToSso'], 1);
        add_action('login_footer', [$this, 'renderLoginSsoButton']);
        add_action('login_enqueue_scripts', [$this, 'enqueueLoginStyles']);
    }

    /**
     * Redirect unauthenticated wp-login requests to the IdP when auto-SSO is enabled.
     */
    public function autoRedirectToSso(): void
    {
        if (! $this->options->get('general', 'auto_sso', true)) {
            return;
        }

        if (is_user_logged_in()) {
            return;
        }

        if ('' !== $this->samlRouteParam()) {
            return;
        }

        $action = isset($_REQUEST['action']) ? sanitize_text_field(wp_unslash((string) $_REQUEST['action'])) : '';
        if (in_array($action, ['logout', 'lostpassword', 'rp', 'resetpass', 'register'], true)) {
            return;
        }

        if ($this->passwordBypass->isPasswordBypassRequest()) {
            $ip = sanitize_text_field(wp_unslash((string) ($_SERVER['REMOTE_ADDR'] ?? '')));
            $this->logger->security('Password bypass requested.', ['ip' => $ip]);

            return;
        }

        $saml = $this->options->getAll()['saml'];
        if (! $this->isIdpConfigured($saml)) {
            return;
        }

        wp_safe_redirect($this->buildLoginUrl());
        exit;
    }

    /**
     * Print a full-width Log in with SSO button below the login form when auto-SSO is off.
     */
    public function renderLoginSsoButton(): void
    {
        if (! $this->shouldShowSsoLoginLink()) {
            return;
        }

        printf(
            '<p class="sc-sso-login" id="sc-sso-login"><a class="button button-primary button-large" href="%1$s">%2$s</a></p>',
            esc_url($this->buildLoginUrl()),
            esc_html__('Log in with SSO', 'signclave-sso')
        );
    }

    /**
     * Style the SSO button and move it directly under #loginform.
     */
    public function enqueueLoginStyles(): void
    {
        if (! $this->shouldShowSsoLoginLink()) {
            return;
        }

        wp_add_inline_style(
            'login',
            '.sc-sso-login{width:320px;max-width:100%;margin:16px auto 0}#login .sc-sso-login{width:100%;margin-left:0;margin-right:0}.sc-sso-login .button{display:block;width:100%;box-sizing:border-box;float:none;height:auto;text-align:center}'
        );

        wp_register_script('signclave-sso-login', false, [], (string) config('app.version'), true);
        wp_enqueue_script('signclave-sso-login');
        wp_add_inline_script(
            'signclave-sso-login',
            'var scForm=document.getElementById("loginform");var scBtn=document.getElementById("sc-sso-login");if(scForm&&scBtn){scForm.insertAdjacentElement("afterend",scBtn);}'
        );
    }

    /**
     * Whether the login screen should offer a manual SAML start link.
     */
    private function shouldShowSsoLoginLink(): bool
    {
        if ($this->options->get('general', 'auto_sso', true)) {
            return false;
        }

        if (is_user_logged_in()) {
            return false;
        }

        $action = isset($_REQUEST['action']) ? sanitize_text_field(wp_unslash((string) $_REQUEST['action'])) : '';
        if (in_array($action, ['logout', 'lostpassword', 'rp', 'resetpass', 'register'], true)) {
            return false;
        }

        return $this->isIdpConfigured($this->options->getAll()['saml']);
    }

    /**
     * @param array<string, mixed> $saml SAML option section.
     */
    private function isIdpConfigured(array $saml): bool
    {
        return '' !== trim((string) ($saml['primary_sso_url'] ?? ''))
            && '' !== trim((string) ($saml['primary_x509_cert'] ?? ''));
    }

    /**
     * Dispatch ?signclave_sso_saml= login, ACS, or metadata routes.
     */
    public function handleSamlRoutes(): void
    {
        $route = $this->samlRouteParam();
        if ('' === $route) {
            return;
        }
        if ('login' === $route) {
            $this->samlLogin();
        } elseif ('acs' === $route) {
            $this->samlAcs();
        } elseif ('metadata' === $route) {
            $this->samlMetadata();
        }
    }

    /**
     * Build and POST an AuthnRequest to the configured IdP.
     */
    private function samlLogin(): void
    {
        if (is_user_logged_in()) {
            wp_safe_redirect($this->requestedRedirectTarget());
            exit;
        }

        $saml = $this->options->getAll()['saml'];
        $ssoUrl = (string) $saml['primary_sso_url'];
        $entityId = (string) $this->options->get('saml', 'sp_entity_id', site_url('/'));
        if ('' === $ssoUrl || '' === $entityId) {
            wp_die(esc_html__('SSO is not configured.', 'signclave-sso'));
        }

        $requestId = '_' . wp_generate_password(22, false, false);
        set_transient('signclave_sso_req_' . md5($requestId), 1, (int) $this->options->get('general', 'saml_request_ttl_seconds', 300));

        $acsUrl = $this->acsUrl();
        $issue = $this->clock->formatGmt('Y-m-d\TH:i:s\Z');
        $xml = sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%1$s" Version="2.0" IssueInstant="%2$s" Destination="%3$s" AssertionConsumerServiceURL="%4$s"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%5$s</saml:Issuer></samlp:AuthnRequest>',
            esc_attr($requestId),
            esc_attr($issue),
            esc_url_raw($ssoUrl),
            esc_url_raw($acsUrl),
            esc_html($entityId)
        );
        $xml = (string) apply_filters('signclave_sso_authn_request', $xml, $saml);

        $relay = $this->createRelayState();
        $samlReq = base64_encode($xml);

        $this->postAuthnRequestToIdp($ssoUrl, $samlReq, $relay);
    }

    /**
     * Handle the SAML Assertion Consumer Service endpoint.
     */
    private function samlAcs(): void
    {
        $method = isset($_SERVER['REQUEST_METHOD'])
            ? strtoupper(sanitize_text_field(wp_unslash((string) $_SERVER['REQUEST_METHOD'])))
            : '';
        if ('POST' !== $method) {
            status_header(405);
            exit;
        }

        try {
            $this->processSamlAcs();
        } catch (InvalidAssertion $e) {
            $this->logger->security(
                'SAML ACS rejected login.',
                array_merge(
                    ['reason' => $e->reason->logCode()],
                    $e->context
                )
            );
            wp_die(esc_html__('Invalid credentials.', 'signclave-sso'));
        } catch (Throwable $e) {
            $this->logger->security(
                'SAML ACS rejected login.',
                [
                    'reason' => AuthFailureReason::AcsException->logCode(),
                    'message' => $e->getMessage(),
                    'file' => basename($e->getFile()),
                    'line' => $e->getLine(),
                ]
            );
            wp_die(esc_html__('Invalid credentials.', 'signclave-sso'));
        }
    }

    /**
     * Validate the SAML response, provision the user, and establish a WordPress session.
     */
    private function processSamlAcs(): void
    {
        nocache_headers();

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IdP POST; base64 XML must not pass sanitize_text_field.
        $response = isset($_POST['SAMLResponse']) ? (string) wp_unslash($_POST['SAMLResponse']) : '';
        if ('' === $response) {
            throw new InvalidAssertion(AuthFailureReason::MissingSamlResponse);
        }

        $maxBytes = (int) $this->options->get('general', 'saml_response_max_bytes', 262144);
        if ($maxBytes > 0 && strlen($response) > $maxBytes) {
            throw new InvalidAssertion(
                AuthFailureReason::SamlResponseTooLarge,
                [
                    'bytes' => strlen($response),
                    'max_bytes' => $maxBytes,
                ]
            );
        }

        $decoded = base64_decode($response, true);
        if (false === $decoded) {
            throw new InvalidAssertion(AuthFailureReason::InvalidSamlResponseEncoding);
        }

        $saml = $this->options->getAll()['saml'];
        $check = $this->crypto->verifySignedXml(
            $decoded,
            SignatureVerifier::normalizeCertPem((string) ($saml['primary_x509_cert'] ?? '')),
            SignatureVerifier::normalizeCertPem((string) ($saml['secondary_x509_cert'] ?? ''))
        );
        if (! $check->ok || ! ($check->dom instanceof DOMDocument)) {
            $detail = '' !== $check->error ? $check->error : 'signature_validation_failed';
            throw new InvalidAssertion($this->signatureFailureReason($detail), ['detail' => $detail]);
        }

        $dom = $check->dom;
        $xp = new DOMXPath($dom);
        $xp->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $responseNode = $this->xpathFirstElement($xp, '/*[local-name()="Response"]');
        if (! $responseNode) {
            throw new InvalidAssertion(AuthFailureReason::MissingResponseNode);
        }

        $signedId = $check->signedId;
        if ('' === $signedId) {
            throw new InvalidAssertion(AuthFailureReason::MissingSignedId);
        }
        if ('Assertion' !== $check->signedNodeName) {
            throw new InvalidAssertion(
                AuthFailureReason::UnsignedAssertion,
                ['signed_node' => $check->signedNodeName]
            );
        }

        $allAssertions = $xp->query('//*[local-name()="Assertion"]');
        if (! $allAssertions || 1 !== $allAssertions->length) {
            throw new InvalidAssertion(
                AuthFailureReason::AssertionCountInvalid,
                ['count' => $allAssertions ? $allAssertions->length : 0]
            );
        }
        $assertionNode = $allAssertions->item(0);
        if (! ($assertionNode instanceof DOMElement)) {
            throw new InvalidAssertion(AuthFailureReason::SignedNodeInvalid);
        }
        // The only assertion in the document must be the one the signature covered.
        if (! hash_equals($signedId, (string) $assertionNode->getAttribute('ID'))) {
            throw new InvalidAssertion(AuthFailureReason::SignedNodeNotFound);
        }

        $status = trim($this->xpathString($xp, '/*[local-name()="Response"]/*[local-name()="Status"]/*[local-name()="StatusCode"]/@Value'));
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $status) {
            throw new InvalidAssertion(
                AuthFailureReason::SamlStatusNotSuccess,
                [
                    'status' => $status,
                    'status_message' => trim($this->xpathString(
                        $xp,
                        '/*[local-name()="Response"]/*[local-name()="Status"]/*[local-name()="StatusMessage"]'
                    )),
                ]
            );
        }

        $responseId = $this->xpathString($xp, '/*[local-name()="Response"]/@ID');
        $replayKey = 'signclave_sso_replay_' . md5($responseId);
        if ('' === $responseId || get_transient($replayKey)) {
            throw new InvalidAssertion(
                AuthFailureReason::ReplayBlocked,
                ['response_id' => $responseId]
            );
        }
        set_transient($replayKey, 1, 600);

        $destination = trim($this->xpathString($xp, '/*[local-name()="Response"]/@Destination'));
        if ($this->isSamlStrict() && '' === $destination) {
            throw new InvalidAssertion(AuthFailureReason::DestinationMissing);
        }
        if ('' !== $destination && ! $this->samlUrlsMatch($this->acsUrl(), $destination)) {
            throw new InvalidAssertion(
                AuthFailureReason::DestinationMismatch,
                [
                    'expected' => $this->acsUrl(),
                    'actual' => $destination,
                ]
            );
        }

        $issuer = trim($this->xpathString($xp, './*[local-name()="Issuer"]', $assertionNode));
        if ('' === $issuer) {
            $issuer = trim($this->xpathString($xp, '/*[local-name()="Response"]/*[local-name()="Issuer"]'));
        }
        $idpEntity = (string) $saml['primary_entity_id'];
        if ($this->isSamlStrict() && '' === $idpEntity) {
            throw new InvalidAssertion(AuthFailureReason::IdpEntityNotConfigured);
        }
        if ('' !== $idpEntity && ! $this->samlEntityIdsMatch($idpEntity, $issuer)) {
            throw new InvalidAssertion(
                AuthFailureReason::IssuerMismatch,
                [
                    'expected' => $idpEntity,
                    'actual' => $issuer,
                ]
            );
        }

        $this->validateAssertionConditions($xp, $assertionNode);
        $attrs = $this->extractAttributes($xp, $assertionNode);

        $username = $this->getAttributeValues($attrs, (string) $saml['primary_username_attr'])[0] ?? '';
        $email = $this->getAttributeValues($attrs, (string) $saml['primary_email_attr'])[0] ?? '';
        $first = $this->getAttributeValues($attrs, (string) $saml['primary_first_name_attr'])[0] ?? '';
        $last = $this->getAttributeValues($attrs, (string) $saml['primary_last_name_attr'])[0] ?? '';
        $groups = $this->getAttributeValues($attrs, (string) $saml['primary_group_attr']);

        $nameIdElement = $this->xpathFirstElement($xp, './*[local-name()="Subject"]/*[local-name()="NameID"]', $assertionNode);
        $nameId = null !== $nameIdElement ? trim($this->signedTextValue($nameIdElement)) : '';
        $nameIdFormat = null !== $nameIdElement ? trim((string) $nameIdElement->getAttribute('Format')) : '';
        if ('' === $nameId) {
            throw new InvalidAssertion(AuthFailureReason::NameIdMissing);
        }
        if ($this->isTransientNameIdFormat($nameIdFormat)) {
            throw new InvalidAssertion(
                AuthFailureReason::TransientNameId,
                ['format' => $nameIdFormat]
            );
        }

        if ('' === $username) {
            $username = $nameId;
        }

        $mapped = apply_filters(
            'signclave_sso_map_attributes',
            [
                'username' => $username,
                'email' => $email,
                'first' => $first,
                'last' => $last,
                'groups' => $groups,
                'nameId' => $nameId,
            ],
            $attrs
        );
        if (is_array($mapped)) {
            $username = (string) ($mapped['username'] ?? $username);
            $email = (string) ($mapped['email'] ?? $email);
            $first = (string) ($mapped['first'] ?? $first);
            $last = (string) ($mapped['last'] ?? $last);
            $groups = isset($mapped['groups']) && is_array($mapped['groups'])
                ? array_values(array_map('strval', $mapped['groups']))
                : $groups;
            // Identity stays the signed assertion NameID. The filter may read
            // `nameId` but cannot rebind the WordPress account.
        }

        if ('' === trim($username)) {
            throw new InvalidAssertion(
                AuthFailureReason::MissingUsername,
                [
                    'attribute_names' => array_keys($attrs),
                    'configured_attr' => (string) $saml['primary_username_attr'],
                ]
            );
        }

        // LDAP-down is allowed only when a WP user already exists (NameID or user_login). Email is not identity.
        $existing = $this->users->findByNameId($nameId) ?? $this->users->findExisting($username, '');
        $filled = $this->enrichFromLdap($username, $email, $first, $last, $groups, $existing);
        $email = $filled['email'];
        $first = $filled['first'];
        $last = $filled['last'];
        $groups = $filled['groups'];

        $user = $this->users->findOrCreateFromSaml($nameId, $nameIdFormat, $issuer, $username, $email, $first, $last);
        if ($user instanceof WP_Error) {
            throw new InvalidAssertion(
                $this->userErrorReason($user, AuthFailureReason::UserCreateFailed),
                ['code' => $user->get_error_code()]
            );
        }
        $mapped = $this->users->applyRoleMapping($user, $groups, 'saml');
        if ($mapped instanceof WP_Error) {
            throw new InvalidAssertion(
                $this->userErrorReason($mapped, AuthFailureReason::RoleMappingDenied),
                ['code' => $mapped->get_error_code()]
            );
        }

        $allow = apply_filters(
            'signclave_sso_allow_login',
            true,
            $user,
            [
                'source' => 'saml',
                'groups' => $groups,
                'nameId' => $nameId,
                'issuer' => $issuer,
            ]
        );
        if ($allow instanceof WP_Error) {
            throw new InvalidAssertion(
                AuthFailureReason::LoginDenied,
                [
                    'code' => $allow->get_error_code(),
                    'message' => $allow->get_error_message(),
                ]
            );
        }

        if (function_exists('wp_destroy_current_session')) {
            wp_destroy_current_session();
        }
        wp_clear_auth_cookie();
        // phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core hooks.
        $secure = (bool) apply_filters('secure_auth_cookie', $this->isSecureRequest(), $user->ID);
        wp_set_auth_cookie($user->ID, false, $secure);
        wp_set_current_user($user->ID, $user->user_login);
        do_action('wp_login', $user->user_login, $user);
        // phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

        $relay = isset($_POST['RelayState'])
            ? sanitize_text_field(wp_unslash((string) $_POST['RelayState']))
            : '';
        $dest = $this->validateRelayState($relay);
        $dest = $this->sanitizeRedirectTarget($dest);
        wp_safe_redirect($dest);
        exit;
    }

    /**
     * Map a signature verification error string to a failure reason.
     *
     * @param string $detail Raw verifier error text.
     */
    private function signatureFailureReason(string $detail): AuthFailureReason
    {
        if (str_contains($detail, 'sha1_rejected')) {
            return AuthFailureReason::Sha1Rejected;
        }
        if (str_contains($detail, 'unsigned_assertion')) {
            return AuthFailureReason::UnsignedAssertion;
        }

        return AuthFailureReason::SignatureValidationFailed;
    }

    /**
     * Map a WP_Error code raised by UserManager to a failure reason.
     *
     * @param WP_Error          $error    Error returned by user provisioning or role mapping.
     * @param AuthFailureReason $fallback Reason used when the code is not a known reason.
     */
    private function userErrorReason(WP_Error $error, AuthFailureReason $fallback): AuthFailureReason
    {
        return AuthFailureReason::tryFrom((string) $error->get_error_code()) ?? $fallback;
    }

    /**
     * Read the text of a leaf element without trusting DOMNode::textContent.
     *
     * A signature covers the canonicalized element, so an injected comment node
     * splits the text content and lets `admin<!---->@evil.example` be read as
     * `admin` while the signature still validates (the 2018 Duo SAML bug).
     * Comment nodes are therefore rejected outright and only direct text or
     * CDATA children are concatenated.
     *
     * @param DOMElement $element Leaf element such as NameID or AttributeValue.
     *
     * @throws InvalidAssertion When the element contains a comment node.
     */
    private function signedTextValue(DOMElement $element): string
    {
        $value = '';
        foreach ($element->childNodes as $child) {
            if (XML_COMMENT_NODE === $child->nodeType) {
                throw new InvalidAssertion(
                    AuthFailureReason::CommentInNameId,
                    ['element' => (string) $element->localName]
                );
            }
            if (XML_TEXT_NODE === $child->nodeType || XML_CDATA_SECTION_NODE === $child->nodeType) {
                $value .= (string) $child->nodeValue;
            }
        }

        return $value;
    }

    /**
     * When LDAP is usable: look up the user to fill empty SAML fields.
     * Directory failure is fatal only if WordPress would have to create a new account.
     *
     * @param list<string> $groups
     * @return array{email:string,first:string,last:string,groups:list<string>}
     */
    private function enrichFromLdap(string $username, string $email, string $first, string $last, array $groups, ?WP_User $existing): array
    {
        if (! $this->options->mustVerifyLdapForSaml()) {
            return compact('email', 'first', 'last', 'groups');
        }

        $ldapUser = $this->ldapLookup->findUser($username);
        if ($ldapUser instanceof AuthFailureReason) {
            if (! $existing) {
                throw new InvalidAssertion(
                    AuthFailureReason::LdapVerificationFailed,
                    ['code' => $ldapUser->logCode()]
                );
            }

            return compact('email', 'first', 'last', 'groups');
        }

        if ('' === $email && '' !== $ldapUser->email) {
            $email = $ldapUser->email;
        }
        if ('' === $first && '' !== $ldapUser->firstName) {
            $first = $ldapUser->firstName;
        }
        if ('' === $last && '' !== $ldapUser->lastName) {
            $last = $ldapUser->lastName;
        }
        if (empty($groups) && ! empty($ldapUser->groups)) {
            $groups = array_values($ldapUser->groups);
        }

        return compact('email', 'first', 'last', 'groups');
    }

    /**
     * Return the first node matching an XPath query.
     */
    private function xpathFirst(DOMXPath $xp, string $query, ?DOMNode $context = null): ?DOMNode
    {
        $list = $context ? $xp->query($query, $context) : $xp->query($query);
        if (! $list instanceof DOMNodeList || $list->length < 1) {
            return null;
        }
        $node = $list->item(0);

        return $node instanceof DOMNode ? $node : null;
    }

    /**
     * Return the first DOMElement matching an XPath query.
     */
    private function xpathFirstElement(DOMXPath $xp, string $query, ?DOMNode $context = null): ?DOMElement
    {
        $node = $this->xpathFirst($xp, $query, $context);

        return $node instanceof DOMElement ? $node : null;
    }

    /**
     * Return the string value of the first node matching an XPath query.
     */
    private function xpathString(DOMXPath $xp, string $query, ?DOMNode $context = null): string
    {
        $node = $this->xpathFirst($xp, $query, $context);
        if (! $node) {
            return '';
        }
        if ($node instanceof DOMAttr) {
            return (string) $node->value;
        }

        return (string) $node->textContent;
    }

    /**
     * Validate SAML assertion time, audience, and subject confirmation constraints.
     */
    private function validateAssertionConditions(DOMXPath $xp, DOMElement $assertionNode): void
    {
        $now = $this->clock->now();
        $skew = min(300, max(0, (int) $this->options->get('general', 'saml_clock_skew_seconds', 60)));

        $notBefore = trim($this->xpathString($xp, './/*[local-name()="Conditions"]/@NotBefore', $assertionNode));
        $notAfter = trim($this->xpathString($xp, './/*[local-name()="Conditions"]/@NotOnOrAfter', $assertionNode));
        if ('' !== $notBefore && strtotime($notBefore) > ($now + $skew)) {
            throw new InvalidAssertion(
                AuthFailureReason::AssertionNotYetValid,
                ['not_before' => $notBefore]
            );
        }
        if ('' !== $notAfter && strtotime($notAfter) <= ($now - $skew)) {
            throw new InvalidAssertion(
                AuthFailureReason::AssertionExpired,
                ['not_after' => $notAfter]
            );
        }

        $audience = trim($this->xpathString($xp, './/*[local-name()="Audience"]', $assertionNode));
        $expected = (string) $this->options->get('saml', 'sp_entity_id', site_url('/'));
        if ($this->isSamlStrict() && '' === $audience) {
            throw new InvalidAssertion(AuthFailureReason::AudienceMissing);
        }
        if ('' !== $audience && ! $this->samlUrlsMatch($expected, $audience)) {
            throw new InvalidAssertion(
                AuthFailureReason::AudienceMismatch,
                [
                    'expected' => $expected,
                    'actual' => $audience,
                ]
            );
        }

        $scdNodes = $xp->query('.//*[local-name()="SubjectConfirmationData"]', $assertionNode);
        if (! $scdNodes || 0 === $scdNodes->length) {
            throw new InvalidAssertion(AuthFailureReason::MissingSubjectConfirmation);
        }
        $validConfirmation = false;
        $strict = $this->isSamlStrict();
        $allowIdpInitiated = (bool) $this->options->get('general', 'allow_idp_initiated', false);
        foreach ($scdNodes as $scdNode) {
            if (! ($scdNode instanceof DOMElement)) {
                continue;
            }
            $recipient = trim((string) $scdNode->getAttribute('Recipient'));
            $scdNoa = trim((string) $scdNode->getAttribute('NotOnOrAfter'));
            $inResponseTo = trim((string) $scdNode->getAttribute('InResponseTo'));
            if ($strict && '' === $recipient) {
                continue;
            }
            if ('' !== $recipient && ! $this->samlUrlsMatch($this->acsUrl(), $recipient)) {
                continue;
            }
            if ('' !== $scdNoa && strtotime($scdNoa) <= ($now - $skew)) {
                continue;
            }

            if ('' === $inResponseTo) {
                // Unsolicited (IdP-initiated) response: no request ID to bind to,
                // so the Recipient must pin the response to this ACS endpoint.
                if (! $allowIdpInitiated) {
                    continue;
                }
                if ('' === $recipient || ! $this->samlUrlsMatch($this->acsUrl(), $recipient)) {
                    continue;
                }
                $validConfirmation = true;
                break;
            }

            $requestKey = 'signclave_sso_req_' . md5($inResponseTo);
            if (! get_transient($requestKey)) {
                continue;
            }
            // Single-use: a matched AuthnRequest ID cannot be replayed.
            delete_transient($requestKey);
            $validConfirmation = true;
            break;
        }
        if (! $validConfirmation) {
            throw new InvalidAssertion(
                AuthFailureReason::SubjectConfirmationInvalid,
                ['allow_idp_initiated' => $allowIdpInitiated]
            );
        }
    }

    /**
     * @return array<string, list<string>>
     */
    private function extractAttributes(DOMXPath $xp, DOMElement $assertionNode): array
    {
        $result = [];
        $attrs = $xp->query('.//*[local-name()="AttributeStatement"]//*[local-name()="Attribute"]', $assertionNode);
        if (! $attrs) {
            return $result;
        }
        foreach ($attrs as $attr) {
            if (! ($attr instanceof DOMElement)) {
                continue;
            }
            $name = trim((string) $attr->getAttribute('Name'));
            $friendly = trim((string) $attr->getAttribute('FriendlyName'));
            if ('' === $name && '' === $friendly) {
                continue;
            }
            $values = [];
            foreach ($attr->childNodes as $child) {
                if ($child instanceof DOMElement && 'AttributeValue' === $child->localName) {
                    $values[] = trim($this->signedTextValue($child));
                }
            }
            if ('' !== $name) {
                $result[$name] = array_merge($result[$name] ?? [], $values);
            }
            if ('' !== $friendly && $friendly !== $name) {
                $result[$friendly] = array_merge($result[$friendly] ?? [], $values);
            }
        }

        return $result;
    }

    /**
     * @param array<string, list<string>> $attrs
     * @return list<string>
     */
    private function getAttributeValues(array $attrs, string $configuredName): array
    {
        if ('' === $configuredName) {
            return [];
        }
        if (isset($attrs[$configuredName])) {
            return $this->normalizeGroupValues($attrs[$configuredName]);
        }

        $needle = strtolower($configuredName);
        foreach ($attrs as $name => $values) {
            $lowerName = strtolower((string) $name);
            if ($lowerName === $needle || str_ends_with($lowerName, '/' . $needle) || str_ends_with($lowerName, ':' . $needle)) {
                return $this->normalizeGroupValues($values);
            }
        }

        return [];
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function normalizeGroupValues(array $values): array
    {
        $normalized = [];
        foreach ($values as $value) {
            $value = trim((string) $value);
            if ('' === $value) {
                continue;
            }
            if (str_contains($value, '|')) {
                foreach (preg_split('/\s*\|\s*/', $value) as $part) {
                    $part = trim((string) $part);
                    if ('' !== $part) {
                        $normalized[] = $part;
                    }
                }
                continue;
            }
            $normalized[] = $value;
        }

        return array_values(array_unique($normalized));
    }

    /**
     * Serve SP metadata XML.
     */
    private function samlMetadata(): void
    {
        header('Content-Type: text/xml; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo $this->metadata->buildSpMetadataXml(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- XML document.
        exit;
    }

    /**
     * Build the plugin login route URL that starts SAML authentication.
     */
    private function buildLoginUrl(): string
    {
        return add_query_arg(
            'signclave_sso_saml',
            'login',
            wp_login_url($this->requestedRedirectTarget())
        );
    }

    /**
     * Read the SAML route from the current query.
     */
    private function samlRouteParam(): string
    {
        if (empty($_GET['signclave_sso_saml'])) {
            return '';
        }

        return sanitize_text_field(wp_unslash((string) $_GET['signclave_sso_saml']));
    }

    /**
     * Return the configured Assertion Consumer Service URL.
     */
    private function acsUrl(): string
    {
        return $this->metadata->spAcsUrl();
    }

    /**
     * HMAC a RelayState blob.
     */
    private function relayMac(string $blob): string
    {
        $key = hash_hkdf('sha256', wp_salt('auth'), 32, 'sc-relay');

        return hash_hmac('sha256', $blob, $key);
    }

    /**
     * Create a signed RelayState blob carrying the post-login redirect target.
     */
    private function createRelayState(): string
    {
        $safe = $this->requestedRedirectTarget();
        $issued = $this->clock->now();
        $json = wp_json_encode(['url' => $safe, 'iat' => $issued]);
        $blob = base64_encode(is_string($json) ? $json : '');

        return $blob . '.' . $this->relayMac($blob);
    }

    /**
     * Validate and decode a RelayState blob, returning a safe redirect target.
     */
    private function validateRelayState(string $relay): string
    {
        if ('' === $relay || ! str_contains($relay, '.')) {
            return admin_url();
        }
        [$blob, $mac] = explode('.', $relay, 2);
        $valid = hash_equals($this->relayMac($blob), $mac);
        if (! $valid) {
            return admin_url();
        }
        $decoded = json_decode((string) base64_decode($blob, true), true);
        if (! is_array($decoded) || empty($decoded['url']) || empty($decoded['iat'])) {
            return admin_url();
        }
        $ttl = (int) $this->options->get('general', 'saml_relay_ttl_seconds', 600);
        if ($this->clock->now() > ((int) $decoded['iat'] + $ttl)) {
            return admin_url();
        }

        return $this->sanitizeRedirectTarget((string) $decoded['url']);
    }

    /**
     * Read redirect_to from the current request and restrict it to allowed hosts.
     */
    private function requestedRedirectTarget(): string
    {
        if (! isset($_REQUEST['redirect_to'])) {
            return admin_url();
        }

        return $this->sanitizeRedirectTarget(
            sanitize_text_field(wp_unslash((string) $_REQUEST['redirect_to']))
        );
    }

    /**
     * Restrict redirect targets to allowed hosts.
     */
    private function sanitizeRedirectTarget(string $target): string
    {
        $safe = wp_validate_redirect($target, admin_url());
        $host = strtolower((string) wp_parse_url($safe, PHP_URL_HOST));
        $allowedHosts = array_map(
            strtolower(...),
            $this->allowedRedirectHosts()
        );
        if ('' !== $host && ! in_array($host, $allowedHosts, true)) {
            return admin_url();
        }

        return $safe;
    }

    /**
     * @return list<string>
     */
    private function allowedRedirectHosts(): array
    {
        $hosts = [
            (string) wp_parse_url(home_url(), PHP_URL_HOST),
            (string) wp_parse_url(site_url(), PHP_URL_HOST),
        ];
        $hosts = array_values(array_filter(array_unique($hosts)));

        // phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core redirect allow-list.
        $hosts = apply_filters('allowed_redirect_hosts', $hosts, '');
        // phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

        return $hosts;
    }

    /**
     * Whether strict SAML validation rules are enabled.
     */
    private function isSamlStrict(): bool
    {
        return (bool) $this->options->get('general', 'saml_strict_validation', true);
    }

    /**
     * Transient NameID cannot bind identity across sessions.
     */
    private function isTransientNameIdFormat(string $format): bool
    {
        $format = strtolower(trim($format));
        if ('' === $format) {
            return false;
        }

        return str_contains($format, 'nameid-format:transient')
            || 'transient' === $format
            || str_ends_with($format, ':transient');
    }

    /**
     * Detect whether the current request is served over HTTPS.
     *
     * Forwarded headers are only consulted when the site is configured to trust
     * a reverse proxy, otherwise any client could claim a secure connection.
     */
    private function isSecureRequest(): bool
    {
        if (is_ssl()) {
            return true;
        }
        if (! (bool) $this->options->get('general', 'trust_proxy_headers', false)) {
            return false;
        }
        $proto = isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
            ? sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_FORWARDED_PROTO']))
            : '';
        if ('' !== $proto) {
            $token = strtok($proto, ',');
            if (is_string($token) && 'https' === strtolower(trim($token))) {
                return true;
            }
        }
        $ssl = isset($_SERVER['HTTP_X_FORWARDED_SSL'])
            ? sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_FORWARDED_SSL']))
            : '';

        return 'on' === strtolower($ssl);
    }

    /**
     * Compare two SAML URLs using a normalized host/path/query representation.
     */
    private function samlUrlsMatch(string $expected, string $actual): bool
    {
        return hash_equals($this->normalizeUrlForSaml($expected), $this->normalizeUrlForSaml($actual));
    }

    /**
     * Normalize a URL for SAML destination/audience comparison.
     */
    private function normalizeUrlForSaml(string $url): string
    {
        $url = trim($url);
        $parts = wp_parse_url($url);
        if (! is_array($parts)) {
            return strtolower($url);
        }

        $host = strtolower((string) ($parts['host'] ?? ''));
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $query = (string) ($parts['query'] ?? '');
        $path = '/' . trim((string) ($parts['path'] ?? ''), '/');
        if ('//' === $path) {
            $path = '/';
        }

        $normalized = $host;
        if (null !== $port && ! in_array($port, [80, 443], true)) {
            $normalized .= ':' . $port;
        }
        $normalized .= $path;
        if ('' !== $query) {
            $normalized .= '?' . $query;
        }

        return $normalized;
    }

    /**
     * Compare two SAML entity IDs using URL normalization rules.
     */
    private function samlEntityIdsMatch(string $expected, string $actual): bool
    {
        return $this->samlUrlsMatch(trim($expected), trim($actual));
    }

    /**
     * Auto-submit an HTML form that POSTs the AuthnRequest to the IdP.
     */
    private function postAuthnRequestToIdp(string $ssoUrl, string $samlRequestB64, string $relay): void
    {
        $configured = (string) $this->options->get('saml', 'primary_sso_url', '');
        $urlHost = strtolower((string) wp_parse_url($ssoUrl, PHP_URL_HOST));
        $cfgHost = strtolower((string) wp_parse_url($configured, PHP_URL_HOST));
        $scheme = strtolower((string) wp_parse_url($ssoUrl, PHP_URL_SCHEME));

        if ('' === $urlHost || '' === $cfgHost || $urlHost !== $cfgHost) {
            $this->logger->security(
                'IdP POST blocked due to host mismatch.',
                [
                    'configured_host' => $cfgHost,
                    'redirect_host' => $urlHost,
                ]
            );
            wp_die(esc_html__('SSO is not configured.', 'signclave-sso'));
        }
        if (! in_array($scheme, ['http', 'https'], true)) {
            wp_die(esc_html__('SSO is not configured.', 'signclave-sso'));
        }

        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');
        $action = esc_url($ssoUrl);
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<title>' . esc_html__('Redirecting to sign in…', 'signclave-sso') . '</title></head><body>';
        echo '<form id="sc-saml-post" method="post" action="' . $action . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $action is esc_url().
        echo '<input type="hidden" name="SAMLRequest" value="' . esc_attr($samlRequestB64) . '">';
        echo '<input type="hidden" name="RelayState" value="' . esc_attr($relay) . '">';
        echo '<noscript><p><button type="submit">' . esc_html__('Continue to sign in', 'signclave-sso') . '</button></p></noscript>';
        echo '</form><script>document.getElementById("sc-saml-post").submit();</script></body></html>';
        exit;
    }
}
