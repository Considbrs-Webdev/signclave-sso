<?php

declare(strict_types=1);

namespace Signclave\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Backed by existing ACS reason / WP_Error codes so logs stay stable.
 */
enum AuthFailureReason: string
{
    case AcsException = 'acs_exception';
    case MissingSamlResponse = 'missing_saml_response';
    case InvalidSamlResponseEncoding = 'invalid_saml_response_encoding';
    case SignatureValidationFailed = 'signature_validation_failed';
    case MissingResponseNode = 'missing_response_node';
    case MissingSignedId = 'missing_signed_id';
    case SignedNodeNotFound = 'signed_node_not_found';
    case SignedNodeInvalid = 'signed_node_invalid';
    case AssertionCountInvalid = 'assertion_count_invalid';
    case AssertionNotSignedOrMissing = 'assertion_not_signed_or_missing';
    case SamlStatusNotSuccess = 'saml_status_not_success';
    case ReplayBlocked = 'replay_blocked';
    case DestinationMissing = 'destination_missing';
    case DestinationMismatch = 'destination_mismatch';
    case IdpEntityNotConfigured = 'idp_entity_not_configured';
    case IssuerMismatch = 'issuer_mismatch';
    case MissingUsername = 'missing_username';
    case UserCreateFailed = 'user_create_failed';
    case RoleMappingDenied = 'role_mapping_denied';
    case LdapVerificationFailed = 'ldap_verification_failed';
    case AssertionNotYetValid = 'assertion_not_yet_valid';
    case AssertionExpired = 'assertion_expired';
    case AudienceMissing = 'audience_missing';
    case AudienceMismatch = 'audience_mismatch';
    case MissingSubjectConfirmation = 'missing_subject_confirmation';
    case SubjectConfirmationInvalid = 'subject_confirmation_invalid';
    case CommentInNameId = 'comment_in_nameid';
    case NameIdCollision = 'nameid_collision';
    case NameIdMissing = 'nameid_missing';
    case TransientNameId = 'transient_nameid';
    case SamlResponseTooLarge = 'saml_response_too_large';
    case LastAdminProtected = 'last_admin_protected';
    case LoginDenied = 'login_denied';
    case UnsignedAssertion = 'unsigned_assertion';
    case Sha1Rejected = 'sha1_rejected';
    case UnsupportedTransform = 'unsupported_transform';

    case LdapInvalidUsername = 'sc_ldap_invalid_username';
    case LdapDisabled = 'sc_ldap_disabled';
    case LdapUnavailable = 'sc_ldap_unavailable';
    case LdapNotConfigured = 'sc_ldap_not_configured';
    case LdapInsecure = 'sc_ldap_insecure';
    case LdapConnectFailed = 'sc_ldap_connect_failed';
    case LdapStartTlsFailed = 'sc_ldap_starttls_failed';
    case LdapBindFailed = 'sc_ldap_bind_failed';
    case LdapSearchFailed = 'sc_ldap_search_failed';
    case LdapUserNotFound = 'sc_ldap_user_not_found';
    case SecretDecryptFailed = 'sc_secret_decrypt_failed';
    case InvalidUser = 'sc_invalid_user';
    case NoGroup = 'sc_no_group';
    case Locked = 'sc_locked';
    case LocalOnly = 'sc_local_only';

    /**
     * Resolve a log code string to a known case, defaulting to AcsException.
     *
     * @param string $code Stored or incoming failure code.
     */
    public static function fromLogCode(string $code): self
    {
        $case = self::tryFrom($code);

        return $case ?? self::AcsException;
    }

    /**
     * Return the stable log/audit code for this failure.
     */
    public function logCode(): string
    {
        return $this->value;
    }

    /**
     * Return the WordPress error code for this failure.
     */
    public function wpErrorCode(): string
    {
        return $this->value;
    }

    /**
     * Return the generic user-facing message for authentication failures.
     */
    public function userMessage(): string
    {
        return __('Invalid credentials.', 'signclave-sso');
    }

    /**
     * Build a WP_Error for this failure reason.
     */
    public function toWpError(): \WP_Error
    {
        return new \WP_Error($this->wpErrorCode(), $this->userMessage());
    }
}
