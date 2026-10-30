<?php

declare(strict_types=1);

namespace Signclave\Saml;

if (!defined('ABSPATH')) {
    exit;
}

use DOMDocument;
use DOMElement;
use DOMXPath;
use Signclave\Vendor\RobRichards\XMLSecLibs\XMLSecurityDSig;
use Signclave\Vendor\RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * XML-DSig verification for SAML via prefixed xmlseclibs (pinned IdP cert).
 *
 * Only a signature covering an Assertion is accepted. A signed Response alone
 * does not authorize reading an unsigned Assertion.
 */
final class SignatureVerifier
{
    private const ALLOWED_SIG_ALGOS = [
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
    ];

    private const ALLOWED_DIGEST_ALGOS = [
        XMLSecurityDSig::SHA256,
        XMLSecurityDSig::SHA384,
        XMLSecurityDSig::SHA512,
    ];

    private const FORBIDDEN_SHA1 = [
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityDSig::SHA1,
        'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
        'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    ];

    /**
     * Transforms a real SAML assertion signature uses. Anything else, including
     * XPath filtering, is rejected before xmlseclibs evaluates it.
     */
    private const ALLOWED_TRANSFORMS = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
    ];

    /**
     * Verify signed SAML XML against one or more pinned IdP certificates.
     *
     * @param string $xml      Raw SAML Response XML.
     * @param string ...$certs PEM certificates (primary, optional secondary).
     */
    public function verifySignedXml(string $xml, string ...$certs): VerificationResult
    {
        $certs = array_values(array_filter(array_map(
            static fn (string $c): string => self::normalizeCertPem($c),
            $certs
        )));
        if ($certs === []) {
            return VerificationResult::failure('Invalid X.509 certificate.');
        }

        if (preg_match('/<!DOCTYPE|<!ENTITY/i', $xml)) {
            return VerificationResult::failure('DOCTYPE/ENTITY is forbidden.');
        }

        $probe = $this->loadDom($xml);
        if ($probe === null) {
            return VerificationResult::failure('Invalid XML.');
        }

        $xp = new DOMXPath($probe);
        $xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $sigCount = (int) $xp->evaluate('count(//ds:Signature)');
        if ($sigCount < 1) {
            $encrypted = $xp->query('//*[local-name()="EncryptedAssertion"]');
            if ($encrypted && $encrypted->length > 0) {
                return VerificationResult::failure(
                    'Encrypted assertion is not supported (disable assertion encryption in F5 or add decryption support).'
                );
            }

            return VerificationResult::failure(
                'No signature found (enable assertion signing on the F5 SAML SP connector).'
            );
        }

        $lastError = 'No valid assertion signature found.';
        for ($pos = 0; $pos < $sigCount; $pos++) {
            foreach ($certs as $certPem) {
                try {
                    $result = $this->verifySignatureAt($xml, $pos, $certPem);
                } catch (Throwable $e) {
                    $lastError = 'Signature processing error: ' . $e->getMessage();
                    continue;
                }
                if ($result->ok) {
                    return $result;
                }
                if ($result->error !== '') {
                    $lastError = $result->error;
                    if ($this->isFatalAlgorithmError($result->error)) {
                        return $result;
                    }
                }
            }
        }

        return VerificationResult::failure($lastError);
    }

    /**
     * Normalize a PEM certificate or raw base64 DER into PEM format.
     */
    public static function normalizeCertPem(string $cert): string
    {
        $cert = trim($cert);
        if ('' === $cert) {
            return '';
        }
        if (str_contains($cert, 'BEGIN CERTIFICATE')) {
            return $cert;
        }
        $cert = preg_replace('/\s+/', '', $cert);
        if (!is_string($cert) || '' === $cert) {
            return '';
        }

        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($cert, 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /**
     * Verify a single Signature node against a pinned certificate.
     */
    private function verifySignatureAt(string $xml, int $pos, string $certPem): VerificationResult
    {
        $dom = $this->loadDom($xml);
        if ($dom === null) {
            return VerificationResult::failure('Invalid XML.');
        }

        $objDSig = new XMLSecurityDSig();
        $objDSig->idKeys = ['ID'];
        $sigNode = $objDSig->locateSignature($dom, $pos);
        if ($sigNode === null) {
            return VerificationResult::failure('No signature found.');
        }

        $algoError = $this->rejectWeakAlgorithms($objDSig, $sigNode);
        if ($algoError !== null) {
            return VerificationResult::failure($algoError);
        }

        $transformError = $this->rejectDisallowedTransforms($sigNode);
        if ($transformError !== null) {
            return VerificationResult::failure($transformError);
        }

        $canonical = $objDSig->canonicalizeSignedInfo();
        if (!is_string($canonical) || '' === $canonical) {
            return VerificationResult::failure('SignedInfo canonicalization failed.');
        }

        try {
            $objDSig->validateReference();
        } catch (Throwable $e) {
            return VerificationResult::failure('Digest mismatch: ' . $e->getMessage());
        }

        $objKey = $objDSig->locateKey();
        if ($objKey === null) {
            return VerificationResult::failure('Unable to locate signature key algorithm.');
        }

        $algo = (string) ($objKey->type ?? '');
        if (!in_array($algo, self::ALLOWED_SIG_ALGOS, true)) {
            if (in_array(strtolower($algo), array_map('strtolower', self::FORBIDDEN_SHA1), true)
                || str_contains(strtolower($algo), 'sha1')
            ) {
                return VerificationResult::failure('sha1_rejected');
            }

            return VerificationResult::failure('Unsupported signature algorithm.');
        }

        $pinnedKey = new XMLSecurityKey($algo, ['type' => 'public']);
        $pinnedKey->loadKey($certPem, false, true);

        $verified = $objDSig->verify($pinnedKey);
        if (1 !== $verified) {
            return VerificationResult::failure(
                -1 === $verified ? 'OpenSSL verify error.' : 'Signature verification failed.'
            );
        }

        $signed = $this->resolveSignedAssertion($objDSig);
        if ($signed === null) {
            return VerificationResult::failure('unsigned_assertion');
        }

        return VerificationResult::success($dom, $signed['id'], $signed['name']);
    }

    /**
     * Reject SHA-1 SignatureMethod / DigestMethod before cryptographic work.
     */
    private function rejectWeakAlgorithms(XMLSecurityDSig $objDSig, \DOMNode $sigNode): ?string
    {
        $doc = $sigNode->ownerDocument;
        if ($doc === null) {
            return 'Invalid signature node.';
        }
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        $sigMethod = strtolower((string) $xpath->evaluate(
            'string(./ds:SignedInfo/ds:SignatureMethod/@Algorithm)',
            $sigNode
        ));
        if ('' !== $sigMethod && (
            in_array($sigMethod, array_map('strtolower', self::FORBIDDEN_SHA1), true)
            || str_contains($sigMethod, 'sha1')
        )) {
            return 'sha1_rejected';
        }
        if ('' !== $sigMethod && !in_array($sigMethod, array_map('strtolower', self::ALLOWED_SIG_ALGOS), true)) {
            return 'Unsupported signature algorithm.';
        }

        $digestNodes = $xpath->query('./ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm', $sigNode);
        if ($digestNodes) {
            foreach ($digestNodes as $attr) {
                $digest = strtolower((string) $attr->nodeValue);
                if (in_array($digest, array_map('strtolower', self::FORBIDDEN_SHA1), true)
                    || str_contains($digest, 'sha1')
                ) {
                    return 'sha1_rejected';
                }
                if (!in_array($digest, array_map('strtolower', self::ALLOWED_DIGEST_ALGOS), true)) {
                    return 'Unsupported digest algorithm.';
                }
            }
        }

        return null;
    }

    /**
     * Reject XPath and any other transform before xmlseclibs runs it.
     *
     * One Reference per signature is enough for F5 and Keycloak. Extra
     * references and unknown algorithms are rejected so validateReference()
     * never evaluates attacker-controlled XPath.
     */
    private function rejectDisallowedTransforms(\DOMNode $sigNode): ?string
    {
        $doc = $sigNode->ownerDocument;
        if ($doc === null) {
            return 'Invalid signature node.';
        }
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        $references = $xpath->query('./ds:SignedInfo/ds:Reference', $sigNode);
        if (!$references instanceof \DOMNodeList || $references->length !== 1) {
            return 'unsupported_transform';
        }

        $algorithms = $xpath->query(
            './ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm',
            $sigNode
        );
        if (!$algorithms instanceof \DOMNodeList || $algorithms->length < 1) {
            return 'unsupported_transform';
        }
        foreach ($algorithms as $attr) {
            $algorithm = strtolower(trim((string) $attr->nodeValue));
            if (!in_array($algorithm, self::ALLOWED_TRANSFORMS, true)) {
                return 'unsupported_transform';
            }
        }

        return null;
    }

    /**
     * @return array{id:string,name:string}|null
     */
    private function resolveSignedAssertion(XMLSecurityDSig $objDSig): ?array
    {
        $validated = $objDSig->getValidatedNodes();
        if (!is_array($validated) || $validated === []) {
            return null;
        }

        foreach ($validated as $id => $node) {
            if (!$node instanceof DOMElement) {
                continue;
            }
            if ('Assertion' !== $node->localName) {
                continue;
            }
            $signedId = is_string($id) && '' !== $id
                ? $id
                : (string) $node->getAttribute('ID');

            return [
                'id' => $signedId,
                'name' => 'Assertion',
            ];
        }

        return null;
    }

    private function isFatalAlgorithmError(string $error): bool
    {
        return 'sha1_rejected' === $error
            || 'unsupported_transform' === $error
            || str_starts_with($error, 'Unsupported');
    }

    private function loadDom(string $xml): ?DOMDocument
    {
        $dom = new DOMDocument();
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;
        $ok = $dom->loadXML($xml, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

        return $ok ? $dom : null;
    }
}
