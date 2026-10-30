<?php

declare(strict_types=1);

/**
 * Build signed SAML Response fixtures for unit tests.
 *
 * Timestamps are fixed so FrozenClock can lock validation. Regenerating does
 * not expire existing tests.
 *
 * Usage: php tests/fixtures/saml/build.php
 */

require dirname(__DIR__, 3) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/vendor-prefixed/autoload.php';

use Signclave\Vendor\RobRichards\XMLSecLibs\XMLSecurityDSig;
use Signclave\Vendor\RobRichards\XMLSecLibs\XMLSecurityKey;

$dir = __DIR__;
$privateKey = (string) file_get_contents($dir . '/idp.key');
$otherKey = (string) file_get_contents($dir . '/other.key');
$certPem = (string) file_get_contents($dir . '/idp.crt');

const SC_FIXTURE_ISSUE = '2024-06-15T12:00:00Z';
const SC_FIXTURE_NOT_BEFORE = '2024-06-15T11:59:00Z';
const SC_FIXTURE_NOT_AFTER = '2024-06-15T13:00:00Z';

/**
 * @param array<string, mixed> $opts
 */
function buildResponse(array $opts): string
{
    $issueInstant = (string) ($opts['issueInstant'] ?? SC_FIXTURE_ISSUE);
    $notBefore = (string) ($opts['notBefore'] ?? SC_FIXTURE_NOT_BEFORE);
    $notOnOrAfter = array_key_exists('notOnOrAfter', $opts)
        ? (string) $opts['notOnOrAfter']
        : SC_FIXTURE_NOT_AFTER;
    $nameIdFormat = (string) ($opts['nameIdFormat'] ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    $nameId = (string) ($opts['nameId'] ?? 'alice');
    $assertionId = (string) ($opts['assertionId'] ?? '_assertion1');
    $responseId = (string) ($opts['responseId'] ?? '_response1');
    $issuer = (string) ($opts['issuer'] ?? 'https://idp.example.test/realms/test');
    $audience = (string) ($opts['audience'] ?? 'https://sp.example.test/');
    $destination = (string) ($opts['destination'] ?? 'https://sp.example.test/?signclave_sso_saml=acs');
    $recipient = (string) ($opts['recipient'] ?? $destination);
    $inResponseTo = array_key_exists('inResponseTo', $opts) ? (string) $opts['inResponseTo'] : '_req1';
    $status = (string) ($opts['status'] ?? 'urn:oasis:names:tc:SAML:2.0:status:Success');
    $statusMessage = (string) ($opts['statusMessage'] ?? '');
    $uid = (string) ($opts['uid'] ?? 'alice');
    $mail = (string) ($opts['mail'] ?? 'alice@example.test');
    $given = (string) ($opts['givenName'] ?? 'Alice');
    $sn = (string) ($opts['sn'] ?? 'Example');
    $groups = $opts['groups'] ?? ['cn=editors,ou=groups,o=example'];
    if (! is_array($groups)) {
        $groups = [$groups];
    }

    $inResponseAttr = '' !== $inResponseTo ? ' InResponseTo="' . htmlspecialchars($inResponseTo, ENT_XML1) . '"' : '';
    $scdNotOnOrAfter = '' !== $notOnOrAfter
        ? ' NotOnOrAfter="' . htmlspecialchars($notOnOrAfter, ENT_XML1) . '"'
        : '';
    $conditionsAttrs = ' NotBefore="' . htmlspecialchars($notBefore, ENT_XML1) . '"';
    if ('' !== $notOnOrAfter) {
        $conditionsAttrs .= ' NotOnOrAfter="' . htmlspecialchars($notOnOrAfter, ENT_XML1) . '"';
    }
    $statusXml = '<samlp:StatusCode Value="' . htmlspecialchars($status, ENT_XML1) . '"/>';
    if ('' !== $statusMessage) {
        $statusXml .= '<samlp:StatusMessage>' . htmlspecialchars($statusMessage, ENT_XML1) . '</samlp:StatusMessage>';
    }

    $groupXml = '';
    foreach ($groups as $group) {
        $groupXml .= '      <saml:AttributeValue>' . htmlspecialchars((string) $group, ENT_XML1) . '</saml:AttributeValue>' . "\n";
    }

    $extraAssertion = (string) ($opts['extraAssertion'] ?? '');

    $assertion = <<<XML
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$assertionId}" Version="2.0" IssueInstant="{$issueInstant}">
  <saml:Issuer>{$issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="{$nameIdFormat}">{$nameId}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData{$scdNotOnOrAfter} Recipient="{$recipient}"{$inResponseAttr}/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions{$conditionsAttrs}>
    <saml:AudienceRestriction>
      <saml:Audience>{$audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="uid">
      <saml:AttributeValue>{$uid}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="mail">
      <saml:AttributeValue>{$mail}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="givenName">
      <saml:AttributeValue>{$given}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="sn">
      <saml:AttributeValue>{$sn}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="groups">
{$groupXml}    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
XML;

    return <<<XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$responseId}" Version="2.0" IssueInstant="{$issueInstant}" Destination="{$destination}">
  <saml:Issuer>{$issuer}</saml:Issuer>
  <samlp:Status>
    {$statusXml}
  </samlp:Status>
  {$assertion}
  {$extraAssertion}
</samlp:Response>
XML;
}

/**
 * @param list<string|array<string, array<string, string>>>|null $transforms
 */
function signXml(string $xml, string $privateKey, string $signTarget, bool $sha1 = false, ?array $transforms = null): string
{
    $dom = new DOMDocument();
    $dom->preserveWhiteSpace = true;
    $dom->formatOutput = false;
    $dom->loadXML($xml);

    $xp = new DOMXPath($dom);
    $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xp->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

    if ('assertion' === $signTarget) {
        $node = $xp->query('//saml:Assertion')->item(0);
    } else {
        $node = $dom->documentElement;
    }
    if (! $node instanceof DOMElement) {
        throw new RuntimeException('Sign target not found');
    }

    $objDSig = new XMLSecurityDSig();
    $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $digest = $sha1 ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256;
    $objDSig->addReference(
        $node,
        $digest,
        $transforms ?? ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
        ['id_name' => 'ID', 'overwrite' => false]
    );

    $algo = $sha1 ? XMLSecurityKey::RSA_SHA1 : XMLSecurityKey::RSA_SHA256;
    $objKey = new XMLSecurityKey($algo, ['type' => 'private']);
    $objKey->loadKey($privateKey, false);
    $objDSig->sign($objKey);
    $objDSig->appendSignature($node);

    return (string) $dom->saveXML();
}

function injectComment(string $xml, string $elementLocalName): string
{
    $dom = new DOMDocument();
    $dom->loadXML($xml);
    $xp = new DOMXPath($dom);
    $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $el = $xp->query('//saml:' . $elementLocalName)->item(0);
    if ($el instanceof DOMElement) {
        $text = $el->textContent;
        while ($el->firstChild) {
            $el->removeChild($el->firstChild);
        }
        $el->appendChild($dom->createTextNode(substr($text, 0, 1)));
        $el->appendChild($dom->createComment('x'));
        $el->appendChild($dom->createTextNode(substr($text, 1)));
    }

    return (string) $dom->saveXML();
}

function writeFixture(string $dir, string $file, string $xml): void
{
    file_put_contents($dir . '/' . $file, $xml);
    echo "Wrote {$file}\n";
}

$unsignedAttacker = <<<XML
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil" Version="2.0" IssueInstant="2024-06-15T12:00:00Z">
  <saml:Issuer>https://idp.example.test/realms/test</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml:NameID>
  </saml:Subject>
</saml:Assertion>
XML;

$signedAssertion = signXml(buildResponse([]), $privateKey, 'assertion');
writeFixture($dir, 'valid-assertion.xml', $signedAssertion);

writeFixture($dir, 'sha1-assertion.xml', signXml(buildResponse([]), $privateKey, 'assertion', true));
$extraReference = signXml(buildResponse([]), $privateKey, 'assertion');
$extraDom = new DOMDocument();
$extraDom->loadXML($extraReference);
$extraXp = new DOMXPath($extraDom);
$extraXp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$firstReference = $extraXp->query('//ds:Reference')->item(0);
if ($firstReference instanceof DOMElement && $firstReference->parentNode instanceof DOMElement) {
    $firstReference->parentNode->appendChild($firstReference->cloneNode(true));
}
writeFixture($dir, 'extra-reference.xml', (string) $extraDom->saveXML());

writeFixture($dir, 'xpath-transform.xml', signXml(
    buildResponse([]),
    $privateKey,
    'assertion',
    false,
    [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        [
            'http://www.w3.org/TR/1999/REC-xpath-19991116' => [
                'query' => 'count(//*) > 0',
            ],
        ],
        XMLSecurityDSig::EXC_C14N,
    ]
));
writeFixture($dir, 'response-only.xml', signXml(buildResponse([]), $privateKey, 'response'));
writeFixture($dir, 'both-signed.xml', signXml(signXml(buildResponse([]), $privateKey, 'assertion'), $privateKey, 'response'));
writeFixture($dir, 'signed-by-other.xml', signXml(buildResponse([]), $otherKey, 'assertion'));

$commentNameId = injectComment(buildResponse(['nameId' => 'admin@evil.example']), 'NameID');
writeFixture($dir, 'comment-nameid.xml', signXml($commentNameId, $privateKey, 'assertion'));

$commentUid = injectComment(buildResponse([]), 'AttributeValue');
writeFixture($dir, 'comment-uid.xml', signXml($commentUid, $privateKey, 'assertion'));

writeFixture($dir, 'transient-nameid.xml', signXml(buildResponse([
    'nameIdFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    'nameId' => '_transient-session-1',
]), $privateKey, 'assertion'));

writeFixture($dir, 'wrong-audience.xml', signXml(buildResponse([
    'audience' => 'https://other-sp.example.test/',
]), $privateKey, 'assertion'));

writeFixture($dir, 'wrong-destination.xml', signXml(buildResponse([
    'destination' => 'https://evil.example.test/?signclave_sso_saml=acs',
    'recipient' => 'https://evil.example.test/?signclave_sso_saml=acs',
]), $privateKey, 'assertion'));

writeFixture($dir, 'status-responder.xml', signXml(buildResponse([
    'status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    'statusMessage' => 'IdP denied the request',
]), $privateKey, 'assertion'));

writeFixture($dir, 'no-inresponseto.xml', signXml(buildResponse([
    'inResponseTo' => '',
]), $privateKey, 'assertion'));

writeFixture($dir, 'expired-assertion.xml', signXml(buildResponse([
    'notBefore' => '2024-06-15T10:00:00Z',
    'notOnOrAfter' => '2024-06-15T11:00:00Z',
]), $privateKey, 'assertion'));

writeFixture($dir, 'future-assertion.xml', signXml(buildResponse([
    'notBefore' => '2024-06-15T12:02:00Z',
    'notOnOrAfter' => '2024-06-15T13:00:00Z',
]), $privateKey, 'assertion'));

writeFixture($dir, 'empty-notonorafter.xml', signXml(buildResponse([
    'notOnOrAfter' => '',
]), $privateKey, 'assertion'));

writeFixture($dir, 'dual-assertion.xml', signXml(buildResponse([
    'extraAssertion' => $unsignedAttacker,
]), $privateKey, 'assertion'));

writeFixture($dir, 'unsigned-response.xml', buildResponse([]));

$tampered = str_replace('>alice@example.test</saml:AttributeValue>', '>eve@evil.test</saml:AttributeValue>', $signedAssertion);
writeFixture($dir, 'tampered-attribute.xml', $tampered);

$tamperedIssuer = str_replace(
    '>https://idp.example.test/realms/test</saml:Issuer>',
    '>https://evil.example.test/idp</saml:Issuer>',
    $signedAssertion
);
writeFixture($dir, 'tampered-issuer.xml', $tamperedIssuer);

writeFixture($dir, 'xxe.xml', <<<XML
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2024-06-15T12:00:00Z">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0" IssueInstant="2024-06-15T12:00:00Z">&xxe;</saml:Assertion>
</samlp:Response>
XML);

writeFixture($dir, 'billion-laughs.xml', <<<XML
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2024-06-15T12:00:00Z">&lol2;</samlp:Response>
XML);

writeFixture($dir, 'keycloak-lab-structure.xml', <<<XML
<?xml version="1.0"?>
<!-- Structural reference only: Keycloak-shaped Response. Signature is not valid. -->
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lab" Version="2.0" IssueInstant="2024-06-15T12:00:00Z" Destination="https://sp.example.test/?signclave_sso_saml=acs">
  <saml:Issuer>https://idp.example.test/realms/test</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_lab-assertion" Version="2.0" IssueInstant="2024-06-15T12:00:00Z">
    <saml:Issuer>https://idp.example.test/realms/test</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="mail"><saml:AttributeValue>alice@example.test</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="givenName"><saml:AttributeValue>Alice</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="sn"><saml:AttributeValue>Example</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>cn=editors,ou=groups,o=example</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML);

file_put_contents($dir . '/idp.pem.txt', $certPem);
echo "Done.\n";
