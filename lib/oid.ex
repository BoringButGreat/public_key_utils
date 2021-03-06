defmodule PublicKeyUtils.OID do
  # From public_key/include/OTP-PUB-KEY.hrl
  [
    "dhKeyAgreement": {1,2,840,113549,1,3,1},
    "pkcs-3": {1,2,840,113549,1,3},
    "id-sha512": {2,16,840,1,101,3,4,2,3},
    "id-sha384": {2,16,840,1,101,3,4,2,2},
    "id-sha256": {2,16,840,1,101,3,4,2,1},
    "id-sha224": {2,16,840,1,101,3,4,2,4},
    "id-mgf1": {1,2,840,113549,1,1,8},
    "id-hmacWithSHA512": {1,2,840,113549,2,11},
    "id-hmacWithSHA384": {1,2,840,113549,2,10},
    "id-hmacWithSHA256": {1,2,840,113549,2,9},
    "id-hmacWithSHA224": {1,2,840,113549,2,8},
    "id-md5": {1,2,840,113549,2,5},
    "id-md2": {1,2,840,113549,2,2},
    "id-sha1": {1,3,14,3,2,26},
    "sha-1WithRSAEncryption": {1,3,14,3,2,29},
    "sha224WithRSAEncryption": {1,2,840,113549,1,1,14},
    "sha512WithRSAEncryption": {1,2,840,113549,1,1,13},
    "sha384WithRSAEncryption": {1,2,840,113549,1,1,12},
    "sha256WithRSAEncryption": {1,2,840,113549,1,1,11},
    "sha1WithRSAEncryption": {1,2,840,113549,1,1,5},
    "md5WithRSAEncryption": {1,2,840,113549,1,1,4},
    "md2WithRSAEncryption": {1,2,840,113549,1,1,2},
    "id-RSASSA-PSS": {1,2,840,113549,1,1,10},
    "id-pSpecified": {1,2,840,113549,1,1,9},
    "id-RSAES-OAEP": {1,2,840,113549,1,1,7},
    "rsaEncryption": {1,2,840,113549,1,1,1},
    "pkcs-1": {1,2,840,113549,1,1},
    "sect571r1": {1,3,132,0,39},
    "sect571k1": {1,3,132,0,38},
    "sect409r1": {1,3,132,0,37},
    "sect409k1": {1,3,132,0,36},
    "secp521r1": {1,3,132,0,35},
    "secp384r1": {1,3,132,0,34},
    "secp224r1": {1,3,132,0,33},
    "secp224k1": {1,3,132,0,32},
    "secp192k1": {1,3,132,0,31},
    "secp160r2": {1,3,132,0,30},
    "secp128r2": {1,3,132,0,29},
    "secp128r1": {1,3,132,0,28},
    "sect233r1": {1,3,132,0,27},
    "sect233k1": {1,3,132,0,26},
    "sect193r2": {1,3,132,0,25},
    "sect193r1": {1,3,132,0,24},
    "sect131r2": {1,3,132,0,23},
    "sect131r1": {1,3,132,0,22},
    "sect283r1": {1,3,132,0,17},
    "sect283k1": {1,3,132,0,16},
    "sect163r2": {1,3,132,0,15},
    "secp256k1": {1,3,132,0,10},
    "secp160k1": {1,3,132,0,9},
    "secp160r1": {1,3,132,0,8},
    "secp112r2": {1,3,132,0,7},
    "secp112r1": {1,3,132,0,6},
    "sect113r2": {1,3,132,0,5},
    "sect113r1": {1,3,132,0,4},
    "sect239k1": {1,3,132,0,3},
    "sect163r1": {1,3,132,0,2},
    "sect163k1": {1,3,132,0,1},
    "secp256r1": {1,2,840,10045,3,1,7},
    "secp192r1": {1,2,840,10045,3,1,1},
    "ellipticCurve": {1,3,132,0},
    "certicom-arc": {1,3,132},
    "id-ecPublicKey": {1,2,840,10045,2,1},
    "id-publicKeyType": {1,2,840,10045,2},
    "ppBasis": {1,2,840,10045,1,2,3,3},
    "tpBasis": {1,2,840,10045,1,2,3,2},
    "gnBasis": {1,2,840,10045,1,2,3,1},
    "id-characteristic-two-basis": {1,2,840,10045,1,2,3},
    "characteristic-two-field": {1,2,840,10045,1,2},
    "prime-field": {1,2,840,10045,1,1},
    "id-fieldType": {1,2,840,10045,1},
    "ecdsa-with-SHA512": {1,2,840,10045,4,3,4},
    "ecdsa-with-SHA384": {1,2,840,10045,4,3,3},
    "ecdsa-with-SHA256": {1,2,840,10045,4,3,2},
    "ecdsa-with-SHA224": {1,2,840,10045,4,3,1},
    "ecdsa-with-SHA2": {1,2,840,10045,4,3},
    "ecdsa-with-SHA1": {1,2,840,10045,4,1},
    "id-ecSigType": {1,2,840,10045,4},
    "ansi-X9-62": {1,2,840,10045},
    "id-keyExchangeAlgorithm": {2,16,840,1,101,2,1,1,22},
    "dhpublicnumber": {1,2,840,10046,2,1},
    "id-dsaWithSHA1": {1,3,14,3,2,27},
    "id-dsa-with-sha1": {1,2,840,10040,4,3},
    "id-dsa": {1,2,840,10040,4,1},
    "id-at-clearance": {2,5,1,5,55},
    "id-at-role": {2,5,4,72},
    "id-aca-encAttrs": {1,3,6,1,5,5,7,10,6},
    "id-aca-group": {1,3,6,1,5,5,7,10,4},
    "id-aca-chargingIdentity": {1,3,6,1,5,5,7,10,3},
    "id-aca-accessIdentity": {1,3,6,1,5,5,7,10,2},
    "id-aca-authenticationInfo": {1,3,6,1,5,5,7,10,1},
    "id-aca": {1,3,6,1,5,5,7,10},
    "id-ce-targetInformation": {2,5,29,55},
    "id-pe-ac-proxying": {1,3,6,1,5,5,7,1,10},
    "id-pe-aaControls": {1,3,6,1,5,5,7,1,6},
    "id-pe-ac-auditIdentity": {1,3,6,1,5,5,7,1,4},
    "id-ce-invalidityDate": {2,5,29,24},
    "id-holdinstruction-reject": {2,2,840,10040,2,3},
    "id-holdinstruction-callissuer": {2,2,840,10040,2,2},
    "id-holdinstruction-none": {2,2,840,10040,2,1},
    "holdInstruction": {2,2,840,10040,2},
    "id-ce-holdInstructionCode": {2,5,29,23},
    "id-ce-certificateIssuer": {2,5,29,29},
    "id-ce-cRLReasons": {2,5,29,21},
    "id-ce-deltaCRLIndicator": {2,5,29,27},
    "id-ce-issuingDistributionPoint": {2,5,29,28},
    "id-ce-cRLNumber": {2,5,29,20},
    "id-pe-subjectInfoAccess": {1,3,6,1,5,5,7,1,11},
    "id-pe-authorityInfoAccess": {1,3,6,1,5,5,7,1,1},
    "id-ce-freshestCRL": {2,5,29,46},
    "id-ce-inhibitAnyPolicy": {2,5,29,54},
    "id-kp-OCSPSigning": {1,3,6,1,5,5,7,3,9},
    "id-kp-timeStamping": {1,3,6,1,5,5,7,3,8},
    "id-kp-emailProtection": {1,3,6,1,5,5,7,3,4},
    "id-kp-codeSigning": {1,3,6,1,5,5,7,3,3},
    "id-kp-clientAuth": {1,3,6,1,5,5,7,3,2},
    "id-kp-serverAuth": {1,3,6,1,5,5,7,3,1},
    "anyExtendedKeyUsage": {2,5,29,37,0},
    "id-ce-extKeyUsage": {2,5,29,37},
    "id-ce-cRLDistributionPoints": {2,5,29,31},
    "id-ce-policyConstraints": {2,5,29,36},
    "id-ce-nameConstraints": {2,5,29,30},
    "id-ce-basicConstraints": {2,5,29,19},
    "id-ce-subjectDirectoryAttributes": {2,5,29,9},
    "id-ce-issuerAltName": {2,5,29,18},
    "id-ce-subjectAltName": {2,5,29,17},
    "id-ce-policyMappings": {2,5,29,33},
    "anyPolicy": {2,5,29,32,0},
    "id-ce-certificatePolicies": {2,5,29,32},
    "id-ce-privateKeyUsagePeriod": {2,5,29,16},
    "id-ce-keyUsage": {2,5,29,15},
    "id-ce-subjectKeyIdentifier": {2,5,29,14},
    "id-ce-authorityKeyIdentifier": {2,5,29,35},
    "id-ce": {2,5,29},
    "id-extensionReq": {2,16,840,1,113733,1,9,8},
    "id-transId": {2,16,840,1,113733,1,9,7},
    "id-recipientNonce": {2,16,840,1,113733,1,9,6},
    "id-senderNonce": {2,16,840,1,113733,1,9,5},
    "id-failInfo": {2,16,840,1,113733,1,9,4},
    "id-pkiStatus": {2,16,840,1,113733,1,9,3},
    "id-messageType": {2,16,840,1,113733,1,9,2},
    "id-attributes": {2,16,840,1,113733,1,9},
    "id-pki": {2,16,840,1,113733,1},
    "id-VeriSign": {2,16,840,1,113733},
    "encryptedData": {1,2,840,113549,1,7,6},
    "digestedData": {1,2,840,113549,1,7,5},
    "signedAndEnvelopedData": {1,2,840,113549,1,7,4},
    "envelopedData": {1,2,840,113549,1,7,3},
    "signedData": {1,2,840,113549,1,7,2},
    "data": {1,2,840,113549,1,7,1},
    "pkcs-7": {1,2,840,113549,1,7},
    "pkcs-9-at-counterSignature": {1,2,840,113549,1,9,6},
    "pkcs-9-at-signingTime": {1,2,840,113549,1,9,5},
    "pkcs-9-at-messageDigest": {1,2,840,113549,1,9,4},
    "pkcs-9-at-contentType": {1,2,840,113549,1,9,3},
    "pkcs-9": {1,2,840,113549,1,9},
    "pkcs-9-at-extensionRequest": {1,2,840,113549,1,9,14},
    "pkcs-9-at-challengePassword": {1,2,840,113549,1,9,7},
    "brainpoolP512t1": {1,3,36,3,3,2,8,1,1,14},
    "brainpoolP512r1": {1,3,36,3,3,2,8,1,1,13},
    "brainpoolP384t1": {1,3,36,3,3,2,8,1,1,12},
    "brainpoolP384r1": {1,3,36,3,3,2,8,1,1,11},
    "brainpoolP320t1": {1,3,36,3,3,2,8,1,1,10},
    "brainpoolP320r1": {1,3,36,3,3,2,8,1,1,9},
    "brainpoolP256t1": {1,3,36,3,3,2,8,1,1,8},
    "brainpoolP256r1": {1,3,36,3,3,2,8,1,1,7},
    "brainpoolP224t1": {1,3,36,3,3,2,8,1,1,6},
    "brainpoolP224r1": {1,3,36,3,3,2,8,1,1,5},
    "brainpoolP192t1": {1,3,36,3,3,2,8,1,1,4},
    "brainpoolP192r1": {1,3,36,3,3,2,8,1,1,3},
    "brainpoolP160t1": {1,3,36,3,3,2,8,1,1,2},
    "brainpoolP160r1": {1,3,36,3,3,2,8,1,1,1},
    "versionOne": {1,3,36,3,3,2,8,1,1},
    "ellipticCurveRFC5639": {1,3,36,3,3,2,8,1},
    "ecStdCurvesAndGeneration": {1,3,36,3,3,2,8},
    "ub-x121-address-length": 16,
    "ub-unformatted-address-length": 180,
    "ub-terminal-id-length": 24,
    "ub-surname-length": 40,
    "ub-pseudonym-universal": 256,
    "ub-pseudonym-utf8": 256,
    "ub-pseudonym": 128,
    "ub-postal-code-length": 16,
    "ub-pds-physical-address-lines": 6,
    "ub-pds-parameter-length": 30,
    "ub-pds-name-length": 16,
    "ub-organizational-units": 4,
    "ub-numeric-user-id-length": 32,
    "ub-integer-options": 256,
    "ub-initials-length": 5,
    "ub-given-name-length": 16,
    "ub-generation-qualifier-length": 3,
    "ub-e163-4-sub-address-length": 40,
    "ub-e163-4-number-length": 15,
    "ub-extension-attributes": 256,
    "ub-domain-name-length": 16,
    "ub-domain-defined-attribute-value-length": 128,
    "ub-domain-defined-attribute-type-length": 8,
    "ub-domain-defined-attributes": 4,
    "ub-country-name-numeric-length": 3,
    "ub-country-name-alpha-length": 2,
    "ub-emailaddress-length": 255,
    "ub-match": 128,
    "ub-serial-number": 64,
    "ub-title-utf8": 256,
    "ub-title-universal": 256,
    "ub-title-printable": 128,
    "ub-title-teletex": 128,
    "ub-title": 64,
    "ub-organizational-unit-name-utf8": 256,
    "ub-organizational-unit-name-universal": 256,
    "ub-organizational-unit-name-teletex": 128,
    "ub-organizational-unit-name-printable": 128,
    "ub-organizational-unit-name": 64,
    "ub-organization-name-utf8": 256,
    "ub-organization-name-universal": 256,
    "ub-organization-name-teletex": 128,
    "ub-organization-name-printable": 128,
    "ub-organization-name": 64,
    "ub-state-name-utf8": 256,
    "ub-state-name-universal": 256,
    "ub-state-name": 128,
    "ub-locality-name-universal": 256,
    "ub-locality-name-utf8": 256,
    "ub-locality-name": 128,
    "ub-common-name-utf8": 256,
    "ub-common-name-universal": 256,
    "ub-common-name-printable": 128,
    "ub-common-name-teletex": 128,
    "ub-common-name": 64,
    "ub-name-utf8": 131072,
    "ub-name-universal": 131072,
    "ub-name-printable": 65536,
    "ub-name-teletex": 65536,
    "ub-name": 32768,
    "teletex-domain-defined-attributes": 6,
    "terminal-type": 23,
    "extended-network-address": 22,
    "local-postal-attributes": 21,
    "unique-postal-name": 20,
    "poste-restante-address": 19,
    "post-office-box-address": 18,
    "street-address": 17,
    "unformatted-postal-address": 16,
    "extension-physical-delivery-address-components": 15,
    "physical-delivery-organization-name": 14,
    "physical-delivery-personal-name": 13,
    "extension-OR-address-components": 12,
    "physical-delivery-office-number": 11,
    "physical-delivery-office-name": 10,
    "postal-code": 9,
    "physical-delivery-country-name": 8,
    "pds-name": 7,
    "teletex-organizational-unit-names": 5,
    "teletex-personal-name": 4,
    "teletex-organization-name": 3,
    "teletex-common-name": 2,
    "common-name": 1,
    "id-emailAddress": {1,2,840,113549,1,9,1},
    "id-domainComponent": {0,9,2342,19200300,100,1,25},
    "id-at-pseudonym": {2,5,4,65},
    "id-at-serialNumber": {2,5,4,5},
    "id-at-countryName": {2,5,4,6},
    "id-at-dnQualifier": {2,5,4,46},
    "id-at-title": {2,5,4,12},
    "id-at-organizationalUnitName": {2,5,4,11},
    "id-at-organizationName": {2,5,4,10},
    "id-at-stateOrProvinceName": {2,5,4,8},
    "id-at-localityName": {2,5,4,7},
    "id-at-commonName": {2,5,4,3},
    "id-at-generationQualifier": {2,5,4,44},
    "id-at-initials": {2,5,4,43},
    "id-at-givenName": {2,5,4,42},
    "id-at-surname": {2,5,4,4},
    "id-at-name": {2,5,4,41},
    "id-at": {2,5,4},
    "id-ad-caRepository": {1,3,6,1,5,5,7,48,5},
    "id-ad-timeStamping": {1,3,6,1,5,5,7,48,3},
    "id-ad-caIssuers": {1,3,6,1,5,5,7,48,2},
    "id-ad-ocsp": {1,3,6,1,5,5,7,48,1},
    "id-qt-unotice": {1,3,6,1,5,5,7,2,2},
    "id-qt-cps": {1,3,6,1,5,5,7,2,1},
    "id-ad": {1,3,6,1,5,5,7,48},
    "id-kp": {1,3,6,1,5,5,7,3},
    "id-qt": {1,3,6,1,5,5,7,2},
    "id-pe": {1,3,6,1,5,5,7,1},
    "id-pkix": {1,3,6,1,5,5,7},
  ]
  |> Enum.reduce(MapSet.new, fn({name, oid}, done) ->
    qoid = Macro.escape(oid)
    def to_oid(unquote(name)), do: unquote(qoid)
    if MapSet.member?(done, oid) do
      done
    else
      def from_oid(unquote(qoid)), do: unquote(name)
      MapSet.put(done, oid)
    end
  end)
  def from_oid(:asn1_NOVALUE), do: nil
  def from_oid(_), do: :unknown
  def to_oid(_), do: :unknown

  def decode_binary_oid(<<firsttwo, threeplus :: binary>>) do
    [div(firsttwo, 40), rem(firsttwo, 40) | Enum.reverse(_decode_binary_oid(threeplus, [], 0))]
    |> List.to_tuple
  end
  def _decode_binary_oid(<<>>, elements, _), do: elements
  def _decode_binary_oid(<<n, rest :: binary>>, elements, c) when n < 128 do
    _decode_binary_oid(rest, [ c + n | elements], 0)
  end
  def _decode_binary_oid(<<n, rest :: binary>>, elements, c) do
    _decode_binary_oid(rest, elements, (c + n - 128) * 128)
  end
end
