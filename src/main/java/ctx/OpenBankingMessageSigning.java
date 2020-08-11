package ctx;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

public class OpenBankingMessageSigning {
    private final Utils utils;

    public OpenBankingMessageSigning() {
        this.utils = new Utils();
    }

    /**
     * Open banking requires some requests to be signed with a detached JWS
     * Pattern: base64Url(jwsHeader) + ".." + base64Url(sign(base64Url(jwsHeader).jsonBody))
     *
     * Example:
     * {
     *     "alg": "RS512",
     *     "kid": "90210ABAD",
     *     "b64": false,
     *     "http://openbanking.org.uk/iat": 1501497671,
     *     "http://openbanking.org.uk/iss": "C=UK, ST=England, L=London, O=Acme Ltd.",
     *     "http://openbanking.org.uk/tan": "openbanking.org.uk",
     *     "crit": [ "b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan"]
     * }
     * Request header = x-jws-signature: V2hhdCB3ZSBnb3QgaGVyZQ0K..aXMgZmFpbHVyZSB0byBjb21tdW5pY2F0ZQ0K
     *
     * Details: https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937656404/Read+Write+Data+API+Specification+-+v3.1#Read/WriteDataAPISpecification-v3.1-MessageSigning.1
     */
    public String generateDetachedJWS(String payload, String alg, String privateKey, String kid, String iss,
                                      String tan, String[] crit, String typ, String cty) {
        JsonWebSignature jws = new JsonWebSignature();

        // signing settings
        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue(alg);
        jws.setKey(this.utils.getPrivateKey(privateKey));
        jws.setKeyIdHeaderValue(kid);

        // set headers
        jws.setHeader(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
        jws.setHeader("http://openbanking.org.uk/iat", System.currentTimeMillis() / 1000l);
        jws.setHeader("http://openbanking.org.uk/iss", iss);
        jws.setHeader("http://openbanking.org.uk/tan", tan);
        jws.setCriticalHeaderNames(crit);

        // set optional headers
        if(!cty.isEmpty()) {
            jws.setHeader("cty", cty);
        }
        if(!typ.isEmpty()) {
            jws.setHeader("typ", typ);
        }

        String detachedJwt = "";
        try {
            detachedJwt = jws.getDetachedContentCompactSerialization();
        } catch (JoseException e) {
            e.printStackTrace();
        }

        return detachedJwt;
    }


    /**
     * Verify signing with public certificate
     *
     * @param detachedContentJws provide the detached JWT to verify the signature
     * @return boolean value if signature is correct (true) or not (false)
     */
    public Boolean verifySigning(String detachedContentJws, String alg, String payload, String publicKey, String[] crit) {
        JsonWebSignature verifierJws = new JsonWebSignature();
        verifierJws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, alg));
        boolean isValid = false;

        try {
            verifierJws.setCompactSerialization(detachedContentJws);
            verifierJws.setPayload(payload);
            verifierJws.setKey(this.utils.getPublicKey(publicKey));
            verifierJws.setKnownCriticalHeaders(crit);
            isValid = verifierJws.verifySignature();
        } catch (JoseException e) {
            e.printStackTrace();
        }

        return isValid;
    }
}
