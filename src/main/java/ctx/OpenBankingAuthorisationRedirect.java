package ctx;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import java.io.PrintWriter;
import java.util.UUID;

public class OpenBankingAuthorisationRedirect {
    Utils utils;
    private PrintWriter stdout;

    public OpenBankingAuthorisationRedirect(PrintWriter stdout) {
        this.utils = new Utils();
        this.stdout = stdout;
    }

    public String userRedirect(String audience, String scope, String clientId, String consentId, String responseType,
                               String jwtRedirect, String privateKey, String kid, String alg, String paramRedirect,
                               String state, String nonce) {
        String payload = generatePayload(audience, scope, clientId, consentId, responseType, jwtRedirect, state, nonce);
        String jwt = generateSignedJwt(payload, privateKey, kid, alg);
        return generateUrlParams(clientId, paramRedirect, responseType, state, scope, jwt);
    }

    public boolean verifyJwt(String jwt, String alg, String publicKey, String payload) {
        JsonWebSignature verifierJws = new JsonWebSignature();
        verifierJws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, alg));

        boolean isValid = false;
        try {
            verifierJws.setCompactSerialization(jwt);
            verifierJws.setPayload(payload);
            verifierJws.setKey(this.utils.getPublicKey(publicKey));

            isValid = verifierJws.verifySignature();
        } catch (JoseException e) {
            e.printStackTrace();
        }

        return isValid;
    }

    public String generateUrlParams(String clientId, String paramRedirect, String responseType, String state, String scope, String signedJwt) {
        String paramString = "client_id={0}&redirect_uri={1}&response_type={2}&state={3}&scope={4}&request={5}";
        return java.text.MessageFormat.format(paramString, clientId, paramRedirect, responseType.replace(" ", "+"), state, scope.replace(" ", "+"), signedJwt);
    }

    public String generatePayload(String audience, String scope, String clientId, String consentId, String responseType, String jwtRedirect, String state, String nonce) {
        long seconds = System.currentTimeMillis() / 1000l;
        String exp = Long.toString(seconds + 300);
        String iat = Long.toString(seconds); // as per open banking specification
        UUID uuid = UUID.randomUUID();

        String payloadTemplate = "{\n" +
                "  \"aud\": \"{0}\",\n" +
                "  \"claims\": {\n" +
                "    \"id_token\": {\n" +
                "      \"openbanking_intent_id\": {\n" +
                "        \"essential\": true,\n" +
                "        \"value\": \"{1}\"\n" +
                "      },\n" +
                "      \"acr\": {\n" +
                "        \"essential\": true,\n" +
                "        \"values\": [\n" +
                "          \"urn:openbanking:psd2:ca\",\n" +
                "          \"urn:openbanking:psd2:sca\"\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  },\n" +
                "  \"client_id\": \"{2}\",\n" +
                "  \"exp\":" + exp + "," +
                "  \"iat\":" + iat + "," +
                "  \"iss\": \"{3}\",\n" +
                "  \"jti\": \"{4}\",\n" +
                "  \"nonce\": \"{5}\",\n" +
                "  \"redirect_uri\": \"{6}\",\n" +
                "  \"response_type\": \"{7}\",\n" +
                "  \"scope\": \"{8}\",\n" +
                "  \"state\": \"{9}\",\n" +
                "  \"max_age\": 86400\n" +
                "}";

        return payloadTemplate.replace("{0}", audience)
                .replace("{1}", consentId)
                .replace("{2}", clientId)
                .replace("{3}", clientId)
                .replace("{4}", uuid.toString())
                .replace("{5}", nonce)
                .replace("{6}", jwtRedirect)
                .replace("{7}", responseType)
                .replace("{8}", scope)
                .replace("{9}", state);
    }

    public String generateSignedJwt(String payload, String privateKey, String kid, String alg) {
        JsonWebSignature signerJws = new JsonWebSignature();

        // signing settings
        signerJws.setPayload(payload);
        signerJws.setAlgorithmHeaderValue(alg);
        signerJws.setKey(this.utils.getPrivateKey(privateKey));
        signerJws.setKeyIdHeaderValue(kid);

        // set headers
        signerJws.setHeader("typ", "JWT");

        // create detached JWS
        String jws = "";
        try {
            jws = signerJws.getCompactSerialization();
        } catch (JoseException e) {
            stdout.println(e);
        }
        return jws;
    }
}
