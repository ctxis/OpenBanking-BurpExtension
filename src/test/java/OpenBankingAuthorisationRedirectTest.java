import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ctx.OpenBankingAuthorisationRedirect;
import ctx.Utils;
import org.junit.Assert;
import org.junit.Test;
import java.io.PrintWriter;
import java.util.UUID;

public class OpenBankingAuthorisationRedirectTest {

    private OpenBankingAuthorisationRedirect obRedirect = new OpenBankingAuthorisationRedirect(new PrintWriter(System.out));
    private Utils utils = new Utils();

    private final String audience = "https://authentication-portal.bank.com";
    private final String scope = "openid accounts";
    private final String clientId = "dc-ClientID";
    private final String consentId = "currentConsentID";
    private final String responseType = "code id_token";
    private final String redirectUrl = "https://tpp.com/callback";
    private final String state = UUID.randomUUID().toString();
    private final String nonce = UUID.randomUUID().toString();
    private final String kid = "90210ABAD";
    private final String alg = "PS256";

    private String createSignedJwt(String payload) {
        String privateKey = getClass().getClassLoader().getResource("certs/MockupPrivateKey.pkcs8.der").getFile().replace("%20", " ");
        return this.obRedirect.generateSignedJwt(payload, privateKey, kid, alg);
    }

    @Test
    public void generatePayloadTest() {
        String payload = this.obRedirect.generatePayload(audience, scope, clientId, consentId, responseType, redirectUrl, state, nonce);
        JsonObject jsonPayload = new JsonParser().parse(payload).getAsJsonObject();

        Assert.assertNotEquals("Verify that payload is not empty", "", payload);
        Assert.assertTrue("Verify that the payload is a valid JSON object", jsonPayload.isJsonObject());
        Assert.assertEquals("Verify audience parameter", "https://authentication-portal.bank.com", jsonPayload.get("aud").getAsString());
        Assert.assertEquals("Verify client ID", "dc-ClientID", jsonPayload.get("client_id").getAsString());
        Assert.assertEquals("Verify TPP redirect URL", "https://tpp.com/callback", jsonPayload.get("redirect_uri").getAsString());
    }

    @Test
    public void generateUrlParamsTest() {
        String paramRedirect = redirectUrl.replace(":", "%3A").replace("/", "%2F");
        String payload = this.obRedirect.generatePayload(audience, scope, clientId, consentId, responseType, redirectUrl, state, nonce);
        String signedJwt = createSignedJwt(payload);

        String urlParams = this.obRedirect.generateUrlParams(clientId, paramRedirect, responseType, state, scope, signedJwt);

        Assert.assertNotEquals("Verify that the URL parameters are not empty", "", urlParams);

        Assert.assertTrue("Verify that the redirect parameters include 'client_id'", urlParams.contains("client_id"));
        Assert.assertTrue("Verify that the redirect parameters include 'redirect_uri'", urlParams.contains("redirect_uri"));
        Assert.assertTrue("Verify that the redirect parameters include 'response_type'", urlParams.contains("response_type"));
        Assert.assertTrue("Verify that the redirect parameters include 'state'", urlParams.contains("state"));
        Assert.assertTrue("Verify that the redirect parameters include 'scope'", urlParams.contains("scope"));
        Assert.assertTrue("Verify that the redirect parameters include 'request'", urlParams.contains("request"));

        Assert.assertTrue("Verify that the response type has been URL encoded", urlParams.contains(responseType.replace(" ", "+")));
    }
}
