import ctx.OpenBankingMessageSigning;
import org.junit.Assert;
import org.junit.Test;

public class OpenBankingMessageSigningTest {

    @Test
    public void detachedJWSTest() {
        OpenBankingMessageSigning messageSigning = new OpenBankingMessageSigning();

        String payload = "TestPayloadJUnitTest";
        String alg = "RS256";
        String privateKey = getClass().getClassLoader().getResource("certs/MockupPrivateKey.pkcs8.der").getFile().replace("%20", " ");
        String publicKey = getClass().getClassLoader().getResource("certs/MockupPublicKey.der").getFile().replace("%20", " ");
        String kid = "90210ABAD";
        String iss = "C=UK, ST=England, L=London, O=Acme Ltd.";
        String tan = "openbanking.org.uk";
        String[] crit = {"http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan"};
        String cty = "json";
        String typ = "JOSE";

        String signedObj = messageSigning.generateDetachedJWS(payload, alg, privateKey, kid, iss, tan, crit, typ, cty);
        boolean isSignedCorrect = messageSigning.verifySigning(signedObj, alg, payload, publicKey, crit);

        Assert.assertNotEquals("Verify if detached JWS is not empty", "", signedObj);
        Assert.assertTrue("Verify if generated signature validates correctly.", isSignedCorrect);
    }

}
