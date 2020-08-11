package ctx;

import javax.swing.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Utils {

    /**
     * Load file
     *
     * @param filename is the absolute path to the file
     * @return bytes
     * @throws IOException
     */
    public byte[] readFileBytes(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);
    }

    /**
     * Load private certificate from file
     * openssl pkcs8 -topk8 -nocrypt -in signing.key -outform der -out priv-key.der
     *
     * @return Private Key - requires the key in der format
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public PrivateKey getPrivateKey(String file) {
        PKCS8EncodedKeySpec keySpec = null;
        KeyFactory keyFactory = null;
        PrivateKey privateKey = null;

        try {
            keySpec = new PKCS8EncodedKeySpec(readFileBytes(file));
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return privateKey;
    }


    /**
     * Load Public Key - requires the key in der format
     * PEM certificate to PEM public key: openssl x509 -pubkey -noout -in cert.pem  > pub-key.pem
     * PEM public key to DER public key: openssl rsa -pubin -inform PEM -in pub-key.pem -outform DER -out pub-key.der
     *
     * @return Public Key Object
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public PublicKey getPublicKey(String file) {
        X509EncodedKeySpec publicSpec = null;
        KeyFactory keyFactory = null;
        PublicKey publicKey = null;

        try {
            publicSpec = new X509EncodedKeySpec(readFileBytes(file));
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(publicSpec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public JLabel createLabel(String name, int x, int y, String toolTip) {
        JLabel label = new JLabel(name);
        label.setSize(80, 30);
        label.setLocation(x, y);
        if (!toolTip.isEmpty()) {
            label.setToolTipText(toolTip);
        }
        return label;
    }

    public JTextField createTextField(int width, int x, int y) {
        JTextField textField = new JTextField();
        textField.setSize(width, 25);
        textField.setLocation(x, y);
        return textField;
    }

}
