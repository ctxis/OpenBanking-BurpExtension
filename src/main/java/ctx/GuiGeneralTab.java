package ctx;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class GuiGeneralTab {
    private JPanel panel;
    private Utils utils;

    // buttons
    private JButton saveConfig;
    private JButton loadConfig;
    private JButton choosePrivateKey;
    private JButton choosePublicKey;

    // encryption params
    private JTextField textKid;
    private JTextField textPublicKey;
    private JTextField textPrivateKey;
    private JTextField textAlg;

    // message signing
    private JTextField textIss;
    private JTextField textTan;
    private JTextArea textUrl;
    private JTextField textCrit;
    private JTextField textTyp;
    private JTextField textCty;

    // redirect / auth token
    private JTextField textClientId;
    private JTextField textScope;
    private JTextField textRedirect;
    private JTextField textOAuth;

    // redirect
    private JTextField textConsentId;
    private JTextField textState;
    private JTextField textNonce;
    private JTextField textResponseType;
    private JTextField textAudience;
    private JCheckBox useConsentId;

    public GuiGeneralTab() {
        this.panel = new JPanel();
        this.utils = new Utils();
        initPanel();
    }

    private void initPanel() {
        this.panel.setLayout(null);

        this.saveConfig = new JButton("Save Settings");
        this.saveConfig.setSize(100, 30);
        this.saveConfig.setLocation(20, 20);
        this.panel.add(saveConfig);

        this.loadConfig = new JButton("Load Settings");
        this.loadConfig.setSize(100, 30);
        this.loadConfig.setLocation(120, 20);
        this.panel.add(loadConfig);

        int textLength = 300;
        int labelColumn1 = 20;
        int textColumn1 = 100;
        int labelColumn2 = 420;
        int textColumn2 = 500;

        // section 1 - encryption settings
        int section1 = 60;
        int section1Row1 = 110;
        int section1Row2 = 140;
        int section1Row3 = 170;

        JLabel encryptionParams = new JLabel("Encryption Parameters (Msg Signing & Redirect)");
        encryptionParams.setSize(500, 50);
        encryptionParams.setLocation(labelColumn1, section1);
        this.panel.add(encryptionParams);

        this.panel.add(this.utils.createLabel("ALG", labelColumn1, section1Row1, "Open Banking Specification: PS256 or RS256"));
        this.textAlg = this.utils.createTextField(textLength,  textColumn1, section1Row1);
        this.textAlg.setText("PS256");
        this.panel.add(this.textAlg);

        this.panel.add(this.utils.createLabel("Private Key", labelColumn1, section1Row2, "Enter the full path to the private key file (in DER format)."));
        this.textPrivateKey = this.utils.createTextField(textLength,  textColumn1, section1Row2);
        this.panel.add(this.textPrivateKey);

        this.choosePrivateKey = new JButton("Choose File");
        this.choosePrivateKey.setSize(150, 30);
        this.choosePrivateKey.setLocation(textColumn1, section1Row3);
        this.panel.add(choosePrivateKey);

        this.panel.add(this.utils.createLabel("KID", labelColumn2, section1Row1, "Certificate Signing Key"));
        this.textKid = this.utils.createTextField(textLength,  textColumn2, section1Row1);
        this.panel.add(this.textKid);

        this.panel.add(this.utils.createLabel("Public Key*", labelColumn2, section1Row2, "Optional: Enter the full path to the public *key* file (in DER format)."));
        this.textPublicKey = this.utils.createTextField(textLength,  textColumn2, section1Row2);
        this.panel.add(this.textPublicKey);

        this.choosePublicKey = new JButton("Choose File");
        this.choosePublicKey.setSize(150, 30);
        this.choosePublicKey.setLocation(textColumn2, section1Row3);
        this.panel.add(choosePublicKey);

        // section 2 - message signing
        int section2 = 210;
        int section2Row1 = 260;
        int section2Row2 = 290;
        int section2Row3 = 320;
        int endpointsLbl = 350;
        int endpointsTxt = 380;

        JLabel messageSigningParams = new JLabel("Message Signing Parameters");
        messageSigningParams.setSize(500, 50);
        messageSigningParams.setLocation(labelColumn1, section2);
        this.panel.add(messageSigningParams);

        this.panel.add(this.utils.createLabel("ISS", labelColumn1, section2Row1, "http://openbanking.org.uk/iss - This must be a string that identifies the PSP."));
        this.textIss = this.utils.createTextField(textLength,  textColumn1, section2Row1);
        this.panel.add(this.textIss);

        this.panel.add(this.utils.createLabel("TAN", labelColumn1, section2Row2, "This must be a string that consists of a domain name that is registered to and identifies the Trust Anchor"));
        this.textTan = this.utils.createTextField(textLength,  textColumn1, section2Row2);
        this.textTan.setText("openbanking.org.uk");
        this.panel.add(this.textTan);

        this.panel.add(this.utils.createLabel("Crit", labelColumn2, section2Row2, "String array consisting of the set values"));
        this.textCrit = this.utils.createTextField(textLength,  textColumn2, section2Row2);
        this.textCrit.setText("b64,http://openbanking.org.uk/iat,http://openbanking.org.uk/iss,http://openbanking.org.uk/tan");
        this.panel.add(this.textCrit);

        this.panel.add(this.utils.createLabel("Typ*", labelColumn1, section2Row3, "Optional - if required set to 'JOSE'"));
        this.textTyp = this.utils.createTextField(textLength,  textColumn1, section2Row3);
        this.panel.add(this.textTyp);

        this.panel.add(this.utils.createLabel("Cty*", labelColumn2, section2Row3, "Optional - if required set to 'application/json'"));
        this.textCty = this.utils.createTextField(textLength,  textColumn2, section2Row3);
        this.panel.add(this.textCty);

        JLabel lblMsgSigningEndpoints = new JLabel("Message Signing Endpoints (comma separated)");
        lblMsgSigningEndpoints.setSize(250, 30);
        lblMsgSigningEndpoints.setLocation(labelColumn1, endpointsLbl);
        this.panel.add(lblMsgSigningEndpoints);

        this.textUrl = new JTextArea();
        this.textUrl.setSize(700, 60);
        this.textUrl.setLocation(textColumn1, endpointsTxt);
        this.panel.add(textUrl);


        // section 3 - user redirect & auth token
        int section3 = 450;
        int section3Row1 = 500;
        int section3Row2 = 530;

        JLabel redirectAuthToken = new JLabel("Redirect & Auth Token Parameters");
        redirectAuthToken.setSize(200, 50);
        redirectAuthToken.setLocation(labelColumn1, section3);
        this.panel.add(redirectAuthToken);

        this.panel.add(this.utils.createLabel("Client ID", labelColumn1, section3Row1, "Enter the TPP client ID"));
        this.textClientId = this.utils.createTextField(textLength,  textColumn1, section3Row1);
        this.panel.add(this.textClientId);

        this.panel.add(this.utils.createLabel("Redirect", labelColumn1, section3Row2, "Enter the redirect URL which was registered for the TPP"));
        this.textRedirect = this.utils.createTextField(textLength,  textColumn1, section3Row2);
        this.panel.add(this.textRedirect);

        this.panel.add(this.utils.createLabel("Scope", labelColumn2, section3Row1, "Enter the required permissions: openid [accounts|payments|fundsconfirmations] separated with a space"));
        this.textScope = this.utils.createTextField(textLength,  textColumn2, section3Row1);
        this.textScope.setText("openid accounts payments fundsconfirmations");
        this.panel.add(this.textScope);

        this.panel.add(this.utils.createLabel("OAuth URL", labelColumn2, section3Row2, "The bank's authentication endpoint for the bearer token"));
        this.textOAuth = this.utils.createTextField(textLength,  textColumn2, section3Row2);
        this.panel.add(this.textOAuth);

        // section 4 - user redirect
        int section4 = 570;
        int section4Row1 = 620;
        int section4Row2 = 650;
        int section4Row3 = 680;

        JLabel redirect = new JLabel("Redirect Parameters");
        redirect.setSize(200, 50);
        redirect.setLocation(labelColumn1, section4);
        this.panel.add(redirect);

        this.panel.add(this.utils.createLabel("Consent ID", labelColumn1, section4Row1, "Enter the current consent id to generate the redirect parameters."));
        this.textConsentId = this.utils.createTextField(textLength,  textColumn1, section4Row1);
        this.panel.add(this.textConsentId);

        this.panel.add(this.utils.createLabel("State", labelColumn1, section4Row2, "This is usually a random value. Some banks use the consent id. Select the checkbox below if that is the case."));
        this.textState = this.utils.createTextField(textLength,  textColumn1, section4Row2);
        this.panel.add(this.textState);

        this.panel.add(this.utils.createLabel("Nonce", labelColumn1, section4Row3, "This is usually a random value. Some banks use the consent id. Select the checkbox below if that is the case."));
        this.textNonce = this.utils.createTextField(textLength,  textColumn1, section4Row3);
        this.panel.add(this.textNonce);

        this.panel.add(this.utils.createLabel("Response Type", labelColumn2, section4Row1, "Select the response type - available values: code, code id_token, id_token, token"));
        this.textResponseType = this.utils.createTextField(textLength,  textColumn2, section4Row1);
        this.textResponseType.setText("code id_token");
        this.panel.add(this.textResponseType);

        this.panel.add(this.utils.createLabel("Audience", labelColumn2, section4Row2, "Enter the Bank's URL for the user redirect."));
        this.textAudience = this.utils.createTextField(textLength,  textColumn2, section4Row2);
        this.panel.add(this.textAudience);


        JLabel useConsentIdLabel = new JLabel("Use ConsentId for Nonce & State: ");
        useConsentIdLabel.setSize(250, 30);
        useConsentIdLabel.setLocation(labelColumn2, section4Row3);
        this.panel.add(useConsentIdLabel);

        this.useConsentId = new JCheckBox();
        this.useConsentId.setLocation(650, section4Row3);
        this.useConsentId.setEnabled(true);
        this.useConsentId.setSize(30, 30);
        this.panel.add(this.useConsentId);
    }

    public JButton getChoosePrivateKey() {
        return choosePrivateKey;
    }

    public JButton getChoosePublicKey() {
        return choosePublicKey;
    }

    public JTextField getTextIss() {
        return textIss;
    }

    public JTextField getTextTan() {
        return textTan;
    }

    public JTextArea getTextUrl() {
        return textUrl;
    }

    public JTextField getTextCrit() {
        return textCrit;
    }

    public JTextField getTextTyp() {
        return textTyp;
    }

    public JTextField getTextCty() {
        return textCty;
    }

    public JTextField getTextRedirect() {
        return textRedirect;
    }

    public JTextField getTextOAuth() {
        return textOAuth;
    }

    public JTextField getTextConsentId() {
        return textConsentId;
    }

    public JTextField getTextState() {
        return textState;
    }

    public JTextField getTextNonce() {
        return textNonce;
    }

    public JTextField getTextResponseType() {
        return textResponseType;
    }

    public JTextField getTextAudience() {
        return textAudience;
    }

    public JCheckBox getUseConsentId() {
        return useConsentId;
    }

    public JPanel getPanel() {
        return panel;
    }

    public JTextField getTextKid() {
        return textKid;
    }

    public JTextField getTextPublicKey() {
        return textPublicKey;
    }

    public JTextField getTextPrivateKey() {
        return textPrivateKey;
    }

    public JTextField getTextClientId() {
        return textClientId;
    }

    public JTextField getTextScope() {
        return textScope;
    }

    public JTextField getTextAlg() {
        return this.textAlg;
    }

    public JButton getSaveConfig() {
        return saveConfig;
    }

    public JButton getLoadConfig() {
        return loadConfig;
    }
}
