package ctx;

import burp.IBurpExtenderCallbacks;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javax.swing.JFileChooser;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class GuiController {
    private Gui gui;
    private GuiGeneralTab guiGeneral;
    private GuiMessageSigningTab guiMessageSigning;
    private GuiUserRedirectTab guiUserRedirect;
    private GuiAuthTokenTab guiAuthToken;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private File currentSaveFile;

    private OpenBankingMessageSigning ctxMessageSigning;
    private OpenBankingAuthorisationRedirect ctxUserRedirect;

    public GuiController(IBurpExtenderCallbacks callbacks, PrintWriter stdout, Gui gui) {
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.ctxMessageSigning = new OpenBankingMessageSigning();
        this.ctxUserRedirect = new OpenBankingAuthorisationRedirect(this.stdout);

        this.gui = gui;
        this.guiGeneral = gui.getTabGeneral();
        this.guiMessageSigning = gui.getTabMessageSigning();
        this.guiUserRedirect = gui.getTabUserRedirect();
        this.guiAuthToken = gui.getTabAuthToken();

        this.guiMessageSigning.getCreateButton().addActionListener(this::signMessage);
        this.guiUserRedirect.getCreateButton().addActionListener(this::createRedirect);
        this.guiAuthToken.getClearButton().addActionListener(this::clearAuthTokenOutput);
        this.guiAuthToken.getBtnCopyBearerToken().addActionListener(this::copyAuthBearerToken);
        this.guiAuthToken.getBtnCopyCode().addActionListener(this::copyAuthCode);
        this.guiGeneral.getSaveConfig().addActionListener(this::saveConfig);
        this.guiGeneral.getLoadConfig().addActionListener(this::loadConfig);
        this.guiGeneral.getChoosePublicKey().addActionListener(this::loadCert);
        this.guiGeneral.getChoosePrivateKey().addActionListener(this::loadCert);
    }

    public void signMessage(ActionEvent e) {
        String alg = this.guiGeneral.getTextAlg().getText();
        String kid = this.guiGeneral.getTextKid().getText();
        String iss = this.guiGeneral.getTextIss().getText();
        String tan = this.guiGeneral.getTextTan().getText();
        String crit = this.guiGeneral.getTextCrit().getText();
        String privateKey = this.guiGeneral.getTextPrivateKey().getText();
        String typ = this.guiGeneral.getTextTyp().getText();
        String cty = this.guiGeneral.getTextCty().getText();
        String payload = this.guiMessageSigning.getPayload().getText();

        boolean allValues = false;
        if (!alg.trim().isEmpty() &&
                !kid.trim().isEmpty() &&
                !iss.trim().isEmpty() &&
                !tan.trim().isEmpty() &&
                !crit.trim().isEmpty() &&
                !privateKey.trim().isEmpty()) {
            allValues = true;
        }

        String[] critValues = crit.split(",");
        if (allValues && !payload.isEmpty()) {
            String detachedJws = ctxMessageSigning.generateDetachedJWS(payload, alg, privateKey, kid, iss, tan, critValues, typ, cty);
            this.guiMessageSigning.getOutput().setText(detachedJws);
        }
    }

    public void createRedirect(ActionEvent e) {
        String alg = this.guiGeneral.getTextAlg().getText();
        String kid = this.guiGeneral.getTextKid().getText();
        String clientId = this.guiGeneral.getTextClientId().getText();
        String consentId = this.guiGeneral.getTextConsentId().getText();
        String jwtRedirect = this.guiGeneral.getTextRedirect().getText();
        String privateKey = this.guiGeneral.getTextPrivateKey().getText();
        String nonce = this.guiGeneral.getTextNonce().getText();
        String responseType = this.guiGeneral.getTextResponseType().getText();
        String state = this.guiGeneral.getTextState().getText();
        String scope = this.guiGeneral.getTextScope().getText();
        String audience = this.guiGeneral.getTextAudience().getText();
        boolean useConsentId = this.guiGeneral.getUseConsentId().isValid();

        if(useConsentId) {
            nonce = consentId;
            state = consentId;
        }

        String paramRedirect = jwtRedirect.replace(":", "%3A").replace("/", "%2F");

        if (!alg.trim().isEmpty() && !kid.trim().isEmpty() && !clientId.trim().isEmpty() && !consentId.trim().isEmpty() &&
                !paramRedirect.trim().isEmpty() && !jwtRedirect.trim().isEmpty() && !privateKey.trim().isEmpty() &&
                !nonce.trim().isEmpty() && !responseType.trim().isEmpty() && !state.trim().isEmpty() &&
                !scope.trim().isEmpty() && !audience.trim().isEmpty()) {

            String jws = this.ctxUserRedirect.userRedirect(audience, scope, clientId, consentId, responseType,
                    jwtRedirect, privateKey, kid, alg, paramRedirect, state, nonce);

            this.guiUserRedirect.getOutput().setText(jws);
        }
    }

    public void clearAuthTokenOutput(ActionEvent e) {
        this.guiAuthToken.getOutput().setText("");
    }

    public void copyAuthBearerToken(ActionEvent e) {
        StringSelection stringSelection = new StringSelection(this.guiAuthToken.getTxtBearerToken().getText());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
    }

    public void copyAuthCode(ActionEvent e) {
        StringSelection stringSelection = new StringSelection(this.guiAuthToken.getTxtCode().getText());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
    }

    public File getFileFromDialog(boolean saveFile, String defaultName){
        JFileChooser fc = new JFileChooser();

        if(defaultName != "") {
            fc.setSelectedFile(new File(defaultName));
        }

        int returnVal;

        if(saveFile) {
            returnVal = fc.showSaveDialog(this.gui.getTabbedPane());
        }
        else {
            returnVal = fc.showOpenDialog(this.gui.getTabbedPane());
        }

        if(returnVal == JFileChooser.APPROVE_OPTION){
            File f = fc.getSelectedFile();
            if(!saveFile) {
                return f; //Not saving over file, so just return it
            }

            try{
                if(f.exists()){
                    f.delete();
                }
                f.createNewFile();

                return f;
            } catch(IOException exc){
                stdout.println(exc.getMessage());
            }
        }
        return null;
    }

    public String getConfigData() {
        JsonObject data = new JsonObject();
        data.addProperty("alg", this.gui.getTabGeneral().getTextAlg().getText());
        data.addProperty("kid", this.gui.getTabGeneral().getTextKid().getText());
        data.addProperty("private-key", this.gui.getTabGeneral().getTextPrivateKey().getText());
        data.addProperty("public-key", this.gui.getTabGeneral().getTextPublicKey().getText());
        data.addProperty("iss", this.gui.getTabGeneral().getTextIss().getText());
        data.addProperty("url", this.gui.getTabGeneral().getTextUrl().getText());
        data.addProperty("tan", this.gui.getTabGeneral().getTextTan().getText());
        data.addProperty("crit", this.gui.getTabGeneral().getTextCrit().getText());
        data.addProperty("typ", this.gui.getTabGeneral().getTextTyp().getText());
        data.addProperty("cty", this.gui.getTabGeneral().getTextCty().getText());
        data.addProperty("client-id", this.gui.getTabGeneral().getTextClientId().getText());
        data.addProperty("scope", this.gui.getTabGeneral().getTextScope().getText());
        data.addProperty("redirect", this.gui.getTabGeneral().getTextRedirect().getText());
        data.addProperty("oauth", this.gui.getTabGeneral().getTextOAuth().getText());
        data.addProperty("consent-id", this.gui.getTabGeneral().getTextConsentId().getText());
        data.addProperty("response-type", this.gui.getTabGeneral().getTextResponseType().getText());
        data.addProperty("state", this.gui.getTabGeneral().getTextState().getText());
        data.addProperty("audience", this.gui.getTabGeneral().getTextAudience().getText());
        data.addProperty("nonce", this.gui.getTabGeneral().getTextNonce().getText());
        data.addProperty("use-consent-id", this.gui.getTabGeneral().getUseConsentId().isSelected());
        return data.toString();
    }

    public void setConfigData(JsonObject configData) {
        this.gui.getTabGeneral().getTextAlg().setText(configData.get("alg").getAsString());
        this.gui.getTabGeneral().getTextKid().setText(configData.get("kid").getAsString());
        this.gui.getTabGeneral().getTextPrivateKey().setText(configData.get("private-key").getAsString());
        this.gui.getTabGeneral().getTextPublicKey().setText(configData.get("public-key").getAsString());
        this.gui.getTabGeneral().getTextIss().setText(configData.get("iss").getAsString());
        this.gui.getTabGeneral().getTextUrl().setText(configData.get("url").getAsString());
        this.gui.getTabGeneral().getTextTan().setText(configData.get("tan").getAsString());
        this.gui.getTabGeneral().getTextCrit().setText(configData.get("crit").getAsString());
        this.gui.getTabGeneral().getTextTyp().setText(configData.get("typ").getAsString());
        this.gui.getTabGeneral().getTextCty().setText(configData.get("cty").getAsString());
        this.gui.getTabGeneral().getTextClientId().setText(configData.get("client-id").getAsString());
        this.gui.getTabGeneral().getTextScope().setText(configData.get("scope").getAsString());
        this.gui.getTabGeneral().getTextRedirect().setText(configData.get("redirect").getAsString());
        this.gui.getTabGeneral().getTextOAuth().setText(configData.get("oauth").getAsString());
        this.gui.getTabGeneral().getTextConsentId().setText(configData.get("consent-id").getAsString());
        this.gui.getTabGeneral().getTextResponseType().setText(configData.get("response-type").getAsString());
        this.gui.getTabGeneral().getTextState().setText(configData.get("state").getAsString());
        this.gui.getTabGeneral().getTextAudience().setText(configData.get("audience").getAsString());
        this.gui.getTabGeneral().getTextNonce().setText(configData.get("nonce").getAsString());
        this.gui.getTabGeneral().getUseConsentId().setSelected(configData.get("use-consent-id").getAsBoolean());
    }

    public void saveConfig(ActionEvent e){
        File f;
        if((f = getFileFromDialog(true, (currentSaveFile != null ? currentSaveFile.getPath() : "open-banking-config.json"))) != null){
            currentSaveFile = f;

            try {
                FileWriter fw = new FileWriter(f);
                fw.write(getConfigData());
                fw.flush();
                fw.close();

            } catch(IOException exc) {
                stdout.println(exc.getMessage());
            }
        }
    }

    public void loadConfig(ActionEvent e){
        File file;
        try {
            if((file = getFileFromDialog(false, (currentSaveFile != null ? currentSaveFile.getPath() : ""))) != null) {
                currentSaveFile = file;

                if(file.exists() && file.isFile() && file.canRead()){
                    byte[] encoded = Files.readAllBytes(Paths.get(file.getPath()));
                    String config = new String(encoded, StandardCharsets.UTF_8);

                    JsonObject configObject = new JsonParser().parse(config).getAsJsonObject();
                    setConfigData(configObject);
                }
            }
        } catch (IOException exc) {
            stdout.println(exc.getMessage());
        }
    }

    /**
     * This is the file browser for selecting the private and public keys. It will fill in the absolute path to
     * the Open Banking signing keys. Both public and private key need to be in DER format.
     *
     * @param e "Settings" tab - "Choose File" buttons
     */
    public void loadCert(ActionEvent e){
        File file;
        if((file = getFileFromDialog(false, (currentSaveFile != null ? currentSaveFile.getPath() : ""))) != null) {
            if(file.exists() && file.isFile() && file.canRead()) {
                String absolutePath = file.getAbsolutePath();

                if(e.getSource() == this.gui.getTabGeneral().getChoosePrivateKey()) {
                    this.gui.getTabGeneral().getTextPrivateKey().setText(absolutePath);
                } else if(e.getSource() == this.gui.getTabGeneral().getChoosePublicKey()) {
                    this.gui.getTabGeneral().getTextPublicKey().setText(absolutePath);
                }
            }
        }
    }
}
