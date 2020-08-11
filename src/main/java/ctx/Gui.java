package ctx;

import javax.swing.JTabbedPane;

public class Gui {
    private JTabbedPane tabbedPane;
    private GuiMessageSigningTab tabMessageSigning;
    private GuiUserRedirectTab tabUserRedirect;
    private GuiAuthTokenTab tabAuthToken;
    private GuiGeneralTab tabGeneral;

    public Gui() {
        iniGui();
    }

    private void iniGui() {
        this.tabbedPane = new JTabbedPane();

        this.tabGeneral = new GuiGeneralTab();
        this.tabMessageSigning = new GuiMessageSigningTab();
        this.tabUserRedirect = new GuiUserRedirectTab();
        this.tabAuthToken = new GuiAuthTokenTab();

        this.tabbedPane.add("Settings", tabGeneral.getPanel());
        this.tabbedPane.add("Message Signing", tabMessageSigning.getPanel());
        this.tabbedPane.add("User Redirect", tabUserRedirect.getPanel());
        this.tabbedPane.add("Auth Token", tabAuthToken.getPanel());
    }

    public JTabbedPane getTabbedPane() {
        return this.tabbedPane;
    }

    public GuiMessageSigningTab getTabMessageSigning() {
        return this.tabMessageSigning;
    }

    public GuiUserRedirectTab getTabUserRedirect() {
        return this.tabUserRedirect;
    }

    public GuiAuthTokenTab getTabAuthToken() {
        return this.tabAuthToken;
    }

    public GuiGeneralTab getTabGeneral() {
        return this.tabGeneral;
    }
}
