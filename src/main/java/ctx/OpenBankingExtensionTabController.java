package ctx;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import javax.swing.JScrollPane;
import java.awt.Component;
import java.io.PrintWriter;

public class OpenBankingExtensionTabController implements ITab {
    private JScrollPane scrollPane;
    private Gui gui;

    public OpenBankingExtensionTabController(IBurpExtenderCallbacks callbacks, PrintWriter stdout) {
        this.gui = new Gui();
        GuiController msgSigningCtr = new GuiController(callbacks, stdout, this.gui);
        this.scrollPane = new JScrollPane(gui.getTabbedPane());
    }

    @Override
    public String getTabCaption() {
        return "Open Banking";
    }

    @Override
    public Component getUiComponent() {
        return this.scrollPane;
    }

    public Gui getGui() {
        return this.gui;
    }
}
