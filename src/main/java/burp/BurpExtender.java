package burp;

import ctx.OpenBankingExtensionHttpListener;
import ctx.OpenBankingExtensionTabController;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("Open Banking");
        stdout.println("Loading Burp Extension 'Open Banking'");

        OpenBankingExtensionTabController tabCtr = new OpenBankingExtensionTabController(callbacks, stdout);
        callbacks.addSuiteTab(tabCtr);

        OpenBankingExtensionHttpListener httpListener = new OpenBankingExtensionHttpListener(callbacks, helpers, stdout, tabCtr);
        callbacks.registerHttpListener(httpListener);
    }
}
