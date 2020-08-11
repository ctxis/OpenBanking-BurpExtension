package ctx;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class GuiAuthTokenTab {
    private JPanel panel;
    private Utils utils;
    private JTextField txtCode;
    private JTextField txtBearerToken;
    private JButton btnCopyCode;
    private JButton btnCopyBearerToken;
    private JTextArea output;
    private JButton clearButton;

    public GuiAuthTokenTab() {
        this.utils = new Utils();
        this.panel = new JPanel();
        initPanel();
    }

    private void initPanel() {
        this.panel.setLayout(null);

        int textLength = 300;
        int labelRow1 = 20;
        int textRow1 = 100;

        JLabel lblCode = utils.createLabel("Current Code", labelRow1, 20, "OAuth Code");
        this.panel.add(lblCode);
        this.txtCode = utils.createTextField(textLength, textRow1, 20);
        this.panel.add(txtCode);
        this.btnCopyCode = new JButton("Copy Code");
        this.btnCopyCode.setSize(150, 30);
        this.btnCopyCode.setLocation(420, 20);
        this.panel.add(btnCopyCode);

        JLabel lblBearerToken = utils.createLabel("Current Token", labelRow1, 60, "Authorised Bearer Token");
        this.panel.add(lblBearerToken);
        this.txtBearerToken = utils.createTextField(textLength, textRow1, 60);
        this.panel.add(txtBearerToken);
        this.btnCopyBearerToken = new JButton("Copy Token");
        this.btnCopyBearerToken.setSize(150, 30);
        this.btnCopyBearerToken.setLocation(420, 60);
        this.panel.add(btnCopyBearerToken);

        this.output = new JTextArea();
        this.output.setSize(800, 300);
        this.output.setLocation(20, 100);
        JScrollPane outputScrollPane = new JScrollPane(this.output);
        outputScrollPane.setBounds(20, 100, 800, 300);
        this.panel.add(outputScrollPane);

        this.clearButton = new JButton("Clear");
        this.clearButton.setSize(100, 30);
        this.clearButton.setLocation(20, 425);
        this.panel.add(clearButton);
    }

    public JPanel getPanel() {
        return panel;
    }

    public JButton getClearButton() {
        return clearButton;
    }

    public JTextArea getOutput() {
        return output;
    }

    public JTextField getTxtCode() {
        return txtCode;
    }

    public JTextField getTxtBearerToken() {
        return txtBearerToken;
    }

    public JButton getBtnCopyCode() {
        return btnCopyCode;
    }

    public JButton getBtnCopyBearerToken() {
        return btnCopyBearerToken;
    }
}
