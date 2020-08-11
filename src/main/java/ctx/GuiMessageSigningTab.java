package ctx;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class GuiMessageSigningTab {
    private JPanel panel;
    private JTextArea payload;
    private JTextArea output;
    private JButton createButton;
    private Utils utils;


    public GuiMessageSigningTab() {
        this.utils = new Utils();
        this.panel = new JPanel();
        initPanel();
    }

    private void initPanel() {
        this.panel.setLayout(null);

        this.panel.add(utils.createLabel("Payload", 20, 20, ""));
        this.panel.add(utils.createLabel("Detached JWS", 450, 20, ""));

        this.payload = new JTextArea();
        this.payload.setSize(400, 400);
        this.payload.setLocation(20, 60);
        JScrollPane payloadScrollPane = new JScrollPane(this.payload);
        payloadScrollPane.setBounds(20, 60, 400, 400);
        this.panel.add(payloadScrollPane);

        this.output = new JTextArea();
        this.output.setSize(400, 400);
        this.output.setLocation(450, 60);
        JScrollPane outputScrollPane = new JScrollPane(this.output);
        outputScrollPane.setBounds(450, 60, 400, 400);
        this.panel.add(outputScrollPane);

        this.createButton = new JButton("Create JWS");
        this.createButton.setSize(100, 30);
        this.createButton.setLocation(20, 470);
        this.panel.add(createButton);
    }

    public JTextArea getPayload() {
        return payload;
    }

    public JTextArea getOutput() {
        return output;
    }

    public JPanel getPanel() {
        return panel;
    }

    public JButton getCreateButton() {
        return this.createButton;
    }
}
