package ctx;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class GuiUserRedirectTab {
    private JPanel panel;
    private JButton createButton;
    private JTextArea output;

    public GuiUserRedirectTab() {
        this.panel = new JPanel();
        initPanel();
    }

    private void initPanel() {
        this.panel.setLayout(null);

        this.createButton = new JButton("Create URL");
        this.createButton.setSize(100, 30);
        this.createButton.setLocation(20, 20);
        this.panel.add(createButton);

        this.output = new JTextArea();
        this.output.setSize(750, 200);
        this.output.setLocation(20, 50);
        JScrollPane outputScrollPane = new JScrollPane(this.output);
        outputScrollPane.setBounds(20, 50, 750, 200);
        this.panel.add(outputScrollPane);
    }

    public JPanel getPanel() {
        return this.panel;
    }

    public JButton getCreateButton() {
        return createButton;
    }

    public JTextArea getOutput() {
        return output;
    }
}
