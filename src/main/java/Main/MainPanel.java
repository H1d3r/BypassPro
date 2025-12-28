package Main;

import burp.BurpExtender;
import burp.ITab;
import org.apache.commons.lang3.StringUtils;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * 主面板：包含 Dashboard 和 Config 两个页签
 */
public class MainPanel extends JPanel implements ITab {

    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.85;
    private static final int DEFAULT_THREAD_NUM = 5;

    private BypassTableModel bypassTableModel;
    private JTextField threadNumText;
    private JLabel allRequestNumberText;
    private JLabel finishRequestNumberText;
    private JLabel errorRequestNumText;
    private JCheckBox isAutoCheckBox;
    private ConfigPanel configPanel;
    private ManualWafPanel manualWafPanel;
    private JProgressBar progressBar;

    public MainPanel() {

        setLayout(new BorderLayout());

        // 主分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 结果表格
        bypassTableModel = new BypassTableModel();
        BypassTable bypassTable = new BypassTable(bypassTableModel);
        JScrollPane scrollPane = new JScrollPane(bypassTable);
        splitPane.setLeftComponent(scrollPane);

        // Request/Response 双窗格
        JSplitPane httpSplitPane = new JSplitPane();
        httpSplitPane.setResizeWeight(0.50);
        // request
        JTabbedPane reqJTabbedPane = new JTabbedPane();
        reqJTabbedPane.add("Request",bypassTable.getRequestViewer().getComponent());
        // response
        JTabbedPane resJTabbedPane = new JTabbedPane();
        resJTabbedPane.add("Response", bypassTable.getResponseViewer().getComponent());
        httpSplitPane.add(reqJTabbedPane,"left");
        httpSplitPane.add(resJTabbedPane,"right");
        splitPane.setRightComponent(httpSplitPane);


        // 控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlPanel.setBorder(new EmptyBorder(4, 8, 4, 8));

        isAutoCheckBox = new JCheckBox("Auto Scan", false);
        isAutoCheckBox.addActionListener(e -> Utils.isProxySelected = isAutoCheckBox.isSelected());
        controlPanel.add(isAutoCheckBox);

        controlPanel.add(new JLabel("Threads:"));
        threadNumText = new JTextField(2);
        threadNumText.setText(String.valueOf(Utils.getConfigThreads(DEFAULT_THREAD_NUM)));
        controlPanel.add(threadNumText);

        controlPanel.add(Box.createHorizontalStrut(8));

        controlPanel.add(new JLabel("Req:"));
        allRequestNumberText = new JLabel("0");
        controlPanel.add(allRequestNumberText);

        controlPanel.add(new JLabel("/"));
        finishRequestNumberText = new JLabel("0");
        controlPanel.add(finishRequestNumberText);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(false);
        progressBar.setValue(0);
        progressBar.setBorderPainted(false);
        progressBar.setPreferredSize(new Dimension(120, 6));
        controlPanel.add(progressBar);

        controlPanel.add(Box.createHorizontalStrut(8));

        controlPanel.add(new JLabel("Err:"));
        errorRequestNumText = new JLabel("0");
        controlPanel.add(errorRequestNumText);

        controlPanel.add(Box.createHorizontalStrut(8));

        JButton clearButton = new JButton("Clear");
        clearButton.setMargin(new Insets(2, 8, 2, 8));
        clearButton.addActionListener(e -> {
            bypassTableModel.clearAll();
            allRequestNumberText.setText("0");
            finishRequestNumberText.setText("0");
            errorRequestNumText.setText("0");
            Utils.count = 0;
            updateProgressBar();
        });
        controlPanel.add(clearButton);

        JPanel databoardPanel = new JPanel(new BorderLayout());
        databoardPanel.add(controlPanel, BorderLayout.NORTH);
        databoardPanel.add(splitPane, BorderLayout.CENTER);

        this.configPanel = new ConfigPanel();
        this.manualWafPanel = new ManualWafPanel();

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Dashboard", databoardPanel);
        tabs.addTab("Manual WAF", this.manualWafPanel);
        tabs.addTab("Config", this.configPanel);

        add(tabs, BorderLayout.CENTER);

        BurpExtender.callbacks.customizeUiComponent(this);
    }

    public String getTabCaption() {

        return "BypassPro";
    }

    public Component getUiComponent() {

        return this;
    }

    public int getThreadNum() {
        if(StringUtils.isBlank(threadNumText.getText())) {
            return DEFAULT_THREAD_NUM;
        }
        try {
            return Integer.parseInt(threadNumText.getText());
        } catch (NumberFormatException e) {
            return DEFAULT_THREAD_NUM;
        }
    }

    public BypassTableModel getBypassTableModel() {

        return bypassTableModel;
    }

    public void setAllRequestNumberText(int num) {
        allRequestNumberText.setText(String.valueOf(num));
    }

    public void addAllRequestNum(int num) {
        SwingUtilities.invokeLater(() -> {
            setAllRequestNumberText(Integer.parseInt(allRequestNumberText.getText()) + num);
            updateProgressBar();
        });
    }

    public void addFinishRequestNum(int num) {
        SwingUtilities.invokeLater(() -> {
            finishRequestNumberText.setText(String.valueOf(Integer.parseInt(finishRequestNumberText.getText()) + num));
            updateProgressBar();
        });
    }

    public void addErrorRequestNum(int num) {
        SwingUtilities.invokeLater(() -> errorRequestNumText.setText(String.valueOf(Integer.parseInt(errorRequestNumText.getText()) + num)));
    }

    public double getSimilarityThreshold() {
        // 统一从 Config 中读取，Dashboard 不再单独维护阈值输入框
        return Utils.getConfigSimilarityThreshold(DEFAULT_SIMILARITY_THRESHOLD);
    }

    private void updateProgressBar() {
        if (progressBar == null) return;
        int all = 0, finish = 0;
        try {
            all = Integer.parseInt(allRequestNumberText.getText());
            finish = Integer.parseInt(finishRequestNumberText.getText());
        } catch (Exception ignored) {}

        if (all <= 0) {
            progressBar.setIndeterminate(false);
            progressBar.setValue(0);
        } else if (finish >= all) {
            progressBar.setIndeterminate(false);
            progressBar.setValue(100);
        } else {
            progressBar.setIndeterminate(true);
        }
    }


    public JCheckBox getIsAutoCheckBox() {
        return isAutoCheckBox;
    }

    public void setIsAutoCheckBox(JCheckBox isAutoCheckBox) {
        this.isAutoCheckBox = isAutoCheckBox;
    }

    /**
     * 从配置文件更新 UI 默认值
     */
    public void updateFromConfig() {
        SwingUtilities.invokeLater(() -> {
            threadNumText.setText(String.valueOf(Utils.getConfigThreads(DEFAULT_THREAD_NUM)));
        });
    }

    public ManualWafPanel getManualWafPanel() {
        return manualWafPanel;
    }
}
