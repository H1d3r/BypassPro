package Main;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;
import java.awt.*;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class ConfigPanel extends JPanel {
    private final JTextField configPathText;
    private final JLabel formatLabel;
    private final JTextArea accessControlTextArea;
    private final JTextArea wafRulesTextArea;
    private final JTextArea rawTextArea;
    private final Yaml yamlDumper;

    // General Options
    private final JTextField tfThreads;
    private final JTextField tfSimilarityThreshold;

    // WAF Options 复选框
    private final JCheckBox cbUtf16;
    private final JCheckBox cbUtf16be;
    private final JCheckBox cbUtf16le;
    private final JCheckBox cbUtf32;
    private final JCheckBox cbUtf32be;
    private final JCheckBox cbUtf32le;
    private final JCheckBox cbIbm037;
    private final JCheckBox cbGzip;
    private final JCheckBox cbFormUrlencoded;
    private final JCheckBox cbMultipart;
    private final JCheckBox cbTextPlain;

    public ConfigPanel() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top panel: config path + buttons
        JPanel top = new JPanel(new BorderLayout(8, 0));
        JLabel pathLabel = new JLabel("Config Path:");
        configPathText = new JTextField();
        configPathText.setEditable(false);

        formatLabel = new JLabel("");

        JButton reloadButton = new JButton("Reload");
        JButton reinitButton = new JButton("Reinit");

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(formatLabel);
        buttons.add(reinitButton);
        buttons.add(reloadButton);

        top.add(pathLabel, BorderLayout.WEST);
        top.add(configPathText, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);

        this.yamlDumper = createYamlDumper();

        // General Options
        tfThreads = new JTextField(5);
        tfSimilarityThreshold = new JTextField(5);

        // Access Control Tab - 只有 Rules
        accessControlTextArea = createReadOnlyTextArea();
        JScrollPane acScrollPane = new JScrollPane(accessControlTextArea);
        acScrollPane.setBorder(BorderFactory.createTitledBorder("Rules: access_control"));

        // WAF Tab - Rules + Options
        wafRulesTextArea = createReadOnlyTextArea();

        // 创建 WAF Options 复选框
        cbUtf16 = new JCheckBox("UTF-16");
        cbUtf16be = new JCheckBox("UTF-16BE");
        cbUtf16le = new JCheckBox("UTF-16LE");
        cbUtf32 = new JCheckBox("UTF-32");
        cbUtf32be = new JCheckBox("UTF-32BE");
        cbUtf32le = new JCheckBox("UTF-32LE");
        cbIbm037 = new JCheckBox("IBM037");
        cbGzip = new JCheckBox("Gzip");
        cbFormUrlencoded = new JCheckBox("form-urlencoded");
        cbMultipart = new JCheckBox("multipart");
        cbTextPlain = new JCheckBox("text/plain");

        JPanel generalPanel = createGeneralPanel();
        JPanel wafPanel = createWafPanel();

        // Raw Tab
        rawTextArea = createReadOnlyTextArea();
        JScrollPane rawScrollPane = new JScrollPane(rawTextArea);
        rawScrollPane.setBorder(BorderFactory.createTitledBorder("Raw File"));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("General", generalPanel);
        tabs.addTab("Access Control", acScrollPane);
        tabs.addTab("WAF", wafPanel);
        tabs.addTab("Raw", rawScrollPane);

        add(top, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);

        reloadButton.addActionListener(e -> reload());
        reinitButton.addActionListener(e -> reinit());

        refreshView();
    }

    private JPanel createGeneralPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder("通用配置"));

        // Threads
        JPanel threadsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        threadsPanel.add(new JLabel("线程数 (Threads):"));
        threadsPanel.add(tfThreads);
        optionsPanel.add(threadsPanel);

        // Similarity Threshold
        JPanel thresholdPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        thresholdPanel.add(new JLabel("相似度阈值 (Diff Thresh):"));
        thresholdPanel.add(tfSimilarityThreshold);
        thresholdPanel.add(new JLabel("(0-1，值越大越“宽松”，更容易入表；值越小越“严格”，更少噪声)"));
        optionsPanel.add(thresholdPanel);

        // Save button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save General");
        saveButton.addActionListener(e -> saveGeneralOptions());
        buttonPanel.add(saveButton);
        optionsPanel.add(buttonPanel);

        // 说明文字
        JTextArea helpText = new JTextArea();
        helpText.setEditable(false);
        helpText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        helpText.setText(
            "说明：\n" +
            "- 线程数：并发请求数，建议 3-10\n" +
            "- 相似度阈值：0-1 表示“响应与原始响应的相似程度”。\n" +
            "  - 值越大：越容易入表（更宽松，噪声可能更多）\n" +
            "  - 值越小：越不容易入表（更严格，只保留差异更大的响应）\n" +
            "- 修改后点击 Save General 保存到配置文件\n" +
            "- 保存后立即生效（Dashboard 不再单独维护阈值）"
        );
        helpText.setBorder(BorderFactory.createTitledBorder("帮助"));

        panel.add(optionsPanel, BorderLayout.NORTH);
        panel.add(helpText, BorderLayout.CENTER);

        return panel;
    }

    private void saveGeneralOptions() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            JOptionPane.showMessageDialog(this, "ConfigLoader not available", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            int threads = Integer.parseInt(tfThreads.getText().trim());
            double threshold = Double.parseDouble(tfSimilarityThreshold.getText().trim());

            if (threads < 1 || threads > 100) {
                JOptionPane.showMessageDialog(this, "线程数应在 1-100 之间", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (threshold < 0 || threshold > 1) {
                JOptionPane.showMessageDialog(this, "相似度阈值应在 0-1 之间", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            boolean success = loader.saveGeneralConfig(threads, threshold);
            if (success) {
                Map<String, Object> config = loader.loadConfig();
                Utils.setConfigMap(config);
                refreshView();
                // 同步更新 MainPanel 的默认值
                if (Utils.panel != null) {
                    Utils.panel.updateFromConfig();
                }
                JOptionPane.showMessageDialog(this, "General options saved successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Failed to save general options", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "请输入有效的数字", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createWafPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Rules area (top)
        JScrollPane rulesScroll = new JScrollPane(wafRulesTextArea);
        rulesScroll.setBorder(BorderFactory.createTitledBorder("Rules: waf"));
        rulesScroll.setPreferredSize(new Dimension(0, 300));

        // Options area (bottom)
        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Options (仅对 POST/PUT 等有 Body 的请求生效)",
                TitledBorder.LEFT,
                TitledBorder.TOP));

        // Body Charset
        JPanel charsetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        charsetPanel.setBorder(BorderFactory.createTitledBorder("Body Charset"));
        charsetPanel.add(cbUtf16);
        charsetPanel.add(cbUtf16be);
        charsetPanel.add(cbUtf16le);
        charsetPanel.add(cbUtf32);
        charsetPanel.add(cbUtf32be);
        charsetPanel.add(cbUtf32le);
        charsetPanel.add(cbIbm037);

        // Body Transform
        JPanel transformPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        transformPanel.setBorder(BorderFactory.createTitledBorder("Body Transform"));
        transformPanel.add(cbGzip);

        // Content-Type Spoof
        JPanel ctPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ctPanel.setBorder(BorderFactory.createTitledBorder("Content-Type Spoof"));
        ctPanel.add(cbFormUrlencoded);
        ctPanel.add(cbMultipart);
        ctPanel.add(cbTextPlain);

        // Save button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save Options");
        saveButton.addActionListener(e -> saveOptions());
        buttonPanel.add(saveButton);

        optionsPanel.add(charsetPanel);
        optionsPanel.add(transformPanel);
        optionsPanel.add(ctPanel);
        optionsPanel.add(buttonPanel);

        panel.add(rulesScroll, BorderLayout.CENTER);
        panel.add(optionsPanel, BorderLayout.SOUTH);

        return panel;
    }

    public void refreshView() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader != null) {
            configPathText.setText(loader.getConfigFilePath());
            rawTextArea.setText(loader.readConfigText());

            Map<String, Object> root = loader.loadConfig();
            if (root == null) {
                root = Collections.emptyMap();
            }

            Object profilesObj = root.get("profiles");
            if (profilesObj instanceof Map) {
                formatLabel.setText("Format: profiles");
            } else {
                formatLabel.setText("Format: legacy");
            }

            // 加载 General 配置
            loadGeneralOptions();

            Map<String, Object> ac = Utils.getProfileConfig("access_control");
            Map<String, Object> waf = Utils.getProfileConfig("waf");
            accessControlTextArea.setText(toYaml(filterRulesOnly(ac)));
            wafRulesTextArea.setText(toYaml(filterRulesOnly(waf)));

            // 加载 WAF Options 到复选框
            loadWafOptions(waf);
        } else {
            configPathText.setText("");
            formatLabel.setText("");
            accessControlTextArea.setText("");
            wafRulesTextArea.setText("");
            rawTextArea.setText("");
            resetGeneralOptions();
            resetWafOptions();
        }
    }

    private void loadGeneralOptions() {
        int threads = Utils.getConfigThreads(5);
        double threshold = Utils.getConfigSimilarityThreshold(0.85);
        tfThreads.setText(String.valueOf(threads));
        tfSimilarityThreshold.setText(String.valueOf(threshold));
    }

    private void resetGeneralOptions() {
        tfThreads.setText("5");
        tfSimilarityThreshold.setText("0.85");
    }

    private Map<String, Object> filterRulesOnly(Map<String, Object> profile) {
        if (profile == null) return Collections.emptyMap();
        Map<String, Object> rules = new LinkedHashMap<>();
        if (profile.containsKey("suffix")) rules.put("suffix", profile.get("suffix"));
        if (profile.containsKey("headers")) rules.put("headers", profile.get("headers"));
        if (profile.containsKey("prefix")) rules.put("prefix", profile.get("prefix"));
        if (profile.containsKey("boundary_insert")) rules.put("boundary_insert", profile.get("boundary_insert"));
        return rules;
    }

    @SuppressWarnings("unchecked")
    private void loadWafOptions(Map<String, Object> waf) {
        resetWafOptions();
        if (waf == null) return;

        Object optionsObj = waf.get("options");
        if (!(optionsObj instanceof Map)) return;
        Map<String, Object> options = (Map<String, Object>) optionsObj;

        // Body Charset
        Object charsetObj = options.get("body_charset");
        if (charsetObj instanceof Map) {
            Map<String, Object> charset = (Map<String, Object>) charsetObj;
            cbUtf16.setSelected(Boolean.TRUE.equals(charset.get("utf_16")));
            cbUtf16be.setSelected(Boolean.TRUE.equals(charset.get("utf_16be")));
            cbUtf16le.setSelected(Boolean.TRUE.equals(charset.get("utf_16le")));
            cbUtf32.setSelected(Boolean.TRUE.equals(charset.get("utf_32")));
            cbUtf32be.setSelected(Boolean.TRUE.equals(charset.get("utf_32be")));
            cbUtf32le.setSelected(Boolean.TRUE.equals(charset.get("utf_32le")));
            cbIbm037.setSelected(Boolean.TRUE.equals(charset.get("ibm037")));
        }

        // Body Transform
        Object transformObj = options.get("body_transform");
        if (transformObj instanceof Map) {
            Map<String, Object> transform = (Map<String, Object>) transformObj;
            cbGzip.setSelected(Boolean.TRUE.equals(transform.get("gzip")));
        }

        // Content-Type Spoof
        Object ctObj = options.get("content_type_spoof");
        if (ctObj instanceof Map) {
            Map<String, Object> ct = (Map<String, Object>) ctObj;
            cbFormUrlencoded.setSelected(Boolean.TRUE.equals(ct.get("form_urlencoded")));
            cbMultipart.setSelected(Boolean.TRUE.equals(ct.get("multipart")));
            cbTextPlain.setSelected(Boolean.TRUE.equals(ct.get("text_plain")));
        }
    }

    private void resetWafOptions() {
        cbUtf16.setSelected(false);
        cbUtf16be.setSelected(false);
        cbUtf16le.setSelected(false);
        cbUtf32.setSelected(false);
        cbUtf32be.setSelected(false);
        cbUtf32le.setSelected(false);
        cbIbm037.setSelected(false);
        cbGzip.setSelected(false);
        cbFormUrlencoded.setSelected(false);
        cbMultipart.setSelected(false);
        cbTextPlain.setSelected(false);
    }

    private void saveOptions() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            JOptionPane.showMessageDialog(this, "ConfigLoader not available", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 构建 options Map
        Map<String, Object> options = new LinkedHashMap<>();

        Map<String, Object> bodyCharset = new LinkedHashMap<>();
        bodyCharset.put("utf_16", cbUtf16.isSelected());
        bodyCharset.put("utf_16be", cbUtf16be.isSelected());
        bodyCharset.put("utf_16le", cbUtf16le.isSelected());
        bodyCharset.put("utf_32", cbUtf32.isSelected());
        bodyCharset.put("utf_32be", cbUtf32be.isSelected());
        bodyCharset.put("utf_32le", cbUtf32le.isSelected());
        bodyCharset.put("ibm037", cbIbm037.isSelected());
        options.put("body_charset", bodyCharset);

        Map<String, Object> bodyTransform = new LinkedHashMap<>();
        bodyTransform.put("gzip", cbGzip.isSelected());
        options.put("body_transform", bodyTransform);

        Map<String, Object> contentTypeSpoof = new LinkedHashMap<>();
        contentTypeSpoof.put("form_urlencoded", cbFormUrlencoded.isSelected());
        contentTypeSpoof.put("multipart", cbMultipart.isSelected());
        contentTypeSpoof.put("text_plain", cbTextPlain.isSelected());
        options.put("content_type_spoof", contentTypeSpoof);

        boolean success = loader.saveWafOptions(options);
        if (success) {
            // 重新加载配置
            Map<String, Object> config = loader.loadConfig();
            Utils.setConfigMap(config);
            refreshView();
            JOptionPane.showMessageDialog(this, "Options saved successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Failed to save options", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void reload() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader != null) {
            Map<String, Object> config = loader.loadConfig();
            Utils.setConfigMap(config);
            refreshView();
            System.out.println("reload success...");
        }
    }

    private void reinit() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            return;
        }

        int retCode = JOptionPane.showConfirmDialog(this,
                "Do you want to reinitialize config? This action will overwrite your existing config.",
                "Info",
                JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            boolean ok = loader.initConfig();
            if (ok) {
                Map<String, Object> config = loader.loadConfig();
                Utils.setConfigMap(config);
                refreshView();
                System.out.println("reinit success...");
            }
        }
    }

    private JTextArea createReadOnlyTextArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setTabSize(2);
        return ta;
    }

    private Yaml createYamlDumper() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setProcessComments(false);
        loaderOptions.setAllowRecursiveKeys(false);

        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        dop.setPrettyFlow(true);
        dop.setIndent(2);

        Representer representer = new Representer(dop);
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private String toYaml(Object o) {
        try {
            return yamlDumper.dump(o == null ? Collections.emptyMap() : o);
        } catch (Exception e) {
            return "";
        }
    }
}
