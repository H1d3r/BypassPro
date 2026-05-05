package Main;

import Main.ghostbits.GhostBitsEngine;
import Main.ghostbits.GhostBitsCodec;
import Main.ghostbits.GhostBitsRule;
import Main.ghostbits.RawSocketSender;
import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Stack;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * Manual WAF Bypass Panel
 */
public class ManualWafPanel extends JPanel implements IMessageEditorController {

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private JTable historyTable;
    private HistoryTableModel historyModel;
    private final List<HistoryEntry> historyEntries = new ArrayList<>();
    private int historySeq = 0;
    private static final int MAX_HISTORY_SIZE = 50;
    private static final int MAX_UNDO_STEPS = 20;
    private static final int MAX_REDO_STEPS = 20;

    private IHttpService currentHttpService;
    private byte[] currentResponseBytes = new byte[0];
    private byte[] originalRequest = new byte[0];

    private final Stack<byte[]> undoStack = new Stack<>();
    private final Stack<byte[]> redoStack = new Stack<>();

    private JTextField hostField;
    private JTextField portField;
    private JCheckBox httpsCheckBox;
    private JCheckBox followRedirectCheckBox;
    private JButton sendBtn;
    private JButton sendDropdownBtn;
    private JButton cancelBtn;
    private JButton undoBtn;
    private JButton redoBtn;
    private JLabel statusLabel;
    private volatile boolean isCancelled = false;
    private volatile Thread sendThread = null;
    private JLabel inspectorRequestLineLabel;
    private JLabel inspectorMetaLabel;
    private JLabel inspectorFlagsLabel;
    private JLabel inspectorHintsLabel;
    private JLabel inspectorDiffLabel;
    private JLabel ghostSelectionFoldLabel;
    private JLabel ghostPreviewRiskLabel;
    private Timer inspectorTimer;
    private byte[] lastInspectorBytes = new byte[0];
    private byte[] lastInspectorSelectionBytes = new byte[0];
    private Integer pendingRequestCaretPosition = null;

    private static final Pattern TAG_DIRTY = Pattern.compile("\\{\\{\\s*dirty\\((\\d+)\\)\\s*\\}\\}");
    private static final Pattern TAG_DIRTY_NULL = Pattern.compile("\\{\\{\\s*dirtynull\\((\\d+)\\)\\s*\\}\\}");

    /** 发送策略：AUTO 根据请求内容是否含非 ASCII 自动选 */
    enum SenderMode {
        AUTO, BURP, RAW
    }

    private SenderMode senderMode = SenderMode.AUTO;

    /**
     * Atoms 区注入策略。
     * SELECTION 历史命名保留，语义为"光标处插入"（caret-or-fallback）：
     * 优先用 JTextComponent 的 caret 位置插入；Hex 视图等拿不到 caret 时回退到选区路径。
     */
    enum AtomTarget {
        SELECTION, SUFFIX, SEG_PREFIX, SEG_SUFFIX, INTERLEAVE, REPLACE_SPACE
    }

    private AtomTarget atomTarget = AtomTarget.SELECTION;

    private GhostBitsCodec.FoldMode ghostFoldMode = GhostBitsCodec.FoldMode.BIT_8;
    private JToggleButton ghostFold8BitBtn;
    private JToggleButton ghostFold7BitBtn;
    private JPanel ghostTemplatePathRow;

    public ManualWafPanel() {
        setLayout(new BorderLayout());

        JPanel toolbar = createToolbar();

        // Request | Response
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.5);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestViewer = Utils.callbacks.createMessageEditor(this, true);
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responseViewer = Utils.callbacks.createMessageEditor(this, false);
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        mainSplit.setLeftComponent(requestPanel);
        mainSplit.setRightComponent(responsePanel);

        // Bottom: Tools | History
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplit.setResizeWeight(0.6);
        bottomSplit.setLeftComponent(createBypassToolsPanel());
        bottomSplit.setRightComponent(createHistoryPanel());
        bottomSplit.setPreferredSize(new Dimension(0, 200));

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(mainSplit);
        verticalSplit.setBottomComponent(bottomSplit);
        verticalSplit.setResizeWeight(0.76);

        add(toolbar, BorderLayout.NORTH);
        add(verticalSplit, BorderLayout.CENTER);
        add(createStatusPanel(), BorderLayout.SOUTH);

        setupShortcuts();
        startRequestInspectorTimer();
        updateUndoRedoButtons();
    }

    private JPanel createStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusPanel.setBorder(BorderFactory.createEtchedBorder());
        statusLabel = new JLabel(I18n.t("status.ready"));
        statusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        statusPanel.add(statusLabel);
        return statusPanel;
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(new EmptyBorder(5, 8, 5, 8));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        sendBtn = new JButton("Send");
        sendBtn.setBackground(new Color(255, 102, 51));
        sendBtn.setForeground(Color.WHITE);
        sendBtn.setFocusPainted(false);
        sendBtn.setToolTipText("Send (Auto: 含非 ASCII -> Raw, 否则 Burp)");
        sendBtn.addActionListener(e -> sendRequest());

        sendDropdownBtn = new JButton("▾");
        sendDropdownBtn.setBackground(new Color(255, 102, 51));
        sendDropdownBtn.setForeground(Color.WHITE);
        sendDropdownBtn.setFocusPainted(false);
        sendDropdownBtn.setMargin(new Insets(2, 4, 2, 4));
        sendDropdownBtn.setToolTipText("选择发送模式");
        sendDropdownBtn.addActionListener(e -> showSendModeMenu(sendDropdownBtn));

        cancelBtn = new JButton("Cancel");
        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> cancelRequest());

        undoBtn = new JButton("←");
        redoBtn = new JButton("→");
        JButton resetBtn = new JButton("Reset");
        undoBtn.setToolTipText("撤销");
        redoBtn.setToolTipText("恢复");
        resetBtn.setToolTipText("恢复到原始请求");
        undoBtn.addActionListener(e -> undo());
        redoBtn.addActionListener(e -> redo());
        resetBtn.addActionListener(e -> reset());

        followRedirectCheckBox = new JCheckBox("Follow Redirect");
        followRedirectCheckBox.setToolTipText("自动跟随 301/302/303/307/308 跳转");

        left.add(sendBtn);
        left.add(sendDropdownBtn);
        left.add(cancelBtn);
        left.add(Box.createHorizontalStrut(10));
        left.add(undoBtn);
        left.add(redoBtn);
        left.add(resetBtn);
        left.add(Box.createHorizontalStrut(10));
        left.add(followRedirectCheckBox);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        right.add(new JLabel(I18n.t("label.host")));
        hostField = new JTextField(16);
        right.add(hostField);
        right.add(new JLabel(I18n.t("label.port")));
        portField = new JTextField(5);
        right.add(portField);
        httpsCheckBox = new JCheckBox("HTTPS");
        right.add(httpsCheckBox);

        toolbar.add(left, BorderLayout.WEST);
        toolbar.add(right, BorderLayout.EAST);
        return toolbar;
    }

    private void showSendModeMenu(Component anchor) {
        JPopupMenu menu = new JPopupMenu();

        JRadioButtonMenuItem auto = new JRadioButtonMenuItem(
                "Auto (含非 ASCII -> Raw)", senderMode == SenderMode.AUTO);
        auto.addActionListener(e -> setSenderMode(SenderMode.AUTO));

        JRadioButtonMenuItem burp = new JRadioButtonMenuItem(
                "Send (Burp)", senderMode == SenderMode.BURP);
        burp.addActionListener(e -> setSenderMode(SenderMode.BURP));

        JRadioButtonMenuItem raw = new JRadioButtonMenuItem(
                "Send (Raw Socket)", senderMode == SenderMode.RAW);
        raw.addActionListener(e -> setSenderMode(SenderMode.RAW));

        ButtonGroup bg = new ButtonGroup();
        bg.add(auto);
        bg.add(burp);
        bg.add(raw);

        menu.add(auto);
        menu.add(burp);
        menu.add(raw);
        menu.addSeparator();
        JMenuItem hint = new JMenuItem("Raw 模式直连目标，不走 Burp 上游代理，禁用证书校验（CTF/测试）");
        hint.setEnabled(false);
        menu.add(hint);

        menu.show(anchor, 0, anchor.getHeight());
    }

    private void setSenderMode(SenderMode mode) {
        this.senderMode = mode;
        if (sendBtn != null) {
            switch (mode) {
                case BURP:
                    sendBtn.setText("Send (Burp)");
                    break;
                case RAW:
                    sendBtn.setText("Send (Raw)");
                    break;
                default:
                    sendBtn.setText("Send");
            }
        }
    }

    /**
     * AUTO 模式只检查请求行 + 头部是否含非 ASCII。
     * 不看 body，避免被 JSON 中文 / 二进制上传 / gzip / UTF-16 编码 body 误伤。
     * Ghost Bits 真正依赖 char->byte 低位还原的位置都在 request line / headers。
     */
    private boolean shouldUseRawSocket(byte[] requestBytes) {
        if (senderMode == SenderMode.RAW)
            return true;
        if (senderMode == SenderMode.BURP)
            return false;
        // AUTO
        if (requestBytes == null)
            return false;

        // 找到 \r\n\r\n 的位置作为头部结束（兼容 \n\n）
        int headerEnd = findHeaderEnd(requestBytes);
        int upper = headerEnd > 0 ? headerEnd : requestBytes.length;

        for (int i = 0; i < upper; i++) {
            if ((requestBytes[i] & 0xFF) > 0x7F)
                return true;
        }
        return false;
    }

    /**
     * 返回头部结束位置（含分隔符末尾偏移），找不到返回 -1。
     */
    private static int findHeaderEnd(byte[] bytes) {
        if (bytes == null)
            return -1;
        for (int i = 0; i + 3 < bytes.length; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n'
                    && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    private void cancelRequest() {
        isCancelled = true;
        if (sendThread != null) {
            sendThread.interrupt();
        }
        SwingUtilities.invokeLater(() -> {
            if (sendBtn != null) {
                sendBtn.setEnabled(true);
                setSenderMode(senderMode);
            }
            if (cancelBtn != null) {
                cancelBtn.setEnabled(false);
            }
            if (statusLabel != null) {
                statusLabel.setText(I18n.t("status.cancelled"));
            }
        });
    }

    private void setupShortcuts() {
        if (requestViewer == null)
            return;
        Component editorComponent = requestViewer.getComponent();
        addCtrlEnterListener(editorComponent);
    }

    private void addCtrlEnterListener(Component comp) {
        if (comp instanceof JComponent) {
            JComponent jc = (JComponent) comp;
            KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
            KeyStroke metaEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.META_DOWN_MASK);

            String actionName = "BypassProManualWafSendRequest";

            jc.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlEnter, actionName);
            jc.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(ctrlEnter, actionName);
            jc.getInputMap(JComponent.WHEN_FOCUSED).put(metaEnter, actionName);
            jc.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(metaEnter, actionName);

            jc.getActionMap().put(actionName, new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (sendBtn != null && sendBtn.isEnabled()) {
                        sendRequest();
                    }
                }
            });
        }

        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                addCtrlEnterListener(child);
            }
        }
    }

    private JPanel createBypassToolsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Bypass Tools"));

        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        tabs.addTab("Obfuscation & Noise", createObfuscationNoisePanel());
        tabs.addTab("Data Encoding", createDataEncodingPanel());
        tabs.addTab("Char Mutation", createUnicodeNormalizationPanel());
        tabs.addTab("Header Bypass", createHeaderSpoofPanel());
        tabs.addTab("Body Bypass", createBodyTransformPanel());
        tabs.addTab("Gh0st Bits", createGhostBitsPanel());

        inspectorRequestLineLabel = createInspectorLine("Request: -");
        inspectorMetaLabel = createInspectorLine("Meta: -");
        inspectorFlagsLabel = createInspectorLine("Flags: -");
        inspectorHintsLabel = createInspectorLine("Payload hints: -");
        inspectorDiffLabel = createInspectorLine("Diff: -");

        Color separatorColor = UIManager.getColor("Separator.foreground");
        if (separatorColor == null) {
            separatorColor = new Color(90, 90, 90);
        }

        JPanel current = new JPanel(new GridLayout(2, 1, 2, 0));
        current.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, separatorColor),
                new EmptyBorder(5, 6, 5, 6)));

        JPanel currentTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        currentTop.add(inspectorRequestLineLabel);
        currentTop.add(inspectorMetaLabel);

        JPanel currentBottom = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        currentBottom.add(inspectorFlagsLabel);
        currentBottom.add(inspectorHintsLabel);
        currentBottom.add(inspectorDiffLabel);

        current.add(currentTop);
        current.add(currentBottom);

        panel.add(tabs, BorderLayout.CENTER);
        panel.add(current, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createObfuscationNoisePanel() {
        JPanel outer = new JPanel(new BorderLayout());
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(2, 6, 2, 6));

        content.add(createSectionSeparator("Noise Atoms"));

        // ── Noise 作用方式（仅控制 Atoms 区）──
        JPanel targetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JLabel targetLabel = new JLabel(I18n.t("label.noise_target"));
        targetLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        targetPanel.add(targetLabel);

        ButtonGroup targetGroup = new ButtonGroup();
        String[][] targets = {
                { "光标处插入", "SELECTION" }, { "Path 末尾", "SUFFIX" }, { "每段前", "SEG_PREFIX" },
                { "每段后", "SEG_SUFFIX" }, { "字符间", "INTERLEAVE" }, { "替换空格", "REPLACE_SPACE" }
        };
        for (String[] t : targets) {
            JRadioButton rb = new JRadioButton(t[0], "SELECTION".equals(t[1]));
            rb.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
            final String val = t[1];
            rb.setToolTipText(noiseTargetTooltip(val));
            rb.addActionListener(e -> atomTarget = AtomTarget.valueOf(val));
            targetGroup.add(rb);
            targetPanel.add(rb);
        }
        targetPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        targetPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(targetPanel);

        // ── Atoms 区（受 Target 控制）──
        JPanel atomsPanel = createToolCategoryPanel();
        addToolRow(atomsPanel, "Control Chars",
                atomButton("%00"), atomButton("%09"), atomButton("%0a"),
                atomButton("%0d"), atomButton("%20"), atomButton("%0b"),
                atomButton("%0c"));
        addToolRow(atomsPanel, "Space-like",
                atomButton("%a0"), atomButton("%2b"));
        addToolRow(atomsPanel, "Wrappers",
                atomButton("/**/"));
        addToolRow(atomsPanel, "Generated",
                toolButton("Dirty(N)", this::insertDirtyData),
                toolButton("Null(N)", this::insertNullBytes));
        atomsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(atomsPanel);

        // ── Path 专用变形，不受 Noise 作用方式控制 ──
        content.add(createSectionSeparator("Path Mutations"));

        // ── Path Mutations 区（不受 Noise 作用方式控制，每个按钮自带位置语义）──
        JPanel payloadsPanel = createToolCategoryPanel();
        addToolRow(payloadsPanel, "Traversal",
                toolButton("....//", tooltip("Traversal: ....//",
                        "选区: ../ -> ....//",
                        "无选区: 替换 path 中的 ../",
                        "用途: 绕过只匹配标准 ../ 的规则"),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "....//"))),
                toolButton("..%252f", tooltip("Traversal: ..%252f",
                        "选区: ../ -> ..%252f",
                        "无选区: 替换 path 中的 ../",
                        "用途: 双重 URL decode 后恢复 /"),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..%252f"))),
                toolButton("..%c0%af", tooltip("Traversal: ..%c0%af",
                        "选区: ../ -> ..%c0%af",
                        "无选区: 替换 path 中的 ../",
                        "用途: 历史 overlong UTF-8 slash 绕过思路"),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..%c0%af"))),
                toolButton(".%u002e", tooltip("Traversal: .%u002e",
                        I18n.t("tooltip.traversal.selection", "../", ".%u002e/"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.traversal.u002e.usage")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", ".%u002e/"))),
                toolButton("..\\\\", tooltip("Traversal: ..\\\\",
                        I18n.t("tooltip.traversal.selection", "../", "..\\\\"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.traversal.backslash.usage")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..\\\\"))));
        addToolRow(payloadsPanel, "Suffix",
                toolButton(".js", tooltip("Suffix: .js",
                        "选区: 在选区末尾追加 .js",
                        "无选区: 追加到 request path 末尾",
                        "用途: 静态资源伪装"),
                        () -> appendPathSuffix(".js")),
                toolButton(".css", tooltip("Suffix: .css",
                        "选区: 在选区末尾追加 .css",
                        "无选区: 追加到 request path 末尾",
                        "用途: 静态资源伪装"),
                        () -> appendPathSuffix(".css")),
                toolButton(";.js", tooltip("Suffix: ;.js",
                        "选区: 在选区末尾追加 ;.js",
                        "无选区: 追加到 request path 末尾",
                        "用途: 分号路径参数 + 静态资源伪装"),
                        () -> appendPathSuffix(";.js")),
                toolButton("/.", tooltip("Suffix: /.",
                        "选区: 在选区末尾追加 /.",
                        "无选区: 追加到 request path 末尾",
                        "用途: 路径规范化差异"),
                        () -> appendPathSuffix("/.")),
                toolButton("?", tooltip("Suffix: ?",
                        "选区: 在选区末尾追加 ?",
                        "无选区: 追加到 request path 末尾",
                        "用途: query 边界混淆"),
                        () -> appendPathSuffix("?")));
        addToolRow(payloadsPanel, "Segment",
                toolButton("//", tooltip("Segment: //",
                        "选区: 在选区前加 //",
                        "无选区: 给每个 path segment 加 //",
                        "用途: 双斜杠规范化 / path collapse 差异"),
                        () -> prefixEachPathSegment("//")),
                toolButton("/./", tooltip("Segment: /./",
                        "选区: 在选区前加 /./",
                        "无选区: 给每个 path segment 加 /./",
                        "用途: 当前目录规范化差异"),
                        () -> prefixEachPathSegment("/./")),
                toolButton("/%2e/", tooltip("Segment: /%2e/",
                        "选区: 在选区前加 /%2e/",
                        "无选区: 给每个 path segment 加 /%2e/",
                        "用途: 编码当前目录规范化差异"),
                        () -> prefixEachPathSegment("/%2e/")),
                toolButton(";/", tooltip("Segment: ;/",
                        "选区: 在选区前加 ;/",
                        "无选区: 给每个 path segment 加 ;/",
                        "用途: 分号路径参数 / segment 解析差异"),
                        () -> prefixEachPathSegment(";/")),
                toolButton("./", tooltip("Segment: ./",
                        "选区: 在选区前加 ./",
                        "无选区: 给每个 path segment 加 ./",
                        "用途: 当前目录规范化差异"),
                        () -> prefixEachPathSegment("./")),
                toolButton(".;/", tooltip("Segment: .;/",
                        "选区: 在选区前加 .;/",
                        "无选区: 给每个 path segment 加 .;/",
                        "用途: 点 + 分号组合解析差异"),
                        () -> prefixEachPathSegment(".;/")),
                toolButton("%2e/", tooltip("Segment: %2e/",
                        "选区: 在选区前加 %2e/",
                        "无选区: 给每个 path segment 加 %2e/",
                        "用途: 编码点前缀"),
                        () -> prefixEachPathSegment("%2e/")),
                toolButton("%252e/", tooltip("Segment: %252e/",
                        "选区: 在选区前加 %252e/",
                        "无选区: 给每个 path segment 加 %252e/",
                        "用途: 双重编码点前缀"),
                        () -> prefixEachPathSegment("%252e/")),
                toolButton("..%5c/", tooltip("Segment: ..%5c/",
                        "选区: 在选区前加 ..%5c/",
                        "无选区: 给每个 path segment 加 ..%5c/",
                        "用途: 编码反斜杠路径差异"),
                        () -> prefixEachPathSegment("..%5c/")));
        addToolRow(payloadsPanel, "Boundary",
                toolButton(";", tooltip("Boundary: ;",
                        "选区: 在选区末尾追加 ;",
                        "无选区: 给每个 path segment 追加 ;",
                        "用途: 矩阵参数 / 分号边界"),
                        () -> appendEachPathSegment(";")),
                toolButton(".;", tooltip("Boundary: .;",
                        "选区: 在选区末尾追加 .;",
                        "无选区: 给每个 path segment 追加 .;",
                        "用途: 点分号解析差异"),
                        () -> appendEachPathSegment(".;")),
                toolButton("..;", tooltip("Boundary: ..;",
                        "选区: 在选区末尾追加 ..;",
                        "无选区: 给每个 path segment 追加 ..;",
                        "用途: 点点分号解析差异"),
                        () -> appendEachPathSegment("..;")),
                toolButton(";param=1", tooltip("Boundary: ;param=1",
                        "选区: 在选区末尾追加 ;param=1",
                        "无选区: 给每个 path segment 追加 ;param=1",
                        "用途: 矩阵参数混淆"),
                        () -> appendEachPathSegment(";param=1")),
                toolButton(";jsessionid=1", tooltip("Boundary: ;jsessionid=1",
                        "选区: 在选区末尾追加 ;jsessionid=1",
                        "无选区: 给每个 path segment 追加 ;jsessionid=1",
                        "用途: Java session path 参数"),
                        () -> appendEachPathSegment(";jsessionid=1")),
                toolButton(";foo=bar", tooltip("Boundary: ;foo=bar",
                        "选区: 在选区末尾追加 ;foo=bar",
                        "无选区: 给每个 path segment 追加 ;foo=bar",
                        "用途: 泛化 matrix param / 分号参数解析差异"),
                        () -> appendEachPathSegment(";foo=bar")));
        payloadsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(payloadsPanel);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        outer.add(scroll, BorderLayout.CENTER);
        return outer;
    }

    /** Atoms 区按钮：根据当前 Target 策略决定插入行为 */
    private JButton atomButton(String text) {
        return toolButton(text, atomTooltip(text), () -> applyAtom(text));
    }

    private void applyAtom(String atom) {
        switch (atomTarget) {
            case SUFFIX:
                // 强制追加到 path 末尾，不受选区影响
                mutateRequestPath(path -> {
                    int q = path.indexOf('?');
                    if (q >= 0) {
                        return path.substring(0, q) + atom + path.substring(q);
                    }
                    return path + atom;
                });
                break;
            case SEG_PREFIX:
                // 强制给每个 path segment 加前缀，不受选区影响
                mutateRequestPath(path -> mutatePathOnly(path, seg -> seg.isEmpty() ? seg : atom + seg));
                break;
            case SEG_SUFFIX:
                // 强制给每个 path segment 加后缀，不受选区影响
                mutateRequestPath(path -> mutatePathOnly(path, seg -> seg.isEmpty() ? seg : seg + atom));
                break;
            case INTERLEAVE:
                transformSelection(s -> {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < s.length(); i++) {
                        sb.append(s.charAt(i));
                        if (i < s.length() - 1)
                            sb.append(atom);
                    }
                    return sb.toString();
                });
                break;
            case REPLACE_SPACE:
                if (hasSelectedRequestBytes()) {
                    transformSelection(s -> s.replace(" ", atom));
                } else {
                    // 无选区时替换 path 中的空格
                    mutateRequestPath(path -> path.replace(" ", atom));
                }
                break;
            case SELECTION:
            default:
                insertAt(atom);
                break;
        }
    }

    /** 带标题的分割线 */
    private JPanel createSectionSeparator(String title) {
        JPanel sep = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("── " + resolveSectionTitle(title) + " ──");
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        label.setForeground(new Color(120, 120, 120));
        sep.add(label);
        return sep;
    }

    private JPanel createHeaderSpoofPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Client IP",
                toolButton("XFF 127.0.0.1", () -> upsertRequestHeader("X-Forwarded-For", "127.0.0.1")),
                toolButton("X-Real-IP", () -> upsertRequestHeader("X-Real-IP", "127.0.0.1")),
                toolButton("X-Client-IP", () -> upsertRequestHeader("X-Client-IP", "127.0.0.1")),
                toolButton("X-Remote-Addr", () -> upsertRequestHeader("X-Remote-Addr", "127.0.0.1")),
                toolButton("CF-Connecting-IP", () -> upsertRequestHeader("CF-Connecting-IP", "127.0.0.1")),
                toolButton("Forwarded",
                        () -> upsertRequestHeader("Forwarded", "for=127.0.0.1;proto=http;host=127.0.0.1")));
        addToolRow(p, "Source Trust",
                toolButton("X-Custom-IP", () -> upsertRequestHeader("X-Custom-IP-Authorization", "127.0.0.1")),
                toolButton("Referer local", () -> upsertRequestHeader("Referer", "http://127.0.0.1")),
                toolButton("X-Host local", () -> upsertRequestHeader("X-Host", "127.0.0.1")),
                toolButton("XF Host local", () -> upsertRequestHeader("X-Forwarded-Host", "127.0.0.1")),
                toolButton("X-Original-URL", () -> upsertRequestHeader("X-Original-URL", "/")),
                toolButton("HTTP/1.0", this::switchToHttp10));
        return wrapToolPanel(p);
    }

    private JPanel createBodyTransformPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Type Spoof",
                toolButton("form", () -> setRequestContentType("application/x-www-form-urlencoded")),
                toolButton("text", () -> setRequestContentType("text/plain")),
                toolButton("json", () -> setRequestContentType("application/json")),
                toolButton("xml", () -> setRequestContentType("application/xml")));
        addToolRow(p, "Body Convert",
                toolButton("To Form", this::toFormUrlEncoded),
                toolButton("To Multipart", this::toMultipart),
                toolButton("To JSON", this::toJsonBody));
        addToolRow(p, "Body Wrap",
                toolButton("Gzip body", this::gzipBody));
        return wrapToolPanel(p);
    }

    private JPanel createDataEncodingPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "URL",
                toolButton("URL Encode", this::urlEncode),
                toolButton("Path Encode", this::pathUrlEncode),
                toolButton("Double URL", this::doubleUrlEncode),
                toolButton("Mixed Encode", this::mixedUrlEncode),
                toolButton("Unicode 转义", this::toUnicodeEscape));
        addToolRow(p, "Base64",
                toolButton("Base64 Encode", this::base64Encode));
        addToolRow(p, "Unicode Encoding",
                toolButton("UTF-16", () -> encodeBodyWithCharset("UTF-16")),
                toolButton("UTF-16BE", () -> encodeBodyWithCharset("UTF-16BE")),
                toolButton("UTF-16LE", () -> encodeBodyWithCharset("UTF-16LE")),
                toolButton("UTF-32", () -> encodeBodyWithCharset("UTF-32")),
                toolButton("UTF-32BE", () -> encodeBodyWithCharset("UTF-32BE")),
                toolButton("UTF-32LE", () -> encodeBodyWithCharset("UTF-32LE")));
        addToolRow(p, "EBCDIC Encoding",
                toolButton("IBM037", () -> encodeBodyWithCharset("IBM037")),
                toolButton("cp290", () -> encodeBodyWithCharset("cp290")));
        addToolRow(p, "Charset Params",
                toolButton("charset first", () -> moveCharsetParam(true)),
                toolButton("charset last", () -> moveCharsetParam(false)));
        return wrapToolPanel(p);
    }

    private JPanel createUnicodeNormalizationPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Unicode",
                toolButton("Fullwidth", this::toFullwidth),
                toolButton("Homoglyph", this::toHomoglyph),
                toolButton("Zero Width", this::insertZeroWidth));
        addToolRow(p, "Case",
                toolButton("Upper", this::toUpper),
                toolButton("Lower", this::toLower),
                toolButton("Random", this::toRandomCase));
        return wrapToolPanel(p);
    }

    private JPanel createGhostBitsPanel() {
        JPanel outer = new JPanel(new BorderLayout());

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(2, 6, 2, 6));

        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Ghost Encode",
                toolButton("Minimal", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.MINIMAL)),
                toolButton("Full", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.FULL)),
                toolButton("Letters", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.LETTERS)),
                toolButton("Digits", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.DIGITS)),
                toolButton("Symbols", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.SYMBOLS)),
                toolButton("Shuffle", this::randomizeGhostSelection));
        ghostFold8BitBtn = createFoldModeToggle("8-bit", GhostBitsCodec.FoldMode.BIT_8, true);
        ghostFold7BitBtn = createFoldModeToggle("7-bit", GhostBitsCodec.FoldMode.BIT_7, false);
        ButtonGroup foldGroup = new ButtonGroup();
        foldGroup.add(ghostFold8BitBtn);
        foldGroup.add(ghostFold7BitBtn);
        addToolRow(p, "Ghost 还原",
                toolButton("Preview", this::showFoldPreview),
                toolButton("Candidates", this::showGhostCandidates),
                ghostFold8BitBtn, ghostFold7BitBtn);
        addToolRow(p, "Common Payload",
                toolButton(".%u002e", () -> applyGhostSequence(".%u002e", "Path traversal chain: .%u002e -> ..")),
                toolButton("CRLF", () -> applyGhostSequence("\r\n", "CRLF pair for header/SMTP boundaries")),
                toolButton(".jsp", () -> applyGhostSequence(".jsp", "JSP suffix: Ghost restore -> .jsp")),
                toolButton("@type", () -> applyGhostSequence("@type", "JSON key: @type")),
                toolButton("class", () -> applyGhostSequence("class", "Java/Spring key: class")));
        addToolRow(p, "JSON Parser",
                toolButton("fastjson \\x4_", this::applyFastjsonLooseHexSelection),
                toolButton("fastjson \\u", this::applyFastjsonUnicodeSelection),
                toolButton("jackson \\u", this::applyJacksonUnicodeSelection),
                toolButton("Unicode Digits", this::applyUnicodeDigitsSelection));
        addToolRow(p, "URL/File Parser",
                toolButton("Jetty %2>", this::applyJettyLooseHexSelection),
                toolButton("Fullwidth URL", this::applyFullwidthUrlSelection),
                toolButton("Tomcat %HH", this::applyTomcatSevenBitHexSelection));
        ghostTemplatePathRow = addTemplateWrapRow(p, "模板",
                createAllGhostTemplateButtons());
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(p);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(12);

        outer.add(scroll, BorderLayout.CENTER);
        outer.add(createGhostCompactPreviewPanel(), BorderLayout.SOUTH);
        return outer;
    }

    private JPanel createGhostCompactPreviewPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 1, 2, 1));
        Color separatorColor = UIManager.getColor("Separator.foreground");
        if (separatorColor == null) {
            separatorColor = new Color(90, 90, 90);
        }
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, separatorColor),
                new EmptyBorder(4, 6, 3, 6)));

        ghostSelectionFoldLabel = createGhostPreviewLine(
                I18n.t("ghost.selection_fold") + ": " + I18n.t("ghost.risk.select"));
        ghostPreviewRiskLabel = createGhostPreviewLine(I18n.t("ghost.risk") + ": -");

        panel.add(ghostSelectionFoldLabel);
        panel.add(ghostPreviewRiskLabel);
        return panel;
    }

    private JLabel createGhostPreviewLine(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        label.setBorder(new EmptyBorder(0, 2, 0, 2));
        return label;
    }

    private JPanel createToolCategoryPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new EmptyBorder(4, 6, 4, 6));
        return p;
    }

    private JPanel wrapToolPanel(JPanel content) {
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(content, BorderLayout.NORTH);
        return outer;
    }

    /**
     * 配置变更后刷新 Templates 行按钮（由 ConfigPanel reload/reinit 调用）。
     */
    public void refreshGhostTemplates() {
        if (ghostTemplatePathRow == null) {
            return;
        }
        ghostTemplatePathRow.removeAll();
        for (JComponent btn : createAllGhostTemplateButtons()) {
            ghostTemplatePathRow.add(btn);
        }
        ghostTemplatePathRow.revalidate();
        ghostTemplatePathRow.repaint();
    }

    private JComponent[] createAllGhostTemplateButtons() {
        Map<String, GhostBitsRule.Template> templates = Utils.getGhostBitsRule().getTemplates();
        List<JComponent> buttons = new ArrayList<>();
        for (GhostBitsRule.Template t : templates.values()) {
            buttons.add(toolButton(templateButtonText(t), ghostTemplateTooltip(t), () -> applyGhostTemplate(t)));
        }
        if (buttons.isEmpty()) {
            JButton empty = toolButton("No templates",
                    I18n.t("tooltip.no_templates"), () -> {
                    });
            empty.setEnabled(false);
            return new JComponent[] { empty };
        }
        return buttons.toArray(new JComponent[0]);
    }

    private String templateButtonText(GhostBitsRule.Template t) {
        String label = t.getLabel();
        if (label == null || label.trim().isEmpty()) {
            label = t.getId();
        }
        if (label == null || label.trim().isEmpty()) {
            label = "template";
        }
        return label.length() > 22 ? label.substring(0, 19) + "..." : label;
    }

    private String ghostTemplateTooltip(GhostBitsRule.Template t) {
        String label = t.getLabel() == null || t.getLabel().isEmpty() ? t.getId() : t.getLabel();
        return tooltip(label,
                "来自 YAML: profiles.manual_waf_bypass.ghost_bits.templates." + t.getId(),
                "目标: " + t.getTarget(),
                "发送: " + ("raw".equalsIgnoreCase(t.getSender()) ? "Raw Socket recommended" : "Burp OK / Raw OK"),
                "操作: 按模板 target 自动处理；selection 模板需先选中替换位置",
                "说明: " + (t.getNotes() == null || t.getNotes().isEmpty() ? "-" : t.getNotes()));
    }

    private JPanel addToolRow(JPanel panel, String label, JComponent... items) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = panel.getComponentCount() / 2;
        left.anchor = GridBagConstraints.WEST;
        left.insets = new Insets(2, 0, 2, 8);

        JLabel rowLabel = new JLabel(resolveRowLabel(label) + ":");
        rowLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        panel.add(rowLabel, left);

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JComponent item : items)
            row.add(item);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = left.gridy;
        right.weightx = 1.0;
        right.fill = GridBagConstraints.HORIZONTAL;
        right.anchor = GridBagConstraints.WEST;
        right.insets = new Insets(2, 0, 2, 0);
        panel.add(row, right);
        return row;
    }

    private static final int TEMPLATE_COLS = 4;

    private JPanel addTemplateWrapRow(JPanel panel, String label, JComponent... items) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = panel.getComponentCount() / 2;
        left.anchor = GridBagConstraints.NORTHWEST;
        left.insets = new Insets(4, 0, 2, 8);

        JLabel rowLabel = new JLabel(resolveRowLabel(label) + ":");
        rowLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        panel.add(rowLabel, left);

        int rows = Math.max(1, (items.length + TEMPLATE_COLS - 1) / TEMPLATE_COLS);
        JPanel row = new JPanel(new GridLayout(rows, TEMPLATE_COLS, 4, 3));
        for (JComponent item : items)
            row.add(item);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = left.gridy;
        right.weightx = 1.0;
        right.fill = GridBagConstraints.HORIZONTAL;
        right.anchor = GridBagConstraints.WEST;
        right.insets = new Insets(2, 0, 2, 0);
        panel.add(row, right);
        return row;
    }

    private JButton toolButton(String text, Runnable action) {
        return toolButton(text, defaultTooltip(text), action);
    }

    /**
     * 把传入的稳定按钮文本 key 转换为当前语言下的显示文本。
     * 转换规则：尝试 I18n 查 "btn.{slug}"，失败则原样返回。
     * 调用方传入的是稳定文本 key（如 "Minimal" / "URL Encode" / "Unicode 转义"），
     * tooltip 查询、case 匹配都可以继续按原始 key 运作。
     */
    private static String resolveBtnText(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "btn." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    private static String resolveRowLabel(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "row." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    private static String resolveSectionTitle(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "sec." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    /** 用于生成 i18n key 的简单 slug，统一委托给 {@link I18n#slug(String)}。 */
    private static String slugifyForI18n(String s) {
        return I18n.slug(s);
    }

    private JButton toolButton(String text, String tooltip, Runnable action) {
        // text 作为稳定 key，UI 显示用当前语言版本
        String displayText = resolveBtnText(text);
        // 若 i18n 中为该按钮注册了 tooltip，则优先用 i18n（确保英文模式下也是英文）
        String i18nTooltip = i18nTooltipFor(text);
        if (i18nTooltip != null) {
            tooltip = i18nTooltip;
        }
        JButton btn = new JButton(displayText) {
            @Override
            public JToolTip createToolTip() {
                JToolTip tip = new MultiLineToolTip();
                tip.setComponent(this);
                return tip;
            }
        };
        btn.setMargin(new Insets(0, 7, 0, 7));
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        btn.setFocusPainted(false);
        if (tooltip != null && !tooltip.isEmpty()) {
            btn.setToolTipText(tooltip);
        }
        Dimension pref = btn.getPreferredSize();
        btn.setPreferredSize(new Dimension(pref.width, 24));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        btn.addActionListener(e -> {
            runRequestMutation(action);
        });
        return btn;
    }

    private String tooltip(String title, String... lines) {
        StringBuilder sb = new StringBuilder(title);
        for (String line : lines) {
            sb.append('\n').append(line);
        }
        return sb.toString();
    }

    /**
     * 根据按钮文本（稳定 key，如 "Minimal" / "URL Encode" / "Unicode 转义"）从 I18n 拼接 tooltip。
     * 约定 I18n 中存在 "tooltip.{slug}.title" 和 "tooltip.{slug}.desc" 两条 key。
     * desc 中可包含 \n 用于多行展示。
     * 任意一条找不到则返回 null，由调用方走旧的 case-switch 兜底。
     */
    private String i18nTooltipFor(String key) {
        String slug = slugifyForI18n(key);
        if (slug.isEmpty()) {
            return null;
        }
        String titleKey = "tooltip." + slug + ".title";
        String descKey = "tooltip." + slug + ".desc";
        String title = I18n.t(titleKey);
        String desc = I18n.t(descKey);
        if (title.equals(titleKey) && desc.equals(descKey)) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(title.equals(titleKey) ? key : title);
        if (!desc.equals(descKey)) {
            for (String line : desc.split("\n")) {
                sb.append('\n').append(line);
            }
        }
        return sb.toString();
    }

    private String noiseTargetTooltip(String target) {
        // 复用 i18n：tooltip.noise.{key}.title / .desc1 / .desc2
        // 切语言只需在 I18nKeys 里维护对应 key，这里不必再写两套字符串
        String slug;
        switch (target) {
            case "SELECTION":
                slug = "selection";
                break;
            case "SUFFIX":
                slug = "suffix";
                break;
            case "SEG_PREFIX":
                slug = "seg_prefix";
                break;
            case "SEG_SUFFIX":
                slug = "seg_suffix";
                break;
            case "INTERLEAVE":
                slug = "interleave";
                break;
            case "REPLACE_SPACE":
                slug = "replace_space";
                break;
            default:
                return null;
        }
        return tooltip(
                I18n.t("tooltip.noise." + slug + ".title"),
                I18n.t("tooltip.noise." + slug + ".desc1"),
                I18n.t("tooltip.noise." + slug + ".desc2"));
    }

    private String atomTooltip(String atom) {
        switch (atom) {
            case "%00":
                return tooltip("Noise Atom: %00",
                        "URL 编码的 NUL 字节",
                        "常用于截断、解析差异、后缀绕过测试",
                        "位置由上方“Noise 作用方式”决定");
            case "%09":
                return tooltip("Noise Atom: %09",
                        "URL 编码的 Tab 制表符",
                        "常用于空白字符混淆、关键字分隔、路径解析差异",
                        "位置由上方“Noise 作用方式”决定");
            case "%0a":
                return tooltip("Noise Atom: %0a",
                        "URL 编码的 LF 换行",
                        "常用于 CRLF、Header 注入、协议边界测试",
                        "位置由上方“Noise 作用方式”决定");
            case "%0d":
                return tooltip("Noise Atom: %0d",
                        "URL 编码的 CR 回车",
                        "通常和 %0a 组合测试 CRLF 注入",
                        "位置由上方“Noise 作用方式”决定");
            case "%20":
                return tooltip("Noise Atom: %20",
                        "URL 编码的空格",
                        "常用于关键字分隔、路径空白混淆、参数边界测试",
                        "位置由上方“Noise 作用方式”决定");
            case "%0b":
                return tooltip("Noise Atom: %0b",
                        "URL 编码的 vertical tab",
                        "部分解析器会当空白处理，部分规则不会",
                        "用于空白字符识别差异测试");
            case "%0c":
                return tooltip("Noise Atom: %0c",
                        "URL 编码的 form feed",
                        "部分解析器会当空白处理，部分规则不会",
                        "用于空白字符识别差异测试");
            case "%a0":
                return tooltip("Noise Atom: %a0",
                        "URL 编码的 NBSP 类空白字节",
                        "看起来像空格，但和普通 %20 不同",
                        "用于空白归一化差异测试");
            case "%2b":
                return tooltip("Noise Atom: %2b",
                        "URL 编码的加号 +",
                        "在 form-urlencoded 中可能被解释为空格",
                        "用于 + / space 解码差异测试");
            case "/**/":
                return tooltip("Noise Atom: /**/",
                        "注释型分隔符",
                        "常用于 SQL 关键字分割、规则匹配绕过",
                        "位置由上方“Noise 作用方式”决定");
            default:
                return tooltip("Noise Atom: " + atom,
                        "通用噪音原子",
                        "位置由上方“Noise 作用方式”决定");
        }
    }

    private String defaultTooltip(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        // 优先从 I18n 取双语 tooltip。注册了 "tooltip.{slug}.title" / ".desc" 的按钮走这条路径。
        String i18nTooltip = i18nTooltipFor(text);
        if (i18nTooltip != null) {
            return i18nTooltip;
        }
        switch (text) {
            case "Dirty(N)":
                return tooltip("Dirty(N)",
                        "插入 {{dirty(N)}} 占位符",
                        "发送前展开为 N 个随机脏字符",
                        "用于填充噪音、拉开特征、测试解析容忍度");
            case "Null(N)":
                return tooltip("Null(N)",
                        "插入 {{dirtynull(N)}} 占位符",
                        "发送前展开为 N 个随机空字节/噪音字节",
                        "用于测试截断、二进制噪音和解析差异");
            case "XFF 127.0.0.1":
                return tooltip("X-Forwarded-For: 127.0.0.1",
                        "添加或覆盖 X-Forwarded-For",
                        "用于代理链 IP 信任、访问控制绕过测试");
            case "X-Real-IP":
                return tooltip("X-Real-IP: 127.0.0.1",
                        "添加或覆盖 X-Real-IP",
                        "Nginx/反代场景常见，用于真实客户端 IP 信任测试");
            case "X-Client-IP":
                return tooltip("X-Client-IP: 127.0.0.1",
                        "添加或覆盖 X-Client-IP",
                        "用于客户端 IP 伪造测试");
            case "X-Remote-Addr":
                return tooltip("X-Remote-Addr: 127.0.0.1",
                        "添加或覆盖 X-Remote-Addr",
                        "用于来源地址信任逻辑测试");
            case "CF-Connecting-IP":
                return tooltip("CF-Connecting-IP: 127.0.0.1",
                        "添加或覆盖 CF-Connecting-IP",
                        "Cloudflare 场景常见，用于边缘代理 IP 信任测试");
            case "Forwarded":
                return tooltip("Forwarded: for=127.0.0.1;proto=http;host=127.0.0.1",
                        "添加或覆盖标准 Forwarded 头",
                        "用于 RFC 7239 代理链解析和来源信任测试");
            case "X-Custom-IP":
                return tooltip("X-Custom-IP-Authorization: 127.0.0.1",
                        "添加或覆盖 X-Custom-IP-Authorization",
                        "用于部分框架/中间件的 IP 信任绕过测试");
            case "Referer local":
                return tooltip("Referer: http://127.0.0.1",
                        "把 Referer 设置为本地地址",
                        "用于来源校验、CSRF Referer 检查绕过测试");
            case "X-Host local":
                return tooltip("X-Host: 127.0.0.1",
                        "添加或覆盖 X-Host",
                        "用于 Host 派生信任逻辑测试");
            case "XF Host local":
                return tooltip("X-Forwarded-Host: 127.0.0.1",
                        "添加或覆盖 X-Forwarded-Host",
                        "用于反代 Host 信任、后端路由和 URL 生成差异测试");
            case "X-Original-URL":
                return tooltip("X-Original-URL: /",
                        "添加或覆盖 X-Original-URL",
                        "用于 IIS/反代/重写链路中的原始 URL 解析差异测试");
            case "HTTP/1.0":
                return tooltip("HTTP/1.0",
                        "把请求行协议版本改为 HTTP/1.0",
                        "用于代理、连接复用、Host/TE 处理差异测试");
            case "form":
                return tooltip("Content-Type: application/x-www-form-urlencoded",
                        "只修改请求 Content-Type",
                        "不改 body，用于 WAF 和后端对 body 类型理解不一致的测试");
            case "text":
                return tooltip("Content-Type: text/plain",
                        "只修改请求 Content-Type",
                        "不改 body，用于让 WAF 按纯文本处理 body 的测试");
            case "json":
                return tooltip("Content-Type: application/json",
                        "只修改请求 Content-Type",
                        "不改 body，用于 JSON parser / WAF 类型识别差异测试");
            case "xml":
                return tooltip("Content-Type: application/xml",
                        "只修改请求 Content-Type",
                        "不改 body，用于 XML parser / WAF 类型识别差异测试");
            case "To Form":
                return tooltip("To Form",
                        "把当前 body 的普通参数转换成 x-www-form-urlencoded",
                        "支持 form、multipart 文本字段、简单 JSON 对象",
                        "会重写 body、Content-Type 和 Content-Length");
            case "To Multipart":
                return tooltip("To Multipart",
                        "把当前 body 的普通参数转换成 multipart/form-data",
                        "支持 form、multipart 文本字段、简单 JSON 对象",
                        "跳过文件字段，会重写 body、boundary 和 Content-Length");
            case "To JSON":
                return tooltip("To JSON",
                        "把当前 body 的普通参数转换成 JSON 对象",
                        "支持 form、multipart 文本字段、简单 JSON 对象",
                        "会重写 body、Content-Type 和 Content-Length");
            case "Gzip body":
                return tooltip("Gzip body",
                        "压缩请求 body 并设置 Content-Encoding: gzip",
                        "用于 WAF 不解压、后端解压的差异测试");
            case "URL Encode":
                return tooltip("URL Encode",
                        "对选中文本做常规 URL 编码",
                        "空格会变成 +",
                        "字母数字属于安全字符，可能保持原样",
                        "若无变化，会询问是否强制编码安全字符",
                        "适合参数值；路径建议用 Path Encode");
            case "Path Encode":
                return tooltip("Path Encode",
                        "对选中文本做路径编码",
                        "保留 / 和常见安全字符，空格变 %20",
                        "适合 request path 或 path 片段");
            case "Double URL":
                return tooltip("Double URL Encode",
                        "对选中文本做双重 URL 编码",
                        "若无变化，会询问是否强制编码安全字符",
                        "用于二次解码链路、WAF/后端解码次数差异测试");
            case "Mixed Encode":
                return tooltip("Mixed Encode",
                        "对选区里的字母数字交错做百分号编码",
                        "保留 / ? = & 等结构字符",
                        "例如 select -> s%65l%65c%74");
            case "Unicode 转义":
                return tooltip("Unicode 转义",
                        "把选中文本转成 \\uXXXX 字符串转义",
                        "这不是 URL 编码，不会生成 %XX",
                        "用于 JSON/JavaScript/Java 字符串解析差异测试");
            case "Base64 Encode":
                return tooltip("Base64 Encode",
                        "对选中文本做 Base64 编码",
                        "用于编码型参数或传输层混淆");
            case "UTF-16":
            case "UTF-16BE":
            case "UTF-16LE":
            case "UTF-32":
            case "UTF-32BE":
            case "UTF-32LE":
            case "IBM037":
            case "cp290":
                return tooltip(text,
                        "把请求 body 按 " + text + " 重新编码",
                        "同时更新 Content-Type charset 和 Content-Length",
                        "用于 WAF 不识别该字符集、后端能解析的场景");
            case "charset first":
                return tooltip("charset first",
                        "重排 Content-Type 参数，把 charset 放在最前",
                        "例如 multipart/form-data; charset=IBM037; boundary=xxx",
                        "只改 header，不重编码 body");
            case "charset last":
                return tooltip("charset last",
                        "重排 Content-Type 参数，把 charset 放在最后",
                        "例如 multipart/form-data; boundary=xxx; charset=IBM037",
                        "只改 header，不重编码 body");
            case "Fullwidth":
                return tooltip("Fullwidth",
                        "把选区里的 ASCII 可见字符转成全角字符",
                        "例如 admin?id=1 -> ａｄｍｉｎ？ｉｄ＝１",
                        "用于 WAF 未归一化全角字符的场景");
            case "Homoglyph":
                return tooltip("Homoglyph",
                        "把选区里的部分拉丁字母换成视觉相似的 Unicode 字符",
                        "例如 admin -> аdmіn",
                        "用于规则按 ASCII 匹配、展示上仍相似的场景");
            case "Zero Width":
                return tooltip("Zero Width",
                        "在选区每两个字符之间插入 U+200B 零宽空格",
                        "例如 admin -> a\u200Bd\u200Bm\u200Bi\u200Bn",
                        "用于关键词匹配和展示解析差异测试");
            case "Upper":
                return tooltip("Upper",
                        "把选区转成大写",
                        "用于大小写敏感规则差异测试");
            case "Lower":
                return tooltip("Lower",
                        "把选区转成小写",
                        "用于大小写敏感规则差异测试");
            case "Random":
                return tooltip("Random Case",
                        "随机改变选区中字母大小写",
                        "用于关键字大小写混淆");
            case "Minimal":
                return tooltip("Minimal — 只编码协议分隔符",
                        "目标字符: . / \\ % @ : ; ? & = ' \" < > CR LF",
                        "字母和数字保持原样，最小变形，先试这个",
                        "操作: 先选中原始 ASCII/UTF-8 payload");
            case "Full":
                return tooltip("Full — 编码全部 ASCII",
                        "选区内所有 ASCII 字符都转成 Ghost Unicode",
                        "Ghost 还原后仍等于原文，隐蔽性最强但更容易破坏解析链",
                        "操作: 先选中原始 ASCII/UTF-8 payload");
            case "Letters":
                return tooltip("Letters — 只编码字母",
                        "只 Ghost 化 a-z A-Z，数字和符号保持原样",
                        "适合绕关键字检测: class / select / union / Runtime",
                        "操作: 先选中原始 ASCII/UTF-8 payload");
            case "Digits":
                return tooltip("Digits — 只编码数字",
                        "只 Ghost 化 0-9，字母和符号保持原样",
                        "适合版本号、参数值、\\uXXXX 数字段测试",
                        "操作: 先选中原始 ASCII/UTF-8 payload");
            case "Symbols":
                return tooltip("Symbols — 只编码符号",
                        "只 Ghost 化非字母非数字的 ASCII 符号",
                        "包含空格、引号、斜杠、百分号、CR/LF 等",
                        "操作: 先选中原始 ASCII/UTF-8 payload");
            case "Shuffle":
                return tooltip("Shuffle — 换一组 Ghost 字符",
                        "先按低位还原结果重新随机选 Ghost Unicode",
                        "同一 payload 换不同变体，多试几次碰运气",
                        "操作: 先选中已 Ghost 化或待 Ghost 化文本");
            case "Preview":
                return tooltip("Preview — 查看 Ghost 还原结果",
                        "逐字符展示: U+XXXX -> low byte -> ASCII",
                        "操作: 先选中 Ghost 化后的文本");
            case "Candidates":
                return tooltip("Candidates — 查看候选字符",
                        "选中一个 ASCII 字符，列出所有可用的 Ghost Unicode 替代品",
                        "批量变形请用上方 Ghost Encode 行按钮");
            case "8-bit":
                return tooltip("8-bit — ch & 0xFF (默认)",
                        "大多数场景: (byte)ch / baos.write(ch) / writeBytes",
                        "Ghost 还原时取 char 的低 8 位");
            case "7-bit":
                return tooltip("7-bit — ch & 0x7F (Tomcat)",
                        "少数场景: Tomcat RFC2231 filename* 的 hex 解析",
                        "Ghost 还原时取 char 的低 7 位");
            case ".%u002e":
                return tooltip(".%u002e",
                        "替换选区为 阮严灵丰丰甲来",
                        "低 8 位还原后为 .%u002e，后续解码可变成 ..",
                        "放在 request path 时推荐 Raw Socket 发送",
                        "操作: 先选中要替换的位置");
            case "CRLF":
                return tooltip("CRLF",
                        "替换选区为 瘍瘊",
                        "低 8 位还原后为 \\r\\n",
                        "用于 Header/SMTP/文本协议边界测试",
                        "放在 header value 时推荐 Raw Socket 发送",
                        "操作: 先选中 header value 或协议字段中的替换位置");
            case ".jsp":
                return tooltip(".jsp",
                        "替换选区为 .陪sp",
                        "陪 的低 8 位是 j，8-bit 还原后为 .jsp",
                        "这是裸字符 Ghost，和 Tomcat %HH 的 URL hex Ghost 不同",
                        "操作: 先选中原扩展名或 filename 中要替换的位置");
            case "@type":
                return tooltip("@type",
                        "把 @type 转成低位等价 Unicode",
                        "用于 fastjson/Jackson key 相关绕过构造",
                        "操作: 先选中 JSON key 或待替换位置");
            case "%2>":
                return tooltip("%2>",
                        "Jetty 非严格 hex 解析案例",
                        "> 经 convertHexDigit 计算可变成 E，%2> 等价 %2E",
                        "这是 parser differential，不是标准 char & 0xFF",
                        "操作: 选中 .、%2e，或包含这些 token 的路径片段");
            case "class":
                return tooltip("class",
                        "把 class 转成低位等价 Unicode",
                        "用于 Spring/Java Bean path 关键字绕过构造",
                        "操作: 先选中 class 或待替换位置");
            case "Spring Path":
                return tooltip("Spring Path",
                        "替换 request path 为 Spring/Jetty 风格探测路径",
                        "包含 阮严灵丰丰甲来 -> .%u002e 与 %64 URL trigger",
                        "推荐发送: Raw Socket");
            case "Tomcat filename*":
                return tooltip("Tomcat filename*",
                        "尝试替换 multipart filename/filename* 为 1.陪sp",
                        "低位还原后可能变成 1.jsp",
                        "SpringBoot ContentDisposition 有额外校验，不保证通用");
            case "fastjson \\x4_":
                return tooltip("fastjson \\x4_",
                        "替换选区为 \\x4Jtype",
                        "fastjson 宽松 \\x 表中非 hex 字符可按 0 参与计算",
                        "\\x4J 可解析为 @",
                        "操作: 先选中 @type 或 JSON key 内容");
            case "fastjson \\u":
                return tooltip("fastjson \\u",
                        "把选区转成 \\uXXXX，并把数字位替换为 Unicode 数字",
                        "例如 @type -> \\u٠٠٤٠\\u٠٠٧٤...",
                        "这是 Unicode digit 绕过，不是标准 low-byte fold",
                        "操作: 先选中 @type 或 JSON key 内容");
            case "jackson \\u":
                return tooltip("jackson \\u",
                        "把选区转成 \\uXXXX，并把 4 个 hex 位换成 Ghost 字符",
                        "低位还原后仍是标准 \\uXXXX，给 Jackson charToHex(ch & 0xFF) 场景用",
                        "只适合 ReaderBasedJsonParser / char[] 输入链",
                        "SpringBoot 默认 UTF8StreamJsonParser 通常不触发",
                        "操作: 先选中要转成 \\u Ghost escape 的 ASCII 文本");
            case "Tomcat %HH":
                return tooltip("Tomcat %HH",
                        "把选区每个字符改成 %HH，但 H 用 7-bit Ghost 字符表示",
                        "还原模式等价 ch & 0x7F，适合 Tomcat RFC2231 filename* hex 解析",
                        "例如选中 j 可生成 %鸶繡 这类变体，后端可能解析为 j",
                        "操作: 先选中 filename* 中要隐藏的原始字符，不要选 6a");
            case "Header CRLF":
                return tooltip("Header CRLF",
                        "替换选区为 瘍瘊",
                        "低位还原后为 \\r\\n，可用于 header value 断行测试",
                        "推荐发送: Raw Socket",
                        "操作: 先选中 header value 中要替换的位置");
            default:
                return tooltip(text,
                        "点击后对当前请求执行该变换",
                        "有选区的功能通常优先处理选区，没选区则按该按钮的默认范围处理");
        }
    }

    private static class MultiLineToolTip extends JToolTip {
        private static final int PAD_X = 8;
        private static final int PAD_Y = 5;
        private static final int GAP = 2;

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            String[] lines = getLines();
            int width = 0;
            for (String line : lines) {
                width = Math.max(width, fm.stringWidth(line));
            }
            int height = lines.length * fm.getHeight() + Math.max(0, lines.length - 1) * GAP;
            Insets insets = getInsets();
            return new Dimension(width + PAD_X * 2 + insets.left + insets.right,
                    height + PAD_Y * 2 + insets.top + insets.bottom);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setColor(getBackground());
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.setFont(getFont());
                g2.setColor(getForeground());
                FontMetrics fm = g2.getFontMetrics();
                Insets insets = getInsets();
                int x = insets.left + PAD_X;
                int y = insets.top + PAD_Y + fm.getAscent();
                for (String line : getLines()) {
                    g2.drawString(line, x, y);
                    y += fm.getHeight() + GAP;
                }
            } finally {
                g2.dispose();
            }
        }

        private String[] getLines() {
            String text = getTipText();
            if (text == null || text.isEmpty()) {
                return new String[] { "" };
            }
            return text.split("\\R", -1);
        }
    }

    private JLabel createInspectorLine(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private void startRequestInspectorTimer() {
        inspectorTimer = new Timer(400, e -> refreshRequestInspector());
        inspectorTimer.setInitialDelay(200);
        inspectorTimer.start();
    }

    private void refreshRequestInspector() {
        if (inspectorRequestLineLabel == null || requestViewer == null)
            return;
        byte[] req = getRequestBytes();
        byte[] sel = getSelectedRequestBytes();
        byte[] safeReq = req == null ? new byte[0] : req;
        byte[] safeSel = sel == null ? new byte[0] : sel;
        boolean sameReq = Arrays.equals(safeReq, lastInspectorBytes);
        boolean sameSelection = Arrays.equals(safeSel, lastInspectorSelectionBytes);
        if (sameReq && sameSelection)
            return;

        if (!sameReq) {
            lastInspectorBytes = Arrays.copyOf(safeReq, safeReq.length);
            updateRequestInspector(lastInspectorBytes);
        }
        if (!sameSelection) {
            lastInspectorSelectionBytes = Arrays.copyOf(safeSel, safeSel.length);
            updateGhostCompactPreview(lastInspectorSelectionBytes);
        }
    }

    private void updateRequestInspector(byte[] req) {
        if (req == null || req.length == 0) {
            inspectorRequestLineLabel.setText("Request: -");
            inspectorMetaLabel.setText("Meta: -");
            inspectorFlagsLabel.setText("Flags: -");
            inspectorHintsLabel.setText("Payload hints: -");
            inspectorDiffLabel.setText("Diff: -");
            return;
        }

        String requestLine = firstLine(req);
        inspectorRequestLineLabel.setText("Request: " + truncateForInspector(requestLine, 110));

        int headerEnd = findHeaderEnd(req);
        int bodyLen = headerEnd > 0 ? Math.max(0, req.length - headerEnd) : 0;
        String contentType = headerValueFromRequest(req, "Content-Type");
        String cl = headerValueFromRequest(req, "Content-Length");
        inspectorMetaLabel.setText("Meta: " + req.length + " bytes"
                + " | body " + bodyLen
                + (cl == null ? "" : " | CL " + cl)
                + (contentType == null ? "" : " | " + truncateForInspector(contentType, 48)));

        List<String> flags = new ArrayList<>();
        if (shouldUseRawSocket(req))
            flags.add("Raw recommended");
        if (containsNonAsciiBeforeBody(req))
            flags.add("non-ASCII line/header");
        if (contentType != null && contentType.toLowerCase().contains("multipart"))
            flags.add("multipart");
        if (new String(req, StandardCharsets.ISO_8859_1).toLowerCase().contains("filename"))
            flags.add("filename");
        if (isContentLengthTampered(req))
            flags.add("CL tampered");
        inspectorFlagsLabel.setText("Flags: " + (flags.isEmpty() ? "-" : String.join(", ", flags)));

        String text = new String(req, StandardCharsets.UTF_8);
        String hints = buildParserIntent(text);
        inspectorHintsLabel
                .setText("Payload hints: " + ("自定义 payload".equals(hints) ? "-" : truncateForInspector(hints, 110)));

        inspectorDiffLabel.setText("Diff: " + buildRequestDiffSummary(req));
    }

    private String foldModeTag() {
        return "[" + GhostBitsCodec.foldModeLabel(ghostFoldMode) + "]";
    }

    private void updateGhostCompactPreview(byte[] selectedBytes) {
        if (ghostSelectionFoldLabel == null) {
            return;
        }
        if (selectedBytes == null || selectedBytes.length == 0) {
            ghostSelectionFoldLabel.setText(I18n.t("ghost.selection_fold") + " " + foldModeTag()
                    + ": " + I18n.t("ghost.risk.select"));
            ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": -");
            ghostPreviewRiskLabel.setForeground(UIManager.getColor("Label.foreground"));
            return;
        }

        String selected = new String(selectedBytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(selected.getBytes(StandardCharsets.UTF_8), selectedBytes)) {
            ghostSelectionFoldLabel
                    .setText(I18n.t("ghost.selection_fold") + ": non UTF-8 bytes (" + selectedBytes.length + ")");
            ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": " + I18n.t("ghost.risk.unsupported"));
            ghostPreviewRiskLabel.setForeground(new Color(170, 70, 20));
            return;
        }

        String folded = GhostBitsCodec.fold(selected, ghostFoldMode);
        updateGhostSelectionFoldPreview(selected, folded, false);
    }

    private void updateGhostSelectionFoldPreview(String selected, String folded, boolean rawRecommended) {
        if (ghostSelectionFoldLabel == null || ghostPreviewRiskLabel == null) {
            return;
        }
        String safeSelected = selected == null ? "" : selected;
        String safeFolded = folded == null ? "" : folded;
        String decoded = decodeUrlForPreview(safeFolded);
        String risk = ghostFoldRisk(safeSelected, safeFolded, decoded);
        if (rawRecommended) {
            risk = "-".equals(risk) ? "Raw Socket recommended" : risk + " | Raw Socket recommended";
        }

        ghostSelectionFoldLabel.setText(I18n.t("ghost.selection_fold") + " " + foldModeTag() + ": "
                + truncateForInspector(escape(safeSelected), 42)
                + " -> " + truncateForInspector(escape(safeFolded), 42)
                + " -> URL: " + truncateForInspector(escape(decoded), 42));
        ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": " + risk);
        ghostPreviewRiskLabel.setForeground("-".equals(risk)
                ? UIManager.getColor("Label.foreground")
                : new Color(190, 70, 30));
    }

    private String decodeUrlForPreview(String folded) {
        if (folded == null || folded.isEmpty()) {
            return "";
        }
        try {
            return URLDecoder.decode(folded, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return folded;
        }
    }

    private String ghostFoldRisk(String selected, String folded, String decoded) {
        if (selected == null || selected.isEmpty()) {
            return "-";
        }
        List<String> risks = new ArrayList<>();
        for (int i = 0; i < selected.length(); i++) {
            char original = selected.charAt(i);
            char low = i < folded.length() ? folded.charAt(i) : 0;
            if (original == low) {
                continue;
            }
            switch (low) {
                case '.':
                    risks.add(". path");
                    break;
                case '/':
                case '\\':
                    risks.add("separator");
                    break;
                case '%':
                    risks.add("% decode");
                    break;
                case '\r':
                case '\n':
                    risks.add("CRLF");
                    break;
                case '@':
                    risks.add("@ key");
                    break;
                case '<':
                case '>':
                case '\'':
                case '"':
                    risks.add("syntax");
                    break;
                case ':':
                case ';':
                    risks.add("delimiter");
                    break;
                default:
                    break;
            }
        }
        if (decoded != null && !decoded.equals(folded)) {
            if (decoded.contains(".."))
                risks.add("URL -> ..");
            if (decoded.indexOf('\r') >= 0 || decoded.indexOf('\n') >= 0)
                risks.add("URL -> CRLF");
        }
        if (risks.isEmpty()) {
            return "-";
        }
        return truncateForInspector(String.join(", ", uniqueStrings(risks)), 54);
    }

    private List<String> uniqueStrings(List<String> values) {
        List<String> unique = new ArrayList<>();
        for (String value : values) {
            if (!unique.contains(value)) {
                unique.add(value);
            }
        }
        return unique;
    }

    private String firstLine(byte[] req) {
        int end = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                end = i;
                break;
            }
        }
        if (end < 0)
            end = Math.min(req.length, 160);
        if (end > 0 && req[end - 1] == '\r')
            end--;
        return new String(req, 0, end, StandardCharsets.UTF_8);
    }

    private String headerValueFromRequest(byte[] req, String name) {
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        String headers = new String(req, 0, upper, StandardCharsets.ISO_8859_1);
        String[] lines = headers.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0)
                continue;
            if (line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private boolean containsNonAsciiBeforeBody(byte[] req) {
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        for (int i = 0; i < upper; i++) {
            if ((req[i] & 0xFF) > 0x7F)
                return true;
        }
        return false;
    }

    private String buildRequestDiffSummary(byte[] req) {
        if (originalRequest == null || originalRequest.length == 0)
            return "original unavailable";
        if (Arrays.equals(originalRequest, req))
            return "unchanged";

        List<String> parts = new ArrayList<>();
        String oldLine = firstLine(originalRequest);
        String newLine = firstLine(req);
        if (!oldLine.equals(newLine))
            parts.add("request line changed");

        int oldBody = bodyLength(originalRequest);
        int newBody = bodyLength(req);
        if (oldBody != newBody)
            parts.add("body " + oldBody + " -> " + newBody);

        if (parts.isEmpty())
            parts.add("headers changed");
        return String.join(", ", parts);
    }

    private int bodyLength(byte[] req) {
        int headerEnd = findHeaderEnd(req);
        return headerEnd > 0 ? Math.max(0, req.length - headerEnd) : 0;
    }

    private String truncateForInspector(String value, int max) {
        if (value == null)
            return "-";
        if (value.length() <= max)
            return value;
        return value.substring(0, Math.max(0, max - 3)) + "...";
    }

    private String buildParserIntent(String payload) {
        if (payload == null || payload.isEmpty()) {
            return "空 payload";
        }
        List<String> hints = new ArrayList<>();
        if (payload.contains("阮严灵丰丰甲来"))
            hints.add("阮严灵丰丰甲来 => .%u002e");
        if (payload.contains("陪sp"))
            hints.add("陪sp => jsp");
        if (payload.contains("瘍瘊"))
            hints.add("瘍瘊 => \\r\\n");
        if (payload.contains("%2>"))
            hints.add("%2> => %2E => .");
        if (payload.contains("%6>"))
            hints.add("%6> => %6E => n");
        if (payload.contains("%64"))
            hints.add("%64 => d");
        if (hints.isEmpty()) {
            String folded = GhostBitsEngine.foldToAscii(payload);
            if (!folded.equals(payload)) {
                hints.add("low-byte => " + escape(folded));
            }
        }
        return hints.isEmpty() ? "自定义 payload" : String.join("；", hints);
    }

    private JPanel createHistoryPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("History"));

        historyModel = new HistoryTableModel();
        historyTable = new JTable(historyModel);
        historyTable.setAutoCreateRowSorter(true);

        // 单击：显示响应
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = historyTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = historyTable.convertRowIndexToModel(row);
                    showHistoryEntry(modelRow);
                }
            }
        });

        // 双击：加载请求到编辑器
        historyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (evt.getClickCount() == 2) {
                    int row = historyTable.rowAtPoint(evt.getPoint());
                    if (row >= 0) {
                        int modelRow = historyTable.convertRowIndexToModel(row);
                        loadHistoryRequest(modelRow);
                    }
                }
            }

            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                showHistoryPopup(evt);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                showHistoryPopup(evt);
            }
        });

        panel.add(new JScrollPane(historyTable), BorderLayout.CENTER);
        return panel;
    }

    private void showHistoryPopup(java.awt.event.MouseEvent evt) {
        if (!evt.isPopupTrigger())
            return;
        int row = historyTable.rowAtPoint(evt.getPoint());
        if (row < 0)
            return;
        historyTable.setRowSelectionInterval(row, row);
        int modelRow = historyTable.convertRowIndexToModel(row);

        JPopupMenu popup = new JPopupMenu();
        JMenuItem loadItem = new JMenuItem("加载请求到编辑器");
        loadItem.addActionListener(e -> loadHistoryRequest(modelRow));
        popup.add(loadItem);

        JMenuItem deleteItem = new JMenuItem("删除此记录");
        deleteItem.addActionListener(e -> {
            if (modelRow >= 0 && modelRow < historyEntries.size()) {
                historyEntries.remove(modelRow);
                historyModel.fireTableDataChanged();
            }
        });
        popup.add(deleteItem);

        popup.show(evt.getComponent(), evt.getX(), evt.getY());
    }

    private void loadHistoryRequest(int index) {
        if (index < 0 || index >= historyEntries.size())
            return;
        HistoryEntry entry = historyEntries.get(index);
        if (entry.requestBytes != null && entry.requestBytes.length > 0) {
            runRequestMutation(() -> setRequestBytes(entry.requestBytes));
            if (statusLabel != null) {
                statusLabel.setText(I18n.t("status.history_loaded", entry.id));
            }
        }
    }

    private void replaceInSelectionOrPath(java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            transformSelection(transformer);
            return;
        }
        String path = getRequestPath();
        if (path != null && transformer.apply(path).equals(path)) {
            JOptionPane.showMessageDialog(this, "当前 path 没有可变换的内容，请先选中目标片段",
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        mutateRequestPath(transformer);
    }

    private void appendPathSuffix(String suffix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> s + suffix);
            return;
        }
        mutateRequestPath(path -> {
            if ("?".equals(suffix)) {
                return path.contains("?") ? path + "&" : path + "?";
            }
            int q = path.indexOf('?');
            if (q >= 0) {
                return path.substring(0, q) + suffix + path.substring(q);
            }
            return path + suffix;
        });
    }

    private void prefixEachPathSegment(String prefix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> prefix + s);
            return;
        }
        mutateRequestPath(path -> mutatePathOnly(path, segment -> segment.isEmpty() ? segment : prefix + segment));
    }

    private void appendEachPathSegment(String suffix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> s + suffix);
            return;
        }
        mutateRequestPath(path -> mutatePathOnly(path, segment -> segment.isEmpty() ? segment : segment + suffix));
    }

    private boolean hasSelectedRequestBytes() {
        byte[] sel = getSelectedRequestBytes();
        return sel != null && sel.length > 0;
    }

    private String mutatePathOnly(String path, java.util.function.Function<String, String> segmentMutator) {
        int q = path.indexOf('?');
        String pathOnly = q >= 0 ? path.substring(0, q) : path;
        String query = q >= 0 ? path.substring(q) : "";
        String[] parts = pathOnly.split("/", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0)
                out.append('/');
            out.append(segmentMutator.apply(parts[i]));
        }
        return out + query;
    }

    private void mutateRequestPath(java.util.function.Function<String, String> transformer) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int lineEnd = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            JOptionPane.showMessageDialog(this, "未识别请求行", I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int realLineEnd = lineEnd;
        if (realLineEnd > 0 && req[realLineEnd - 1] == '\r')
            realLineEnd--;

        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < realLineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            JOptionPane.showMessageDialog(this, "请求行格式不规范，无法定位 path", "提示",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int pathStart = firstSpace + 1;
        int pathEnd = secondSpace;
        String path = new String(req, pathStart, pathEnd - pathStart, StandardCharsets.ISO_8859_1);
        String mutated = transformer.apply(path);
        byte[] replacement = mutated.getBytes(StandardCharsets.ISO_8859_1);

        byte[] out = new byte[req.length - (pathEnd - pathStart) + replacement.length];
        System.arraycopy(req, 0, out, 0, pathStart);
        System.arraycopy(replacement, 0, out, pathStart, replacement.length);
        System.arraycopy(req, pathEnd, out, pathStart + replacement.length, req.length - pathEnd);
        setRequestBytes(out);
    }

    private String getRequestPath() {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            return null;
        }

        int lineEnd = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            return null;
        }
        int realLineEnd = lineEnd;
        if (realLineEnd > 0 && req[realLineEnd - 1] == '\r')
            realLineEnd--;

        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < realLineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            return null;
        }
        return new String(req, firstSpace + 1, secondSpace - firstSpace - 1, StandardCharsets.ISO_8859_1);
    }

    private void upsertRequestHeader(String name, String value) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        updateOrAddHeader(headers, name, value);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private void setRequestContentType(String value) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        updateOrAddHeader(headers, "Content-Type", value);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private void moveCharsetParam(boolean first) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        int idx = findHeaderIndex(headers, "Content-Type");
        if (idx < 0) {
            JOptionPane.showMessageDialog(this, "当前请求没有 Content-Type", "提示",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String line = headers.get(idx);
        int colon = line.indexOf(':');
        if (colon < 0) {
            JOptionPane.showMessageDialog(this, "Content-Type 格式异常", "提示",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String value = line.substring(colon + 1).trim();
        String reordered = reorderCharsetParam(value, first);
        if (reordered == null) {
            JOptionPane.showMessageDialog(this, "当前 Content-Type 没有 charset 参数，请先做字符集编码",
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        headers.set(idx, "Content-Type: " + reordered);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private String reorderCharsetParam(String contentType, boolean first) {
        if (contentType == null || contentType.trim().isEmpty()) {
            return null;
        }
        String[] rawParts = contentType.split(";");
        if (rawParts.length < 2) {
            return null;
        }
        String mediaType = rawParts[0].trim();
        List<String> params = new ArrayList<>();
        String charset = null;
        for (int i = 1; i < rawParts.length; i++) {
            String p = rawParts[i].trim();
            if (p.isEmpty())
                continue;
            if (p.toLowerCase().startsWith("charset=")) {
                charset = p;
            } else {
                params.add(p);
            }
        }
        if (charset == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(mediaType);
        if (first) {
            sb.append("; ").append(charset);
        }
        for (String p : params) {
            sb.append("; ").append(p);
        }
        if (!first) {
            sb.append("; ").append(charset);
        }
        return sb.toString();
    }

    // --- Transform ---

    private void urlEncode() {
        transformSelectionWithNoChangeOption(
                s -> {
                    try {
                        return URLEncoder.encode(s, "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                },
                "当前选区按标准 URL 编码后没有变化。\n\n"
                        + "这通常是因为选区只包含字母、数字等 URL 安全字符。\n"
                        + "是否仍然强制把每个 UTF-8 字节编码成 %XX？",
                this::percentEncodeAllUtf8Bytes);
    }

    private void pathUrlEncode() {
        transformSelectionWithNoChangeOption(
                this::encodePathValue,
                "当前选区按 Path 编码后没有变化。\n\n"
                        + "这通常是因为选区只包含路径安全字符。\n"
                        + "是否仍然强制把每个 UTF-8 字节编码成 %XX？",
                this::percentEncodeAllUtf8Bytes);
    }

    private String percentEncodeAllUtf8Bytes(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            sb.append(String.format("%%%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private String encodePathValue(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (byte raw : bytes) {
            int b = raw & 0xFF;
            char c = (char) b;
            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~'
                    || c == '/') {
                sb.append(c);
            } else {
                sb.append(String.format("%%%02X", b));
            }
        }
        return sb.toString();
    }

    private void doubleUrlEncode() {
        transformSelectionWithNoChangeOption(
                s -> {
                    try {
                        return URLEncoder.encode(URLEncoder.encode(s, "UTF-8"), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                },
                "当前选区按双重 URL 编码后没有变化。\n\n"
                        + "这通常是因为选区只包含字母、数字等 URL 安全字符。\n"
                        + "是否仍然强制编码安全字符？例如 d -> %64 -> %2564。",
                s -> {
                    try {
                        return URLEncoder.encode(percentEncodeAllUtf8Bytes(s), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                });
    }

    private void mixedUrlEncode() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            int eligible = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (isAsciiAlphaNum(c)) {
                    eligible++;
                    if (eligible % 2 == 0) {
                        for (byte b : String.valueOf(c).getBytes(StandardCharsets.UTF_8)) {
                            sb.append(String.format("%%%02X", b & 0xFF));
                        }
                    } else {
                        sb.append(c);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        });
    }

    private boolean isAsciiAlphaNum(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9');
    }

    private void base64Encode() {
        transformSelection(s -> Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)));
    }

    private void toUnicodeEscape() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(String.format("\\u%04x", (int) c));
            }
            return sb.toString();
        });
    }

    private void insertDirtyData() {
        String input = JOptionPane.showInputDialog(this, "输入脏数据长度（数字字符数量）:", "Dirty Data",
                JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty())
            return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, "请输入大于 0 的数字", I18n.t("dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertAtCaretOrFallback(("{{dirty(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1));
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "请输入有效数字", I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void insertNullBytes() {
        String input = JOptionPane.showInputDialog(this, "输入 Null 字节数量:", "Null Bytes", JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty())
            return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, "请输入大于 0 的数字", I18n.t("dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertAtCaretOrFallback(("{{dirtynull(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1));
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "请输入有效数字", I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private static class RequestParts {
        String headers;
        String body;
        String lineEnd;
    }

    private RequestParts splitRequestText(String requestText) {
        RequestParts parts = new RequestParts();
        int bodyStart = requestText.indexOf("\r\n\r\n");
        String lineEnd = "\r\n";
        int sepLen = 4;
        if (bodyStart < 0) {
            bodyStart = requestText.indexOf("\n\n");
            lineEnd = "\n";
            sepLen = 2;
        }
        if (bodyStart < 0)
            return null;
        parts.lineEnd = lineEnd;
        parts.headers = requestText.substring(0, bodyStart);
        parts.body = requestText.substring(bodyStart + sepLen);
        return parts;
    }

    private String removeHeaderLine(String headers, String headerName, String lineEnd) {
        String[] lines = headers.split("\\r?\\n", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                continue;
            }
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(line);
        }
        return sb.toString();
    }

    private String upsertHeaderLine(String headers, String headerName, String headerValue, String lineEnd) {
        String[] lines = headers.split("\\r?\\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                if (!found) {
                    if (sb.length() > 0)
                        sb.append(lineEnd);
                    sb.append(headerName).append(": ").append(headerValue);
                    found = true;
                }
                continue;
            }
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(line);
        }
        if (!found) {
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(headerName).append(": ").append(headerValue);
        }
        return sb.toString();
    }

    private boolean hasHeaderContains(String headers, String headerName, String needle) {
        if (headers == null)
            return false;
        String[] lines = headers.split("\\r?\\n", -1);
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                return line.toLowerCase().contains(needle.toLowerCase());
            }
        }
        return false;
    }

    private boolean looksBinaryBody(String body) {
        if (body == null || body.isEmpty())
            return false;
        int sampleLen = Math.min(body.length(), 4096);
        int suspicious = 0;
        for (int i = 0; i < sampleLen; i++) {
            char c = body.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t')
                continue;
            if (c < 0x20 || (c >= 0x7F && c <= 0x9F))
                suspicious++;
        }
        return suspicious > (sampleLen * 0.10);
    }

    private static class BodyField {
        final String name;
        final String value;

        BodyField(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    private void gzipBody() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, "请求体为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            // 1) Header 检查
            for (String h : headers) {
                String hl = h.toLowerCase();
                if (hl.startsWith("content-encoding:") && hl.contains("gzip")) {
                    JOptionPane.showMessageDialog(this, "Header 显示已是 Gzip 格式，取消操作。", "提示",
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }

            // 2) Magic bytes 检查：1F 8B
            if (body.length >= 2 && (body[0] & 0xFF) == 0x1F && (body[1] & 0xFF) == 0x8B) {
                int ret = JOptionPane.showConfirmDialog(
                        this,
                        "检测到 Body 似乎已经是 Gzip 格式 (Magic Bytes 1F 8B)。\n是否继续强制压缩？(可能导致双重压缩)",
                        "警告",
                        JOptionPane.YES_NO_OPTION);
                if (ret != JOptionPane.YES_OPTION)
                    return;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                gzip.write(body);
            }
            byte[] gzipped = baos.toByteArray();

            updateOrAddHeader(headers, "Content-Encoding", "gzip");
            removeHeaderIgnoreCase(headers, "Transfer-Encoding");
            removeHeaderIgnoreCase(headers, "Content-Length");
            headers.add("Content-Length: " + gzipped.length);

            byte[] newRequest = Utils.helpers.buildHttpMessage(headers, gzipped);
            setRequestBytes(newRequest);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Gzip 错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toFormUrlEncoded() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, "无法从当前 body 提取可转换的普通参数", "提示",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            Charset cs = charsetFromHeaders(headers);
            byte[] newBody = buildFormBody(fields, cs);
            replaceBodyAndContentType(headers, newBody, "application/x-www-form-urlencoded");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Form 转换错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toMultipart() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, "请求体为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            String currentCT = contentTypeFromHeaders(headers);
            if (currentCT.toLowerCase().contains("multipart/form-data")) {
                JOptionPane.showMessageDialog(this, "当前请求已是 Multipart 格式", I18n.t("dialog.tip.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String boundary = "----BypassProBoundary" + System.currentTimeMillis();
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, "无法从当前 body 提取可转换的普通参数", "提示",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            Charset cs = charsetFromHeaders(headers);
            byte[] multipartBody = buildMultipartBody(fields, boundary, cs);
            replaceBodyAndContentType(headers, multipartBody, "multipart/form-data; boundary=" + boundary);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Multipart 转换错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toJsonBody() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, "无法从当前 body 提取可转换的普通参数", "提示",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            byte[] jsonBody = buildJsonBody(fields);
            replaceBodyAndContentType(headers, jsonBody, "application/json");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "JSON 转换错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private List<BodyField> extractBodyFields(List<String> headers, byte[] body) throws Exception {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.length == 0) {
            return fields;
        }
        String ctRaw = contentTypeFromHeaders(headers);
        String ct = ctRaw.toLowerCase();
        Charset cs = charsetFromHeaders(headers);
        if (ct.contains("application/x-www-form-urlencoded")) {
            fields.addAll(parseFormFields(new String(body, cs), cs));
        } else if (ct.contains("multipart/form-data")) {
            fields.addAll(parseMultipartFields(new String(body, StandardCharsets.ISO_8859_1),
                    boundaryFromContentType(ctRaw), cs));
        } else if (ct.contains("json")) {
            fields.addAll(parseFlatJsonFields(new String(body, StandardCharsets.UTF_8)));
        }
        return fields;
    }

    private List<BodyField> parseFormFields(String body, Charset cs) throws Exception {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.trim().isEmpty()) {
            return fields;
        }
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            if (pair == null || pair.isEmpty())
                continue;
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], cs.name());
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], cs.name()) : "";
            fields.add(new BodyField(key, value));
        }
        return fields;
    }

    private List<BodyField> parseMultipartFields(String body, String boundary, Charset cs) {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.isEmpty() || boundary == null || boundary.isEmpty()) {
            return fields;
        }
        String marker = "--" + boundary;
        String[] parts = body.split(Pattern.quote(marker));
        Pattern namePattern = Pattern.compile("(?i)\\bname=\"([^\"]*)\"");
        for (String part : parts) {
            if (part == null || part.isEmpty() || part.startsWith("--"))
                continue;
            int sep = part.indexOf("\r\n\r\n");
            int sepLen = 4;
            if (sep < 0) {
                sep = part.indexOf("\n\n");
                sepLen = 2;
            }
            if (sep < 0)
                continue;
            String partHeaders = part.substring(0, sep);
            if (partHeaders.toLowerCase().contains("filename="))
                continue;
            Matcher m = namePattern.matcher(partHeaders);
            if (!m.find())
                continue;
            String name = m.group(1);
            String value = part.substring(sep + sepLen);
            value = value.replaceFirst("\\r?\\n$", "");
            fields.add(new BodyField(name, new String(value.getBytes(StandardCharsets.ISO_8859_1), cs)));
        }
        return fields;
    }

    private List<BodyField> parseFlatJsonFields(String body) {
        List<BodyField> fields = new ArrayList<>();
        if (body == null)
            return fields;
        String s = body.trim();
        if (!s.startsWith("{") || !s.endsWith("}")) {
            return fields;
        }
        s = s.substring(1, s.length() - 1).trim();
        if (s.isEmpty())
            return fields;

        List<String> pairs = splitTopLevelJsonPairs(s);
        for (String pair : pairs) {
            int colon = findJsonColon(pair);
            if (colon <= 0)
                continue;
            String key = unquoteJsonScalar(pair.substring(0, colon).trim());
            String value = unquoteJsonScalar(pair.substring(colon + 1).trim());
            if (key != null && value != null) {
                fields.add(new BodyField(key, value));
            }
        }
        return fields;
    }

    private List<String> splitTopLevelJsonPairs(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inString = false;
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                cur.append(c);
                escape = false;
                continue;
            }
            if (c == '\\') {
                cur.append(c);
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                cur.append(c);
                continue;
            }
            if (c == ',' && !inString) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0)
            out.add(cur.toString());
        return out;
    }

    private int findJsonColon(String s) {
        boolean inString = false;
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (c == ':' && !inString)
                return i;
        }
        return -1;
    }

    private String unquoteJsonScalar(String s) {
        if (s == null || s.isEmpty())
            return null;
        if (s.startsWith("[") || s.startsWith("{"))
            return null;
        if ("null".equals(s))
            return "";
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            return unescapeJsonString(s.substring(1, s.length() - 1));
        }
        return s;
    }

    private String unescapeJsonString(String s) {
        StringBuilder out = new StringBuilder();
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!escape) {
                if (c == '\\')
                    escape = true;
                else
                    out.append(c);
                continue;
            }
            switch (c) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (i + 4 < s.length()) {
                        try {
                            out.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                            break;
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    out.append('u');
                    break;
                default:
                    out.append(c);
                    break;
            }
            escape = false;
        }
        if (escape)
            out.append('\\');
        return out.toString();
    }

    private byte[] buildFormBody(List<BodyField> fields, Charset cs) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for (BodyField f : fields) {
            if (sb.length() > 0)
                sb.append('&');
            sb.append(URLEncoder.encode(f.name, cs.name()));
            sb.append('=');
            sb.append(URLEncoder.encode(f.value, cs.name()));
        }
        return sb.toString().getBytes(cs);
    }

    private byte[] buildMultipartBody(List<BodyField> fields, String boundary, Charset cs) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (BodyField f : fields) {
            out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("Content-Disposition: form-data; name=\"" + escapeMultipartName(f.name) + "\"\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.write(("Content-Type: text/plain; charset=" + cs.name() + "\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.write(f.value.getBytes(cs));
            out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
        }
        out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    private byte[] buildJsonBody(List<BodyField> fields) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (int i = 0; i < fields.size(); i++) {
            BodyField f = fields.get(i);
            if (i > 0)
                sb.append(',');
            sb.append('"').append(escapeJson(f.name)).append('"');
            sb.append(':');
            sb.append('"').append(escapeJson(f.value)).append('"');
        }
        sb.append('}');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String escapeJson(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }

    private String escapeMultipartName(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void replaceBodyAndContentType(List<String> headers, byte[] body, String contentType) {
        removeHeaderIgnoreCase(headers, "Content-Type");
        headers.add("Content-Type: " + contentType);
        removeHeaderIgnoreCase(headers, "Transfer-Encoding");
        removeHeaderIgnoreCase(headers, "Content-Length");
        headers.add("Content-Length: " + body.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private String contentTypeFromHeaders(List<String> headers) {
        if (headers == null)
            return "";
        for (String h : headers) {
            if (h != null && h.toLowerCase().startsWith("content-type:")) {
                return h.substring("content-type:".length()).trim();
            }
        }
        return "";
    }

    private Charset charsetFromHeaders(List<String> headers) {
        String ct = contentTypeFromHeaders(headers);
        Matcher m = Pattern.compile("(?i)charset\\s*=\\s*([^;\\r\\n]+)").matcher(ct);
        if (m.find()) {
            try {
                return Charset.forName(m.group(1).trim());
            } catch (Exception ignored) {
            }
        }
        return StandardCharsets.UTF_8;
    }

    private String boundaryFromContentType(String ct) {
        if (ct == null)
            return null;
        Matcher m = Pattern.compile("(?i)boundary\\s*=\\s*\"?([^\";\\r\\n]+)").matcher(ct);
        return m.find() ? m.group(1).trim() : null;
    }

    private void encodeBodyWithCharset(String charsetName) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            try {
                Charset charset = Charset.forName(charsetName);
                String selected = new String(sel, StandardCharsets.ISO_8859_1);
                replaceOccurrenceInRequest(sel, selected.getBytes(charset));
                if (statusLabel != null) {
                    statusLabel.setText(I18n.t("status.applied_selection", charsetName));
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "编码错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
            }
            return;
        }

        String text = getRequestTextISO();
        try {
            RequestParts parts = splitRequestText(text);
            if (parts == null) {
                JOptionPane.showMessageDialog(this, "未找到请求体", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            String lineEnd = parts.lineEnd;
            String headers = parts.headers;
            String body = expandInlineTags(parts.body);

            if (body.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请求体为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (looksBinaryBody(body)) {
                JOptionPane.showMessageDialog(this, "当前请求体看起来已是二进制/已编码数据，请先 Reset 再进行字符集编码", "提示",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            Charset charset = Charset.forName(charsetName);
            byte[] encoded = body.getBytes(charset);

            String newHeaders = headers;
            if (newHeaders.toLowerCase().contains("content-type:")) {
                String[] lines = newHeaders.split("\\r?\\n", -1);
                StringBuilder sb = new StringBuilder();
                boolean ctDone = false;
                for (String line : lines) {
                    if (!ctDone && line.toLowerCase().startsWith("content-type:")) {
                        String normalized = line.replaceAll("(?i);\\s*charset=[^;\\r\\n]*", "");
                        normalized = normalized + "; charset=" + charsetName;
                        if (sb.length() > 0)
                            sb.append(lineEnd);
                        sb.append(normalized);
                        ctDone = true;
                    } else {
                        if (sb.length() > 0)
                            sb.append(lineEnd);
                        sb.append(line);
                    }
                }
                newHeaders = sb.toString();
            }
            newHeaders = removeHeaderLine(newHeaders, "Transfer-Encoding", lineEnd);
            newHeaders = upsertHeaderLine(newHeaders, "Content-Length", String.valueOf(encoded.length), lineEnd);

            String newRequest = newHeaders + lineEnd + lineEnd + new String(encoded, StandardCharsets.ISO_8859_1);
            setRequestTextISO(newRequest);
            if (statusLabel != null) {
                statusLabel.setText(I18n.t("status.applied_body", charsetName));
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "编码错误: " + e.getMessage(), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toUpper() {
        transformSelection(String::toUpperCase);
    }

    private void toLower() {
        transformSelection(String::toLowerCase);
    }

    private void toRandomCase() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(Math.random() > 0.5 ? Character.toUpperCase(c) : Character.toLowerCase(c));
            }
            return sb.toString();
        });
    }

    private void toFullwidth() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                if (c >= '!' && c <= '~')
                    sb.append((char) (c - '!' + '！'));
                else if (c == ' ')
                    sb.append('　');
                else
                    sb.append(c);
            }
            return sb.toString();
        });
    }

    private void toHomoglyph() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(toHomoglyphChar(c));
            }
            return sb.toString();
        });
    }

    private char toHomoglyphChar(char c) {
        switch (c) {
            case 'a':
                return 'а';
            case 'e':
                return 'е';
            case 'o':
                return 'о';
            case 'p':
                return 'р';
            case 'c':
                return 'с';
            case 'x':
                return 'х';
            case 'y':
                return 'у';
            case 'i':
                return 'і';
            case 'j':
                return 'ј';
            case 's':
                return 'ѕ';
            case 'A':
                return 'А';
            case 'B':
                return 'В';
            case 'C':
                return 'С';
            case 'E':
                return 'Е';
            case 'H':
                return 'Н';
            case 'I':
                return 'І';
            case 'K':
                return 'К';
            case 'M':
                return 'М';
            case 'O':
                return 'О';
            case 'P':
                return 'Р';
            case 'T':
                return 'Т';
            case 'X':
                return 'Х';
            case 'Y':
                return 'Ү';
            default:
                return c;
        }
    }

    private void insertZeroWidth() {
        transformSelection(s -> {
            if (s.length() <= 1) {
                return s;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                sb.append(s.charAt(i));
                if (i < s.length() - 1) {
                    sb.append('\u200B');
                }
            }
            return sb.toString();
        });
    }

    private void insertAt(String text) {
        insertAtCaretOrFallback(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void switchToHttp10() {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0)
            return;

        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        if (!headers.isEmpty()) {
            String reqLine = headers.get(0);
            reqLine = reqLine.replaceAll("HTTP/1\\.[0-9]", "HTTP/1.0");
            headers.set(0, reqLine);
        }

        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i).toLowerCase();
            if (h.startsWith("connection:") ||
                    h.startsWith("proxy-connection:") ||
                    h.startsWith("keep-alive:") ||
                    h.startsWith("transfer-encoding:")) {
                headers.remove(i);
            }
        }

        boolean hasConnClose = false;
        for (String h : headers) {
            if (h.toLowerCase().startsWith("connection:") && h.toLowerCase().contains("close")) {
                hasConnClose = true;
                break;
            }
        }
        if (!hasConnClose) {
            headers.add("Connection: close");
        }

        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        byte[] newRequest = Utils.helpers.buildHttpMessage(headers, body);
        setRequestBytes(newRequest);
    }

    // ------------------------------------------------------------------
    // Ghost Bits 操作
    // ------------------------------------------------------------------

    private void encodeGhostSelection(GhostBitsCodec.EncodeStrategy strategy) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中要 Ghost 化的原始 payload",
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Gh0st Bits");
        if (selected == null) {
            return;
        }
        if (GhostBitsCodec.containsLineBreak(selected) && GhostBitsCodec.mayEncodeLineBreak(strategy)) {
            int ret = JOptionPane.showConfirmDialog(this,
                    "当前选区包含换行。该策略可能把 CR/LF 也 Ghost 化，导致 HTTP 请求结构被破坏。\n是否继续？",
                    "Gh0st Bits", JOptionPane.YES_NO_OPTION);
            if (ret != JOptionPane.YES_OPTION) {
                return;
            }
        }
        String encoded = GhostBitsCodec.encode(selected, strategy, Utils.getGhostBitsEngine());
        if (encoded.equals(selected)) {
            if (statusLabel != null) {
                statusLabel.setText(I18n.t("status.ghost_no_change"));
            }
            return;
        }
        boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded) && isSelectionLikelyRequestLineOrHeader(sel);
        if (!replaceOccurrenceInRequest(sel, encoded.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        updateGhostStatus(encoded, GhostBitsCodec.fold(encoded, ghostFoldMode),
                rawRecommended);
    }

    private void randomizeGhostSelection() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中已 Ghost 化或待 Ghost 化的文本",
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Gh0st Bits");
        if (selected == null) {
            return;
        }

        int mask = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7 ? 0x7F : 0xFF;
        StringBuilder sb = new StringBuilder(selected.length());
        for (int i = 0; i < selected.length(); i++) {
            char c = selected.charAt(i);
            if (c > 0x7F) {
                sb.append(randomHighByte(c, mask));
            } else {
                sb.append(c);
            }
        }
        String encoded = sb.toString();

        String folded = GhostBitsCodec.fold(encoded, ghostFoldMode);
        boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded)
                && isSelectionLikelyRequestLineOrHeader(sel);

        String msg = buildShufflePreview(selected, encoded, folded, rawRecommended);
        int ret = JOptionPane.showConfirmDialog(this, msg,
                I18n.t("tooltip.shuffle.title"), JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }

        if (!replaceOccurrenceInRequest(sel, encoded.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        updateGhostStatus(encoded, folded, rawRecommended);
    }

    private String buildShufflePreview(String before, String after, String folded, boolean rawRecommended) {
        StringBuilder sb = new StringBuilder();
        String foldedBefore = GhostBitsCodec.fold(before, ghostFoldMode);
        sb.append("Fold:   ").append(GhostBitsCodec.foldModeLabel(ghostFoldMode)).append('\n');
        sb.append('\n');
        sb.append("换组前: ").append(truncateForPreview(before)).append('\n');
        sb.append("换组后: ").append(truncateForPreview(after)).append('\n');
        sb.append('\n');
        sb.append("还原前: ").append(truncateForPreview(escape(foldedBefore))).append('\n');
        sb.append("还原后: ").append(truncateForPreview(escape(folded)));
        if (foldedBefore.equals(folded)) {
            sb.append("  (不变)");
        } else {
            sb.append("  (! 已改变)");
        }
        sb.append('\n');
        if (rawRecommended) {
            sb.append('\n').append("Send: Raw Socket recommended");
        }
        return sb.toString();
    }

    private static String truncateForPreview(String s) {
        if (s == null) return "";
        if (s.length() > 80) return s.substring(0, 77) + "...";
        return s;
    }

    private static char randomHighByte(char c, int mask) {
        int low = c & mask;
        int oldHigh = c >> 8;
        int newHigh;
        do {
            newHigh = 1 + ThreadLocalRandom.current().nextInt(0xFF);
        } while (newHigh == oldHigh);
        int code = (newHigh << 8) | low;
        if (code >= 0xD800 && code <= 0xDFFF) {
            code = (0x4E << 8) | low;
        }
        return (char) code;
    }

    private String decodeSelectedUtf8(byte[] selectedBytes, String title) {
        if (selectedBytes == null) {
            return "";
        }
        String selected = new String(selectedBytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(selected.getBytes(StandardCharsets.UTF_8), selectedBytes)) {
            JOptionPane.showMessageDialog(this,
                    "当前选区不是有效 UTF-8 文本。Gh0st Bits 只处理 ASCII/UTF-8 文本选区，避免破坏二进制 body。",
                    title, JOptionPane.INFORMATION_MESSAGE);
            return null;
        }
        return selected;
    }

    private JToggleButton createFoldModeToggle(String text, GhostBitsCodec.FoldMode mode, boolean selected) {
        String displayText = resolveBtnText(text);
        String i18nTip = i18nTooltipFor(text);
        String tooltip = i18nTip != null ? i18nTip : defaultTooltip(text);
        JToggleButton btn = new JToggleButton(displayText, selected) {
            @Override
            public JToolTip createToolTip() {
                JToolTip tip = new MultiLineToolTip();
                tip.setComponent(this);
                return tip;
            }
        };
        btn.setMargin(new Insets(0, 7, 0, 7));
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        btn.setFocusPainted(false);
        if (tooltip != null && !tooltip.isEmpty()) {
            btn.setToolTipText(tooltip);
        }
        Dimension pref = btn.getPreferredSize();
        btn.setPreferredSize(new Dimension(pref.width, 24));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        btn.addActionListener(e -> setGhostFoldMode(mode));
        return btn;
    }

    private void setGhostFoldMode(GhostBitsCodec.FoldMode mode) {
        ghostFoldMode = mode == null ? GhostBitsCodec.FoldMode.BIT_8 : mode;
        if (ghostFold8BitBtn != null) {
            ghostFold8BitBtn.setSelected(ghostFoldMode == GhostBitsCodec.FoldMode.BIT_8);
        }
        if (ghostFold7BitBtn != null) {
            ghostFold7BitBtn.setSelected(ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7);
        }
        updateGhostCompactPreview(getSelectedRequestBytes());
        if (statusLabel != null) {
            statusLabel.setText("Gh0st Bits restore mode: " + GhostBitsCodec.foldModeLabel(ghostFoldMode));
        }
    }

    private void updateGhostStatus(String encoded, String folded, boolean rawRecommended) {
        if (statusLabel == null) {
            return;
        }
        String msg = "Ghost Restore OK: " + compactForStatus(encoded) + " -> " + compactForStatus(escape(folded));
        if (rawRecommended) {
            msg += " | Send: Raw Socket recommended";
        }
        statusLabel.setText(msg);
        updateGhostSelectionFoldPreview(encoded, folded, rawRecommended);
    }

    private String compactForStatus(String s) {
        if (s == null) {
            return "";
        }
        String value = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
        if (value.length() > 60) {
            return value.substring(0, 57) + "...";
        }
        return value;
    }

    private void applyGhostSequence(String foldedValue, String note) {
        String encoded = encodeGhostPayloadVariant(foldedValue);
        applyFixedGhostSequence(encoded, note);
    }

    private String encodeGhostPayloadVariant(String foldedValue) {
        if (foldedValue == null || foldedValue.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(foldedValue.length());
        for (int i = 0; i < foldedValue.length(); i++) {
            char c = foldedValue.charAt(i);
            if (ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7) {
                List<String> candidates = GhostBitsCodec.buildSevenBitCandidates(c);
                if (candidates.isEmpty()) {
                    sb.append(c);
                } else {
                    String chosen = candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
                    sb.append(chosen);
                }
            } else {
                sb.append(GhostBitsCodec.pickGhostChar(c, null));
            }
        }
        return sb.toString();
    }

    private void applyFixedGhostSequence(String encoded, String note) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中要替换的位置",
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded) && isSelectionLikelyRequestLineOrHeader(sel);
        if (!replaceOccurrenceInRequest(sel, encoded.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        updateGhostStatus(encoded, GhostBitsCodec.fold(encoded, ghostFoldMode), rawRecommended);
        if (note != null && !note.isEmpty() && statusLabel != null) {
            statusLabel.setText(statusLabel.getText() + " | " + note);
        }
    }

    private void applyParserDiffSelection(String payload, String statusText) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中要替换的位置",
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!replaceOccurrenceInRequest(sel, payload.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        if (statusLabel != null) {
            statusLabel.setText(statusText);
        }
        updateGhostSelectionFoldPreview(payload, GhostBitsCodec.fold(payload, ghostFoldMode), false);
    }

    private void applyJettyLooseHexSelection() {
        transformParserBypassSelection("Jetty %2>", this::toJettyLooseHexDots);
    }

    private String toJettyLooseHexDots(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        boolean changed = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                sb.append("%2>");
                changed = true;
                continue;
            }
            if (c == '%' && i + 2 < s.length() && s.charAt(i + 1) == '2'
                    && (s.charAt(i + 2) == 'e' || s.charAt(i + 2) == 'E')) {
                sb.append("%2>");
                i += 2;
                changed = true;
                continue;
            }
            sb.append(c);
        }
        if (!changed) {
            JOptionPane.showMessageDialog(this,
                    "Jetty %2> 只处理点号 token。请选中 .、%2e，或包含这些 token 的路径片段。",
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
        }
        return changed ? sb.toString() : s;
    }

    private void applyFastjsonLooseHexSelection() {
        transformParserBypassSelection("fastjson \\x4_", s -> {
            if (s.contains("@")) {
                return s.replace("@", "\\x4J");
            }
            if (s.contains("\\x40")) {
                return s.replace("\\x40", "\\x4J");
            }
            return "\\x4J" + s;
        });
    }

    private void applyFastjsonUnicodeSelection() {
        transformParserBypassSelection("fastjson \\u", s -> {
            if (s.contains("\\u")) {
                return replaceAsciiDigitsWithUnicodeDigits(s);
            }
            return toUnicodeEscapeWithUnicodeDigits(s);
        });
    }

    private void applyJacksonUnicodeSelection() {
        transformParserBypassSelection("jackson \\u", s -> {
            if (s.contains("\\u")) {
                return ghostifyUnicodeEscapeHexDigits(s);
            }
            return toJacksonGhostUnicodeEscape(s);
        });
    }

    private void applyUnicodeDigitsSelection() {
        transformParserBypassSelection("Unicode Digits", this::replaceAsciiDigitsWithUnicodeDigits);
    }

    private void applyFullwidthUrlSelection() {
        transformParserBypassSelection("Fullwidth URL", this::toFullwidthUrlPayload);
    }

    private void applyTomcatSevenBitHexSelection() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中 filename* 中要隐藏的原始字符，例如 j 或 .jsp",
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Tomcat %HH");
        if (selected == null) {
            return;
        }
        if (looksLikeRawHexBytes(selected)) {
            int choice = JOptionPane.showOptionDialog(this,
                    "Tomcat %HH 接收原始字符，不接收 hex 字符串。\n"
                            + "例如要隐藏 j，请选中 j；不要选中 6a。\n\n"
                            + "如果继续，工具会把字符 " + selected + " 本身逐字节编码。",
                    "Tomcat %HH",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    new Object[]{"取消", "继续按原文编码"},
                    "取消");
            if (choice != 1) {
                return;
            }
        }
        String replaced = toTomcatSevenBitPercentHex(selected);
        if (replaced == null || replaced.equals(selected)) {
            if (statusLabel != null) {
                statusLabel.setText("ParserBypass: Tomcat %HH did not change selection");
            }
            return;
        }
        if (!replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        if (statusLabel != null) {
            statusLabel.setText("ParserBypass: Tomcat %HH applied | input is raw char, not 6a hex text");
        }
        updateGhostSelectionFoldPreview(replaced, GhostBitsCodec.fold(replaced, ghostFoldMode), false);
    }

    private boolean looksLikeRawHexBytes(String s) {
        if (s == null || s.length() != 2) {
            return false;
        }
        return isAsciiHex(s.charAt(0)) && isAsciiHex(s.charAt(1));
    }

    private boolean isAsciiHex(char c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private void transformParserBypassSelection(String name, java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中要处理的解析差异片段",
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "ParserBypass");
        if (selected == null) {
            return;
        }
        String replaced = transformer.apply(selected);
        if (replaced == null || replaced.equals(selected)) {
            if (statusLabel != null) {
                statusLabel.setText("ParserBypass: " + name + " did not change selection");
            }
            return;
        }
        if (!replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        if (statusLabel != null) {
            statusLabel.setText("ParserBypass: " + name + " applied");
        }
        updateGhostSelectionFoldPreview(replaced, GhostBitsCodec.fold(replaced, ghostFoldMode), false);
    }

    private String replaceAsciiDigitsWithUnicodeDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        char[] unicodeDigits = {
                '\u0660', '\u0661', '\u0662', '\u0663', '\u0664',
                '\u0665', '\u0666', '\u0667', '\u0668', '\u0669'
        };
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                sb.append(unicodeDigits[c - '0']);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String toUnicodeEscapeWithUnicodeDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 6);
        for (int i = 0; i < s.length(); i++) {
            String hex = String.format("%04x", (int) s.charAt(i));
            sb.append("\\u").append(replaceAsciiDigitsWithUnicodeDigits(hex));
        }
        return sb.toString();
    }

    private String toJacksonGhostUnicodeEscape(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 6);
        for (int i = 0; i < s.length(); i++) {
            sb.append("\\u").append(ghostEncodeHexDigits(String.format("%04x", (int) s.charAt(i))));
        }
        return sb.toString();
    }

    private String ghostifyUnicodeEscapeHexDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            if (i + 5 < s.length() && s.charAt(i) == '\\' && s.charAt(i + 1) == 'u'
                    && isFourAsciiHexDigits(s, i + 2)) {
                sb.append("\\u");
                sb.append(ghostEncodeHexDigits(s.substring(i + 2, i + 6)));
                i += 5;
            } else {
                sb.append(s.charAt(i));
            }
        }
        return sb.toString();
    }

    private boolean isFourAsciiHexDigits(String s, int start) {
        if (s == null || start < 0 || start + 4 > s.length()) {
            return false;
        }
        for (int i = start; i < start + 4; i++) {
            if (s.charAt(i) > 0x7F || Character.digit(s.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private String ghostEncodeHexDigits(String hex) {
        StringBuilder sb = new StringBuilder(hex.length());
        for (int i = 0; i < hex.length(); i++) {
            char c = Character.toLowerCase(hex.charAt(i));
            if (c <= 0x7F && Character.digit(c, 16) >= 0) {
                sb.append(GhostBitsCodec.pickGhostChar(c, Utils.getGhostBitsEngine()));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String toTomcatSevenBitPercentHex(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 3);
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        for (byte raw : bytes) {
            String hex = String.format("%02x", raw & 0xFF);
            sb.append('%')
                    .append(pickSevenBitGhostChar(hex.charAt(0)))
                    .append(pickSevenBitGhostChar(hex.charAt(1)));
        }
        return sb.toString();
    }

    private char pickSevenBitGhostChar(char target) {
        List<String> candidates = GhostBitsCodec.buildSevenBitCandidates(target);
        if (candidates.isEmpty()) {
            return target;
        }
        String chosen = candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
        return chosen.isEmpty() ? target : chosen.charAt(0);
    }

    private String toFullwidthUrlPayload(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                sb.append(c);
            } else if (c >= '!' && c <= '~') {
                sb.append((char) (c - '!' + '！'));
            } else if (c == ' ') {
                sb.append('　');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private boolean isSelectionLikelyRequestLineOrHeader(byte[] sel) {
        byte[] req = getRequestBytes();
        if (req == null || sel == null || sel.length == 0) {
            return false;
        }
        List<Integer> positions = findAllOccurrences(req, sel);
        int headerEnd = findHeaderEnd(req);
        for (int pos : positions) {
            if (headerEnd < 0 || pos < headerEnd) {
                return true;
            }
        }
        return false;
    }

    private void showGhostCandidates() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中一个 ASCII 字符（如 . / % / @ / \\r / \\n）",
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Candidates");
        if (selected == null) {
            return;
        }
        if (selected.length() != 1) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.candidates.single_char_only"),
                    I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (selected.charAt(0) > 0x7F) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.candidates.ascii_only"),
                    I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<String> candidates = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7
                ? GhostBitsCodec.buildSevenBitCandidates(selected.charAt(0))
                : Utils.getGhostBitsEngine().findCandidates(selected);
        showGhostLookup(selected, candidates);
    }

    private void showGhostLookup(String target, List<String> candidates) {
        StringBuilder sb = new StringBuilder();
        sb.append("字符: ").append(escape(target)).append("  0x")
                .append(String.format("%02X", target.charAt(0) & 0xFF)).append('\n');
        sb.append("模式: ").append(GhostBitsCodec.foldModeLabel(ghostFoldMode)).append("\n\n");
        int max = Math.min(candidates.size(), 24);
        for (int i = 0; i < max; i++) {
            String c = candidates.get(i);
            int code = c.charAt(0);
            int low = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7 ? code & 0x7F : code & 0xFF;
            sb.append(c)
                    .append("  U+").append(String.format("%04X", code))
                    .append("  -> 0x").append(String.format("%02X", low))
                    .append(" -> ").append(escape(String.valueOf((char) low)))
                    .append('\n');
        }
        JOptionPane.showMessageDialog(this, sb.toString(),
                I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
    }

    private void applyGhostTemplate(GhostBitsRule.Template t) {
        if (t == null) {
            return;
        }
        String rendered = Utils.getGhostBitsEngine().renderTemplate(t.getId());
        if (rendered == null || rendered.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "模板 " + t.getId() + " 渲染结果为空，请检查 YAML pattern",
                    "Gh0st Bits Template", JOptionPane.WARNING_MESSAGE);
            return;
        }

        byte[] before = getRequestBytes();
        byte[] payload = rendered.getBytes(StandardCharsets.UTF_8);
        String target = t.getTarget() == null ? "selection" : t.getTarget().toLowerCase();
        switch (target) {
            case "path":
                applyTemplateToPath(t, payload, rendered);
                break;
            case "filename":
                applyTemplateToFilename(t, payload, rendered);
                break;
            case "header":
            case "header_value":
                applyTemplateToHeaderValue(t, payload, rendered);
                break;
            case "selection":
            default:
                applyTemplateToSelection(t, payload, rendered);
                break;
        }

        byte[] after = getRequestBytes();
        if (before != null && after != null && Arrays.equals(before, after)) {
            return;
        }
        boolean rawRecommended = t.requiresRawSender()
                || (GhostBitsCodec.containsNonAscii(rendered) && ("path".equals(target) || "header".equals(target)
                        || "header_value".equals(target)));
        updateGhostStatus(rendered, GhostBitsCodec.fold(rendered, ghostFoldMode), rawRecommended);
        if (statusLabel != null) {
            statusLabel.setText(statusLabel.getText() + " | Template: " + t.getLabel());
        }
    }

    /**
     * target=path: 自动替换请求行中的 path，不需要用户先选中。
     */
    private void applyTemplateToPath(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 找请求行: 第一个 \r\n 之前
        int lineEnd = -1;
        for (int i = 0; i + 1 < req.length; i++) {
            if (req[i] == '\r' && req[i + 1] == '\n') {
                lineEnd = i;
                break;
            }
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            JOptionPane.showMessageDialog(this, "未识别请求行", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 请求行格式: METHOD SP PATH SP HTTP/x.y
        int firstSpace = -1, secondSpace = -1;
        for (int i = 0; i < lineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else if (secondSpace < 0) {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            JOptionPane.showMessageDialog(this, "请求行格式不规范，无法定位 path", "提示",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        int pathStart = firstSpace + 1;
        int pathEnd = secondSpace;

        // 拼装新请求字节
        byte[] out = new byte[req.length - (pathEnd - pathStart) + payload.length];
        System.arraycopy(req, 0, out, 0, pathStart);
        System.arraycopy(payload, 0, out, pathStart, payload.length);
        System.arraycopy(req, pathEnd, out, pathStart + payload.length, req.length - pathEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (path) | " + t.getLabel());
        }
    }

    /**
     * target=filename: 在 multipart body 里找 filename="..." 或 filename*=... 的取值并替换。
     */
    private void applyTemplateToFilename(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        String text = new String(req, StandardCharsets.ISO_8859_1);
        // 优先匹配 RFC2231 形式 filename*=charset''value
        Pattern rfc2231 = Pattern.compile("(?i)filename\\*\\s*=\\s*([\\w\\-]+)''([^;\\r\\n\"]+)");
        Matcher m = rfc2231.matcher(text);
        int valueStart = -1, valueEnd = -1;
        byte[] replacement = payload;
        if (m.find()) {
            valueStart = m.start(2);
            valueEnd = m.end(2);
        } else {
            // 普通 filename="value"
            Pattern plain = Pattern.compile("(?i)filename\\s*=\\s*\"([^\"\\r\\n]*)\"");
            m = plain.matcher(text);
            if (m.find()) {
                if (requiresRfc2231FilenameTemplate(t)) {
                    valueStart = m.start();
                    valueEnd = m.end();
                    replacement = ("filename*=\"UTF-8''" + rendered + "\"").getBytes(StandardCharsets.UTF_8);
                } else {
                    valueStart = m.start(1);
                    valueEnd = m.end(1);
                }
            }
        }

        if (valueStart < 0) {
            int ret = JOptionPane.showConfirmDialog(this,
                    "未在请求中找到 filename= 段。\n是否回退为「替换当前选中文本」？",
                    "filename 定位失败", JOptionPane.YES_NO_OPTION);
            if (ret == JOptionPane.YES_OPTION) {
                applyTemplateToSelection(t, payload, rendered);
            }
            return;
        }

        byte[] out = new byte[req.length - (valueEnd - valueStart) + replacement.length];
        System.arraycopy(req, 0, out, 0, valueStart);
        System.arraycopy(replacement, 0, out, valueStart, replacement.length);
        System.arraycopy(req, valueEnd, out, valueStart + replacement.length, req.length - valueEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (filename) | " + t.getLabel());
        }
    }

    private boolean requiresRfc2231FilenameTemplate(GhostBitsRule.Template t) {
        if (t == null) {
            return false;
        }
        String id = t.getId() == null ? "" : t.getId().toLowerCase();
        String category = t.getCategory() == null ? "" : t.getCategory().toLowerCase();
        return id.contains("tomcat") || category.contains("tomcat");
    }

    /**
     * target=header_value: 让用户选/输入 header 名，把它的 value 替换成 payload。
     */
    private void applyTemplateToHeaderValue(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, "请求为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 收集已有 header 名给用户选择
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        String headerSection = new String(req, 0, upper, StandardCharsets.ISO_8859_1);
        String[] lines = headerSection.split("\\r?\\n", -1);
        java.util.List<String> headerNames = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon > 0)
                headerNames.add(line.substring(0, colon));
        }

        Object[] options = headerNames.toArray();
        Object choice = options.length == 0
                ? JOptionPane.showInputDialog(this, "输入 header 名:", t.getLabel(),
                        JOptionPane.QUESTION_MESSAGE)
                : JOptionPane.showInputDialog(this, "选择要替换 value 的 header:",
                        t.getLabel(), JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        if (choice == null)
            return;
        String headerName = choice.toString().trim();
        if (headerName.isEmpty())
            return;

        // 找到对应行并替换 value
        Pattern p = Pattern.compile("(?im)^" + Pattern.quote(headerName) + "\\s*:\\s*([^\\r\\n]*)");
        String full = new String(req, StandardCharsets.ISO_8859_1);
        Matcher mm = p.matcher(full);
        if (!mm.find()) {
            JOptionPane.showMessageDialog(this, "未找到 header: " + headerName,
                    I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        int valueStart = mm.start(1);
        int valueEnd = mm.end(1);

        byte[] out = new byte[req.length - (valueEnd - valueStart) + payload.length];
        System.arraycopy(req, 0, out, 0, valueStart);
        System.arraycopy(payload, 0, out, valueStart, payload.length);
        System.arraycopy(req, valueEnd, out, valueStart + payload.length, req.length - valueEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (header " + headerName + ") | " + t.getLabel());
        }
    }

    /**
     * target=selection: 严格按选中文本替换；没选区则弹预览。
     */
    private void applyTemplateToSelection(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            replaceOccurrenceInRequest(sel, payload);
            return;
        }
        JOptionPane.showMessageDialog(this,
                "模板已生成，请先选中要替换的位置（target=" + t.getTarget() + "）后再应用：\n\n"
                        + rendered,
                "Template Preview", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showFoldPreview() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "请先选中要预览的 Gh0st Bits 文本",
                    "Fold Preview", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String text = decodeSelectedUtf8(sel, "Fold Preview");
        if (text == null) {
            return;
        }
        String folded = GhostBitsCodec.fold(text, ghostFoldMode);
        JOptionPane.showMessageDialog(this, GhostBitsCodec.buildFoldPreviewReport(text, ghostFoldMode),
                "Fold Preview", JOptionPane.INFORMATION_MESSAGE);
        updateGhostStatus(text, folded, false);
    }

    private static String escape(String s) {
        if (s == null)
            return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\r')
                sb.append("\\r");
            else if (c == '\n')
                sb.append("\\n");
            else if (c == '\t')
                sb.append("\\t");
            else
                sb.append(c);
        }
        return sb.toString();
    }

    private void transformSelection(java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中要变换的文本", I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = new String(sel, StandardCharsets.ISO_8859_1);
        String replaced = transformer.apply(selected);
        if (replaced == null || replaced.equals(selected)) {
            String msg = "当前操作对选区没有产生变化。\n\n"
                    + "常见原因：选区字符在该规则下属于安全字符，或已经符合目标形态。";
            JOptionPane.showMessageDialog(this, msg, I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            if (statusLabel != null)
                statusLabel.setText("No change: operation left selection unchanged");
            return;
        }
        replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void transformSelectionWithNoChangeOption(
            java.util.function.Function<String, String> transformer,
            String prompt,
            java.util.function.Function<String, String> fallbackTransformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中要变换的文本", I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = new String(sel, StandardCharsets.ISO_8859_1);
        String replaced = transformer.apply(selected);
        if (replaced == null || replaced.equals(selected)) {
            int ret = JOptionPane.showConfirmDialog(this, prompt,
                    I18n.t("dialog.tip.title"), JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (ret != JOptionPane.YES_OPTION) {
                if (statusLabel != null)
                    statusLabel.setText("No change: operation left selection unchanged");
                return;
            }
            replaced = fallbackTransformer.apply(selected);
            if (replaced == null || replaced.equals(selected)) {
                if (statusLabel != null)
                    statusLabel.setText("No change: fallback left selection unchanged");
                return;
            }
        }
        replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void runRequestMutation(Runnable action) {
        byte[] before = getRequestBytes();
        CaretSnapshot caret = captureRequestCaret();
        pendingRequestCaretPosition = null;
        action.run();
        byte[] after = getRequestBytes();
        if (!Arrays.equals(before, after)) {
            pushUndo(before);
            redoStack.clear();
            updateUndoRedoButtons();
            if (pendingRequestCaretPosition != null) {
                restoreRequestCaretAt(pendingRequestCaretPosition, after.length);
            } else {
                restoreRequestCaret(caret, after.length);
            }
        }
        pendingRequestCaretPosition = null;
        refreshRequestInspector();
    }

    private void pushUndo(byte[] state) {
        if (state == null) {
            state = new byte[0];
        }
        undoStack.push(Arrays.copyOf(state, state.length));
        if (undoStack.size() > MAX_UNDO_STEPS) {
            undoStack.remove(0);
        }
    }

    private void pushRedo(byte[] state) {
        if (state == null) {
            state = new byte[0];
        }
        redoStack.push(Arrays.copyOf(state, state.length));
        if (redoStack.size() > MAX_REDO_STEPS) {
            redoStack.remove(0);
        }
    }

    private void updateUndoRedoButtons() {
        if (undoBtn != null) {
            undoBtn.setEnabled(!undoStack.isEmpty());
        }
        if (redoBtn != null) {
            redoBtn.setEnabled(!redoStack.isEmpty());
        }
    }

    private CaretSnapshot captureRequestCaret() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return null;
        }
        CaretSnapshot snapshot = new CaretSnapshot();
        snapshot.editor = editor;
        snapshot.caret = editor.getCaretPosition();
        snapshot.selectionStart = editor.getSelectionStart();
        snapshot.selectionEnd = editor.getSelectionEnd();
        return snapshot;
    }

    private JTextComponent findRequestTextComponent() {
        if (requestViewer == null || requestViewer.getComponent() == null) {
            return null;
        }
        Component focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        if (focus instanceof JTextComponent && SwingUtilities.isDescendingFrom(focus, requestViewer.getComponent())) {
            return (JTextComponent) focus;
        }
        return findFirstTextComponent(requestViewer.getComponent());
    }

    private JTextComponent findFirstTextComponent(Component comp) {
        if (comp instanceof JTextComponent) {
            return (JTextComponent) comp;
        }
        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                JTextComponent found = findFirstTextComponent(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private void restoreRequestCaret(CaretSnapshot snapshot, int newLength) {
        if (snapshot == null || snapshot.editor == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                int max = Math.max(0, Math.min(snapshot.editor.getDocument().getLength(), newLength));
                int start = Math.max(0, Math.min(snapshot.selectionStart, max));
                int end = Math.max(0, Math.min(snapshot.selectionEnd, max));
                int caret = Math.max(0, Math.min(snapshot.caret, max));
                snapshot.editor.requestFocusInWindow();
                if (start != end) {
                    snapshot.editor.select(start, end);
                } else {
                    snapshot.editor.setCaretPosition(caret);
                }
            } catch (Exception ignored) {
            }
        });
    }

    private void restoreRequestCaretAt(int position, int newLength) {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                int max = Math.max(0, Math.min(editor.getDocument().getLength(), newLength));
                int caret = Math.max(0, Math.min(position, max));
                editor.requestFocusInWindow();
                editor.setCaretPosition(caret);
            } catch (Exception ignored) {
            }
        });
    }

    private static class CaretSnapshot {
        JTextComponent editor;
        int caret;
        int selectionStart;
        int selectionEnd;
    }

    // --- Undo/Redo ---
    private void undo() {
        if (!undoStack.isEmpty()) {
            CaretSnapshot caret = captureRequestCaret();
            pushRedo(getRequestBytes());
            byte[] prev = undoStack.pop();
            setRequestBytes(prev);
            restoreRequestCaret(caret, prev.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    private void redo() {
        if (!redoStack.isEmpty()) {
            CaretSnapshot caret = captureRequestCaret();
            pushUndo(getRequestBytes());
            byte[] next = redoStack.pop();
            setRequestBytes(next);
            restoreRequestCaret(caret, next.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    private void reset() {
        if (originalRequest != null && originalRequest.length > 0) {
            byte[] before = getRequestBytes();
            if (Arrays.equals(before, originalRequest)) {
                return;
            }
            CaretSnapshot caret = captureRequestCaret();
            pushUndo(before);
            redoStack.clear();
            setRequestBytes(originalRequest);
            restoreRequestCaret(caret, originalRequest.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    // --- Send ---
    private void sendRequest() {
        String host = hostField == null ? "" : hostField.getText().trim();
        String portStr = portField == null ? "" : portField.getText().trim();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Host 不能为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "端口号必须是数字", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        String protocol = (httpsCheckBox != null && httpsCheckBox.isSelected()) ? "https" : "http";
        IHttpService targetService = Utils.helpers.buildHttpService(host, port, protocol);
        currentHttpService = targetService;

        byte[] rawReq = getRequestBytes();
        if (rawReq == null || rawReq.length == 0) {
            JOptionPane.showMessageDialog(this, "请求内容为空", I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        final boolean followRedirect = followRedirectCheckBox != null && followRedirectCheckBox.isSelected();
        isCancelled = false;

        long startNs = System.nanoTime();
        if (statusLabel != null) {
            statusLabel.setText(I18n.t("status.sending"));
        }

        if (sendBtn != null) {
            sendBtn.setEnabled(false);
            sendBtn.setText("Sending...");
        }
        if (cancelBtn != null) {
            cancelBtn.setEnabled(true);
        }

        // 决定 sender
        byte[] preview = buildRequestBytesForSending(rawReq);
        final boolean useRaw = shouldUseRawSocket(preview);
        final String hostFinal = host;
        final int portFinal = port;
        final boolean httpsFinal = "https".equalsIgnoreCase(protocol);

        if (useRaw) {
            sendThread = new Thread(() -> sendViaRawSocket(
                    rawReq, hostFinal, portFinal, httpsFinal, startNs));
            sendThread.start();
            return;
        }

        sendThread = new Thread(() -> {
            try {
                byte[] finalBytes = buildRequestBytesForSending(rawReq);
                IHttpService currentTarget = targetService;
                IHttpRequestResponse resp = null;
                byte[] respBytes = null;
                int redirectCount = 0;
                final int MAX_REDIRECTS = 10;

                // 发送请求（可能跟随重定向）
                while (!isCancelled && redirectCount <= MAX_REDIRECTS) {
                    resp = Utils.callbacks.makeHttpRequest(currentTarget, finalBytes);
                    if (isCancelled)
                        break;

                    respBytes = (resp == null) ? null : resp.getResponse();
                    if (respBytes == null)
                        break;

                    // 检查是否需要跟随重定向
                    if (followRedirect) {
                        short statusCode = Utils.helpers.analyzeResponse(respBytes).getStatusCode();
                        if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307
                                || statusCode == 308) {
                            String location = getHeaderValue(respBytes, "Location");
                            if (location != null && !location.isEmpty()) {
                                try {
                                    // 解析 Location
                                    java.net.URL redirectUrl;
                                    if (location.startsWith("http://") || location.startsWith("https://")) {
                                        redirectUrl = new java.net.URL(location);
                                    } else {
                                        // 相对路径
                                        String base = currentTarget.getProtocol() + "://" + currentTarget.getHost();
                                        if ((currentTarget.getProtocol().equals("http")
                                                && currentTarget.getPort() != 80) ||
                                                (currentTarget.getProtocol().equals("https")
                                                        && currentTarget.getPort() != 443)) {
                                            base += ":" + currentTarget.getPort();
                                        }
                                        if (!location.startsWith("/")) {
                                            location = "/" + location;
                                        }
                                        redirectUrl = new java.net.URL(base + location);
                                    }

                                    // 构建新请求
                                    String newProtocol = redirectUrl.getProtocol();
                                    String newHost = redirectUrl.getHost();
                                    int newPort = redirectUrl.getPort();
                                    if (newPort == -1) {
                                        newPort = "https".equals(newProtocol) ? 443 : 80;
                                    }
                                    String newPath = redirectUrl.getPath();
                                    if (newPath == null || newPath.isEmpty())
                                        newPath = "/";
                                    if (redirectUrl.getQuery() != null) {
                                        newPath += "?" + redirectUrl.getQuery();
                                    }

                                    currentTarget = Utils.helpers.buildHttpService(newHost, newPort, newProtocol);

                                    // 303 强制 GET，其他保持方法
                                    String method = (statusCode == 303) ? "GET"
                                            : Utils.helpers.analyzeRequest(finalBytes).getMethod();
                                    List<String> newHeaders = new ArrayList<>();
                                    newHeaders.add(method + " " + newPath + " HTTP/1.1");
                                    newHeaders.add("Host: " + newHost
                                            + (newPort != 80 && newPort != 443 ? ":" + newPort : ""));

                                    // 复制原有 headers（除了 Host）
                                    List<String> oldHeaders = Utils.helpers.analyzeRequest(finalBytes).getHeaders();
                                    for (int i = 1; i < oldHeaders.size(); i++) {
                                        String h = oldHeaders.get(i);
                                        if (!h.toLowerCase().startsWith("host:")
                                                && !h.toLowerCase().startsWith("content-length:")) {
                                            newHeaders.add(h);
                                        }
                                    }

                                    // 303 不带 body
                                    byte[] body = (statusCode == 303) ? new byte[0]
                                            : Arrays.copyOfRange(finalBytes,
                                                    Utils.helpers.analyzeRequest(finalBytes).getBodyOffset(),
                                                    finalBytes.length);

                                    finalBytes = Utils.helpers.buildHttpMessage(newHeaders, body);
                                    redirectCount++;
                                    continue;
                                } catch (Exception e) {
                                    break; // 解析失败，停止重定向
                                }
                            }
                        }
                    }
                    break; // 不是重定向或不跟随，退出循环
                }

                if (isCancelled)
                    return;

                final byte[] finalRespBytes = respBytes;
                final byte[] finalReqBytes = finalBytes;
                final IHttpRequestResponse finalResp = resp;
                final int finalRedirectCount = redirectCount;
                long durationMs = (System.nanoTime() - startNs) / 1_000_000L;

                SwingUtilities.invokeLater(() -> {
                    if (finalRespBytes == null) {
                        currentResponseBytes = new byte[0];
                        responseViewer.setMessage(new byte[0], false);
                    } else {
                        currentResponseBytes = finalRespBytes;
                        responseViewer.setMessage(finalRespBytes, false);
                    }

                    HistoryEntry e = new HistoryEntry();
                    e.id = (++historySeq);
                    e.time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                    e.durationMs = durationMs;
                    e.requestBytes = finalReqBytes;
                    e.responseBytes = finalRespBytes == null ? new byte[0] : finalRespBytes;
                    if (finalRespBytes != null) {
                        e.status = Utils.helpers.analyzeResponse(finalRespBytes).getStatusCode();
                        e.length = finalRespBytes.length;
                    } else {
                        e.status = 0;
                        e.length = 0;
                    }
                    e.requestResponse = finalResp;
                    try {
                        IRequestInfo reqInfo = Utils.helpers.analyzeRequest(finalReqBytes);
                        e.method = reqInfo.getMethod();
                        java.net.URL url = reqInfo.getUrl();
                        if (url != null) {
                            e.path = url.getPath();
                            if (url.getQuery() != null && !url.getQuery().isEmpty()) {
                                e.path += "?" + url.getQuery();
                            }
                        }
                    } catch (Exception ignored) {
                    }

                    addHistoryEntry(e);

                    if (finalResp != null) {
                        addToDataboard(finalResp);
                    }

                    if (statusLabel != null) {
                        String statusText;
                        if (finalRespBytes != null) {
                            statusText = String.format(
                                    "Status: %d | Time: %dms | Req: %s | Resp: %s%s",
                                    e.status,
                                    durationMs,
                                    formatSize(finalReqBytes.length),
                                    formatSize(finalRespBytes.length),
                                    finalRedirectCount > 0 ? " | Redirects: " + finalRedirectCount : "");
                        } else {
                            statusText = String.format(
                                    "Status: (none) | Time: %dms | Req: %s | Resp: 0B",
                                    durationMs,
                                    formatSize(finalReqBytes.length));
                        }
                        statusLabel.setText(statusText);
                    }
                });
            } catch (Exception ex) {
                if (isCancelled)
                    return;
                long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
                SwingUtilities.invokeLater(() -> {
                    responseViewer.setMessage(("Error: " + ex.getMessage()).getBytes(StandardCharsets.UTF_8), false);
                    if (statusLabel != null) {
                        statusLabel.setText("Error | Time: " + durationMs + "ms");
                    }
                });
            } finally {
                sendThread = null;
                SwingUtilities.invokeLater(() -> {
                    if (sendBtn != null) {
                        sendBtn.setEnabled(true);
                        setSenderMode(senderMode);
                    }
                    if (cancelBtn != null) {
                        cancelBtn.setEnabled(false);
                    }
                });
            }
        });
        sendThread.start();
    }

    /**
     * 通过 RawSocketSender 发送原始字节，绕开 Burp 的客户端规范化。
     * Ghost Bits 漏洞复现的标准路径。失败时同样把 sent bytes 写入 History 供 diff。
     */
    private void sendViaRawSocket(byte[] rawReq, String host, int port, boolean https, long startNs) {
        byte[] finalBytes;
        try {
            finalBytes = buildRequestBytesForSending(rawReq);
        } catch (Exception buildErr) {
            handleRawFailure(rawReq, host, port, https, startNs, buildErr,
                    "build request bytes failed");
            return;
        }
        if (isCancelled)
            return;

        try {
            RawSocketSender sender = new RawSocketSender();
            RawSocketSender.RawResponse rr = sender.send(host, port, https, finalBytes, 5000, 5000);

            if (isCancelled)
                return;
            final byte[] respBytes = rr.getResponseBytes();
            final byte[] sentBytes = rr.getRequestBytesActuallySent();
            final long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
            final int statusCode = rr.getStatusCode();

            SwingUtilities.invokeLater(() -> {
                if (respBytes == null || respBytes.length == 0) {
                    currentResponseBytes = new byte[0];
                    responseViewer.setMessage(new byte[0], false);
                } else {
                    currentResponseBytes = respBytes;
                    responseViewer.setMessage(respBytes, false);
                }

                HistoryEntry e = newRawHistoryEntry(sentBytes, respBytes, durationMs,
                        (short) statusCode, respBytes == null ? 0 : respBytes.length);
                addHistoryEntry(e);

                if (statusLabel != null) {
                    String statusText = String.format(
                            "[Raw] Status: %d | Time: %dms | Req: %s | Resp: %s",
                            statusCode,
                            durationMs,
                            formatSize(sentBytes.length),
                            formatSize(respBytes == null ? 0 : respBytes.length));
                    statusLabel.setText(statusText);
                }
            });
        } catch (Exception ex) {
            if (isCancelled)
                return;
            handleRawFailure(finalBytes, host, port, https, startNs, ex, null);
        } finally {
            sendThread = null;
            SwingUtilities.invokeLater(() -> {
                if (sendBtn != null) {
                    sendBtn.setEnabled(true);
                    setSenderMode(senderMode);
                }
                if (cancelBtn != null) {
                    cancelBtn.setEnabled(false);
                }
            });
        }
    }

    /**
     * Raw 发送失败的统一处理：把已经准备好的 sent bytes 也写进 History，方便用户对比 wire bytes。
     * Ghost Bits 调试最痛的就是失败时看不到发了啥，所以这里必须保留。
     */
    private void handleRawFailure(byte[] sentBytes, String host, int port, boolean https,
            long startNs, Throwable ex, String prefix) {
        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        final String msg = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
        final String displayMsg = prefix == null || prefix.isEmpty() ? msg : prefix + ": " + msg;
        final byte[] safeSent = sentBytes == null ? new byte[0] : sentBytes;
        final long durMs = durationMs;
        final String target = (https ? "https://" : "http://") + host + ":" + port;

        // 失败响应 body 同时包含人类可读错误 + 实际发送字节的 hex 摘要，便于 History 单击查看
        StringBuilder body = new StringBuilder();
        body.append("Raw Socket Error: ").append(displayMsg).append('\n');
        body.append("Target: ").append(target).append('\n');
        body.append("Sent bytes: ").append(safeSent.length).append('\n');
        body.append("Hex (first 256): ").append(toHexShort(safeSent, 256)).append('\n');
        byte[] respPlaceholder = ("HTTP/1.1 0 Raw Socket Error\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8);

        SwingUtilities.invokeLater(() -> {
            responseViewer.setMessage(respPlaceholder, false);

            HistoryEntry e = newRawHistoryEntry(safeSent, respPlaceholder, durMs, (short) 0,
                    respPlaceholder.length);
            addHistoryEntry(e);

            if (statusLabel != null) {
                statusLabel.setText("[Raw] Error | Time: " + durMs + "ms | " + displayMsg);
            }
        });
    }

    private HistoryEntry newRawHistoryEntry(byte[] sentBytes, byte[] respBytes,
            long durationMs, short statusCode, int respLen) {
        HistoryEntry e = new HistoryEntry();
        e.id = (++historySeq);
        e.time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        e.durationMs = durationMs;
        e.requestBytes = sentBytes;
        e.responseBytes = respBytes == null ? new byte[0] : respBytes;
        e.status = statusCode;
        e.length = respLen;
        e.sender = "Raw";
        e.requestResponse = null;

        try {
            int len = Math.min(sentBytes.length, 256);
            String head = new String(sentBytes, 0, len, StandardCharsets.UTF_8);
            int firstSpace = head.indexOf(' ');
            int secondSpace = head.indexOf(' ', firstSpace + 1);
            if (firstSpace > 0 && secondSpace > firstSpace) {
                e.method = head.substring(0, firstSpace);
                e.path = head.substring(firstSpace + 1, secondSpace);
            }
        } catch (Exception ignored) {
        }
        return e;
    }

    private static String toHexShort(byte[] bytes, int max) {
        if (bytes == null || bytes.length == 0)
            return "";
        int len = Math.min(bytes.length, max);
        StringBuilder sb = new StringBuilder(len * 3);
        for (int i = 0; i < len; i++) {
            if (i > 0)
                sb.append(' ');
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        if (bytes.length > max)
            sb.append(" …(+").append(bytes.length - max).append(" bytes)");
        return sb.toString();
    }

    private String getHeaderValue(byte[] response, String headerName) {
        if (response == null)
            return null;
        try {
            IResponseInfo info = Utils.helpers.analyzeResponse(response);
            for (String h : info.getHeaders()) {
                if (h.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                    return h.substring(headerName.length() + 1).trim();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String formatSize(int size) {
        if (size < 1024)
            return size + "B";
        if (size < 1024 * 1024)
            return String.format("%.1fKB", size / 1024.0);
        return String.format("%.1fMB", size / 1024.0 / 1024.0);
    }

    private void addHistoryEntry(HistoryEntry entry) {
        historyEntries.add(0, entry);
        if (historyEntries.size() > MAX_HISTORY_SIZE) {
            historyEntries.subList(MAX_HISTORY_SIZE, historyEntries.size()).clear();
        }
        historyModel.fireTableDataChanged();
    }

    private void addToDataboard(IHttpRequestResponse response) {
        try {
            byte[] respBytes = response.getResponse();
            if (respBytes == null)
                return;
            short statusCode = Utils.helpers.analyzeResponse(respBytes).getStatusCode();
            String title = Utils.getBodyTitle(new String(respBytes, StandardCharsets.UTF_8));
            String reason = String.format("manual send; status:%d", statusCode);
            Utils.panel.getBypassTableModel().addBypass(new Bypass(
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                    Utils.helpers.analyzeRequest(response).getMethod(),
                    String.valueOf(respBytes.length),
                    Utils.callbacks.saveBuffersToTempFiles(response),
                    Utils.helpers.analyzeRequest(response).getUrl(),
                    statusCode,
                    Utils.helpers.analyzeResponse(respBytes).getStatedMimeType(),
                    title,
                    Utils.count++,
                    "manual waf",
                    reason));
        } catch (Exception ignored) {
        }
    }

    private void showHistoryEntry(int index) {
        if (index < 0 || index >= historyEntries.size())
            return;
        byte[] resp = historyEntries.get(index).responseBytes;
        if (resp == null)
            resp = new byte[0];
        currentResponseBytes = resp;
        responseViewer.setMessage(resp, false);
    }

    // --- Public API ---
    public void loadRequest(IHttpRequestResponse requestResponse) {
        if (requestResponse == null)
            return;
        currentHttpService = requestResponse.getHttpService();
        if (currentHttpService != null) {
            if (hostField != null)
                hostField.setText(currentHttpService.getHost());
            if (portField != null)
                portField.setText(String.valueOf(currentHttpService.getPort()));
            if (httpsCheckBox != null)
                httpsCheckBox.setSelected("https".equalsIgnoreCase(currentHttpService.getProtocol()));
        }

        byte[] req = requestResponse.getRequest();
        if (req != null) {
            requestViewer.setMessage(req, true);
            originalRequest = Arrays.copyOf(req, req.length);
            undoStack.clear();
            redoStack.clear();
            updateUndoRedoButtons();
        }

        byte[] resp = requestResponse.getResponse();
        if (resp != null) {
            currentResponseBytes = resp;
            responseViewer.setMessage(resp, false);
        } else {
            currentResponseBytes = new byte[0];
            responseViewer.setMessage(new byte[0], false);
        }
    }

    // --- IMessageEditorController ---
    @Override
    public IHttpService getHttpService() {
        return currentHttpService;
    }

    @Override
    public byte[] getRequest() {
        return getRequestBytes();
    }

    @Override
    public byte[] getResponse() {
        return currentResponseBytes;
    }

    // --- Bytes ---
    private byte[] getRequestBytes() {
        byte[] msg = requestViewer == null ? null : requestViewer.getMessage();
        return msg == null ? new byte[0] : msg;
    }

    private void setRequestBytes(byte[] msg) {
        if (msg == null)
            msg = new byte[0];
        if (requestViewer != null)
            requestViewer.setMessage(msg, true);
    }

    private String getRequestTextISO() {
        return new String(getRequestBytes(), StandardCharsets.ISO_8859_1);
    }

    private void setRequestTextISO(String text) {
        if (text == null)
            text = "";
        setRequestBytes(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private byte[] getSelectedRequestBytes() {
        if (requestViewer == null)
            return new byte[0];
        byte[] sel = requestViewer.getSelectedData();
        return sel == null ? new byte[0] : sel;
    }

    /**
     * 从 JTextComponent 拿用户当前框选的字节偏移 [start, end)。
     * 拿不到（Hex 视图、无焦点、无选区）时返回 null，调用方走降级路径。
     */
    private int[] getSelectionRange() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return null;
        }
        int start = editor.getSelectionStart();
        int end = editor.getSelectionEnd();
        if (start == end) {
            return null;
        }
        return new int[] { start, end };
    }

    /**
     * 拿当前 request 编辑器的 caret 位置（字节偏移）。
     * 注意：JTextComponent.getCaretPosition() 返回字符偏移，但本工程
     * 在 ISO-8859-1 下用 1:1 字符<->字节映射，二者等价。
     * 拿不到（Hex 视图、无 JTextComponent）时返回 -1。
     */
    private int getRequestCaret() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return -1;
        }
        return editor.getCaretPosition();
    }

    /** msg[offset..offset+target.length) == target 的逐字节比较。offset 越界返回 false。 */
    private static boolean bytesMatchAt(byte[] msg, int offset, byte[] target) {
        if (msg == null || target == null || offset < 0 || offset + target.length > msg.length) {
            return false;
        }
        for (int i = 0; i < target.length; i++) {
            if (msg[offset + i] != target[i]) {
                return false;
            }
        }
        return true;
    }

    private boolean replaceOccurrenceInRequest(byte[] target, byte[] replacement) {
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, target);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "未找到选中文本在请求中的位置", I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return false;
        }

        // 唯一匹配：无需交互
        if (positions.size() == 1) {
            replaceAtIndex(msg, positions.get(0), target.length, replacement);
            return true;
        }

        Integer selectionIdx = resolveSelectionIndex(msg, target);

        List<String> optionList = new ArrayList<>();
        String selectionOption = null;
        if (selectionIdx != null) {
            selectionOption = "选区处";
            optionList.add(selectionOption);
        }
        String allOption = "全部 (" + positions.size() + " 处)";
        optionList.add(allOption);
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i);
            String context = getContextSnippet(msg, pos, target.length, 20);
            optionList.add("第 " + (i + 1) + " 处: ..." + context + "...");
        }
        String[] options = optionList.toArray(new String[0]);

        Object choice = JOptionPane.showInputDialog(
                this,
                "请求中有 " + positions.size() + " 处匹配，选择作用域：",
                "作用域",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (choice == null) {
            return false;
        }

        String choiceStr = choice.toString();
        if (selectionOption != null && choiceStr.equals(selectionOption)) {
            replaceAtIndex(msg, selectionIdx, target.length, replacement);
            return true;
        }
        if (choiceStr.equals(allOption)) {
            replaceAllOccurrences(msg, positions, target.length, replacement);
            return true;
        }
        int headerCount = (selectionOption != null ? 1 : 0) + 1;
        for (int i = 0; i < positions.size(); i++) {
            if (choiceStr.equals(options[headerCount + i])) {
                replaceAtIndex(msg, positions.get(i), target.length, replacement);
                return true;
            }
        }
        return false;
    }

    /**
     * 如果用户有明确选区，并且选区字节恰好等于 target，返回选区起点；否则返回 null。
     * 用于在多匹配弹框中作为"选区处"一键选项。
     * 降级场景：Hex 视图 / 多字节偏移不一致 / 选区字节对不上 target。
     */
    private Integer resolveSelectionIndex(byte[] msg, byte[] target) {
        int[] range = getSelectionRange();
        if (range == null) {
            return null;
        }
        int start = range[0];
        int len = range[1] - start;
        if (len != target.length) {
            return null;
        }
        if (!bytesMatchAt(msg, start, target)) {
            return null;
        }
        return start;
    }

    private void replaceAtIndex(byte[] msg, int idx, int targetLen, byte[] replacement) {
        byte[] out = new byte[msg.length - targetLen + replacement.length];
        System.arraycopy(msg, 0, out, 0, idx);
        System.arraycopy(replacement, 0, out, idx, replacement.length);
        System.arraycopy(msg, idx + targetLen, out, idx + replacement.length, msg.length - (idx + targetLen));
        pendingRequestCaretPosition = idx + replacement.length;
        setRequestBytes(out);
    }

    private void replaceAllOccurrences(byte[] msg, List<Integer> positions, int targetLen, byte[] replacement) {
        // 从后往前替换，避免位置偏移
        byte[] current = msg;
        for (int i = positions.size() - 1; i >= 0; i--) {
            int pos = positions.get(i);
            byte[] out = new byte[current.length - targetLen + replacement.length];
            System.arraycopy(current, 0, out, 0, pos);
            System.arraycopy(replacement, 0, out, pos, replacement.length);
            System.arraycopy(current, pos + targetLen, out, pos + replacement.length,
                    current.length - (pos + targetLen));
            current = out;
        }
        pendingRequestCaretPosition = current.length;
        setRequestBytes(current);
    }

    private List<Integer> findAllOccurrences(byte[] haystack, byte[] needle) {
        List<Integer> result = new ArrayList<>();
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length) {
            return result;
        }
        int idx = 0;
        while (idx <= haystack.length - needle.length) {
            int found = indexOfFrom(haystack, needle, idx);
            if (found < 0)
                break;
            result.add(found);
            idx = found + needle.length; // 不允许重叠匹配
        }
        return result;
    }

    private static int indexOfFrom(byte[] haystack, byte[] needle, int fromIndex) {
        if (haystack == null || needle == null || needle.length == 0)
            return -1;
        outer: for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }

    private String getContextSnippet(byte[] msg, int pos, int targetLen, int contextLen) {
        int start = Math.max(0, pos - contextLen);
        int end = Math.min(msg.length, pos + targetLen + contextLen);

        StringBuilder sb = new StringBuilder();
        if (start > 0)
            sb.append("");
        for (int i = start; i < pos; i++) {
            sb.append(safeChar(msg[i]));
        }
        sb.append("[");
        for (int i = pos; i < pos + targetLen && i < msg.length; i++) {
            sb.append(safeChar(msg[i]));
        }
        sb.append("]");
        for (int i = pos + targetLen; i < end; i++) {
            sb.append(safeChar(msg[i]));
        }
        if (end < msg.length)
            sb.append("");
        return sb.toString();
    }

    private char safeChar(byte b) {
        int c = b & 0xFF;
        if (c == '\r')
            return '↵';
        if (c == '\n')
            return '↓';
        if (c == '\t')
            return '→';
        if (c < 0x20 || c >= 0x7F)
            return '·';
        return (char) c;
    }

    /**
     * 纯生成插入入口：光标处插入（caret 优先），拿不到 caret 时回退选区路径。
     * 适用于 Dirty/Null/Atoms 区这类"插入物与选中内容无关"的按钮——选区不参与运算，
     * 不应该强制要求用户先选一段。Hex 视图等无 JTextComponent 的场景才走兜底。
     */
    private void insertAtCaretOrFallback(byte[] insert) {
        int caret = getRequestCaret();
        byte[] msg = getRequestBytes();
        if (caret >= 0 && caret <= msg.length) {
            performInsert(msg, caret, insert);
            return;
        }
        insertIntoSelectionOrWarn(insert, true);
    }

    private void insertIntoSelectionOrWarn(byte[] insert, boolean beforeSelection) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中插入位置", I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, sel);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "未找到选中文本在请求中的位置", I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int chosenIdx;
        if (positions.size() == 1) {
            chosenIdx = positions.get(0);
        } else {
            Integer selectionIdx = resolveSelectionIndex(msg, sel);
            List<String> optionList = new ArrayList<>();
            String selectionOption = null;
            if (selectionIdx != null) {
                selectionOption = "选区处";
                optionList.add(selectionOption);
            }
            for (int i = 0; i < positions.size(); i++) {
                int pos = positions.get(i);
                String context = getContextSnippet(msg, pos, sel.length, 20);
                optionList.add("第 " + (i + 1) + " 处: ..." + context + "...");
            }
            String[] options = optionList.toArray(new String[0]);

            Object choice = JOptionPane.showInputDialog(
                    this,
                    "请求中有 " + positions.size() + " 处匹配，选择作用域：",
                    "作用域",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);

            if (choice == null)
                return;

            String choiceStr = choice.toString();
            if (selectionOption != null && choiceStr.equals(selectionOption)) {
                chosenIdx = selectionIdx;
            } else {
                chosenIdx = -1;
                int headerCount = (selectionOption != null ? 1 : 0);
                for (int i = 0; i < positions.size(); i++) {
                    if (choiceStr.equals(options[headerCount + i])) {
                        chosenIdx = positions.get(i);
                        break;
                    }
                }
                if (chosenIdx < 0)
                    return;
            }
        }

        int insertPos = beforeSelection ? chosenIdx : (chosenIdx + sel.length);
        performInsert(msg, insertPos, insert);
    }

    /** 在 msg 的 insertPos 处插入 insert，设置光标到插入内容末尾，写回 request。 */
    private void performInsert(byte[] msg, int insertPos, byte[] insert) {
        byte[] out = new byte[msg.length + insert.length];
        System.arraycopy(msg, 0, out, 0, insertPos);
        System.arraycopy(insert, 0, out, insertPos, insert.length);
        System.arraycopy(msg, insertPos, out, insertPos + insert.length, msg.length - insertPos);
        pendingRequestCaretPosition = insertPos + insert.length;
        setRequestBytes(out);
    }

    // --- Dirty tags ---
    private byte[] buildRequestBytesForSending(byte[] originalRequestBytes) {
        if (originalRequestBytes == null)
            return new byte[0];

        SplitBytes split = splitRequestBytes(originalRequestBytes);
        if (split == null) {
            // 不是标准的 header/body 结构：只展开占位符，不做 CL 修正
            return expandWholeBytesWithTags(originalRequestBytes);
        }

        boolean tamperedCL = isContentLengthTampered(originalRequestBytes);

        // 展开 headers（通常很小）+ body（流式）
        String headersStr = new String(split.headersBytes, StandardCharsets.ISO_8859_1);
        headersStr = expandInlineTags(headersStr);

        String bodyStr = new String(split.bodyBytes, StandardCharsets.ISO_8859_1);
        boolean binary = hasHeaderContains(headersStr, "Content-Encoding", "gzip") || looksBinaryBody(bodyStr);
        byte[] bodyExpanded = buildBodyBytesWithTags(bodyStr,
                binary ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_8);

        if (tamperedCL) {
            // 用户刻意篡改了 Content-Length：保留 Header 不动，只在 body 里展开 dirty/null 占位符
            return concatRequest(headersStr.getBytes(StandardCharsets.ISO_8859_1), split.delimiterBytes, bodyExpanded);
        }

        String lineEnd = split.lineEnd;
        String newHeaders = headersStr;

        boolean hasTE = hasHeaderName(newHeaders, "Transfer-Encoding");
        boolean hasCL = hasHeaderName(newHeaders, "Content-Length");

        if (hasCL) {
            // 用户没篡改 CL，但 dirty 展开后长度变了：自动更新 CL；同时移除 TE，避免 CL-TE 冲突
            newHeaders = removeHeaderLine(newHeaders, "Transfer-Encoding", lineEnd);
            newHeaders = upsertHeaderLine(newHeaders, "Content-Length", String.valueOf(bodyExpanded.length), lineEnd);
        } else if (!hasTE) {
            // 没有 TE，也没有 CL：补齐 CL
            newHeaders = upsertHeaderLine(newHeaders, "Content-Length", String.valueOf(bodyExpanded.length), lineEnd);
        } else {
            // 有 TE 且无 CL：按用户意图保留（不强行加 CL），只展开 body
        }

        return concatRequest(newHeaders.getBytes(StandardCharsets.ISO_8859_1), split.delimiterBytes, bodyExpanded);
    }

    private boolean hasHeaderName(String headers, String headerName) {
        if (headers == null)
            return false;
        String[] lines = headers.split("\\r?\\n", -1);
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":"))
                return true;
        }
        return false;
    }

    private boolean isContentLengthTampered(byte[] requestBytes) {
        SplitBytes split = splitRequestBytes(requestBytes);
        if (split == null)
            return false;
        String headers = new String(split.headersBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headers.split("\\r?\\n", -1);
        int declared = -1;
        for (String line : lines) {
            if (line.toLowerCase().startsWith("content-length:")) {
                try {
                    declared = Integer.parseInt(line.split(":", 2)[1].trim());
                } catch (Exception e) {
                    return true; // 畸形 CL：视为篡改，不乱动
                }
                break;
            }
        }
        if (declared < 0)
            return false; // 没有 CL
        return declared != split.bodyBytes.length;
    }

    private byte[] expandWholeBytesWithTags(byte[] requestBytes) {
        String s = new String(requestBytes, StandardCharsets.ISO_8859_1);
        // headers/body 不明时，只做基础展开（headers 很可能存在 dirty）
        String expanded = expandInlineTags(s);
        return expanded.getBytes(StandardCharsets.ISO_8859_1);
    }

    private byte[] concatRequest(byte[] headersBytes, byte[] delimiterBytes, byte[] bodyBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(headersBytes);
            out.write(delimiterBytes);
            out.write(bodyBytes);
        } catch (Exception ignored) {
        }
        return out.toByteArray();
    }

    private static class SplitBytes {
        byte[] headersBytes;
        byte[] bodyBytes;
        byte[] delimiterBytes;
        String lineEnd;
    }

    private SplitBytes splitRequestBytes(byte[] requestBytes) {
        if (requestBytes == null)
            return null;
        int idx = indexOfBytes(requestBytes, new byte[] { '\r', '\n', '\r', '\n' });
        byte[] delimiter;
        String lineEnd;
        int sepLen;
        if (idx >= 0) {
            delimiter = new byte[] { '\r', '\n', '\r', '\n' };
            lineEnd = "\r\n";
            sepLen = 4;
        } else {
            idx = indexOfBytes(requestBytes, new byte[] { '\n', '\n' });
            if (idx < 0)
                return null;
            delimiter = new byte[] { '\n', '\n' };
            lineEnd = "\n";
            sepLen = 2;
        }
        SplitBytes split = new SplitBytes();
        split.headersBytes = Arrays.copyOfRange(requestBytes, 0, idx);
        split.bodyBytes = Arrays.copyOfRange(requestBytes, idx + sepLen, requestBytes.length);
        split.delimiterBytes = delimiter;
        split.lineEnd = lineEnd;
        return split;
    }

    private int indexOfBytes(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length)
            return -1;
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }

    private void updateOrAddHeader(List<String> headers, String name, String value) {
        if (headers == null || headers.isEmpty())
            return;
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                headers.set(i, name + ": " + value);
                return;
            }
        }
        headers.add(name + ": " + value);
    }

    private void removeHeaderIgnoreCase(List<String> headers, String name) {
        if (headers == null || headers.size() <= 1)
            return;
        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i);
            if (h.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                headers.remove(i);
            }
        }
    }

    private int findHeaderIndex(List<String> headers, String name) {
        if (headers == null || name == null) {
            return -1;
        }
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null)
                continue;
            int colon = h.indexOf(':');
            if (colon <= 0)
                continue;
            if (h.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -1;
    }

    private String expandInlineTags(String input) {
        if (input == null || input.isEmpty())
            return input;
        String out = input;
        out = replaceDirtyTag(out, TAG_DIRTY, false);
        out = replaceDirtyTag(out, TAG_DIRTY_NULL, true);
        return out;
    }

    private String replaceDirtyTag(String input, Pattern pattern, boolean isNull) {
        Matcher m = pattern.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            int count;
            try {
                count = Integer.parseInt(m.group(1));
            } catch (Exception e) {
                count = 0;
            }
            if (count <= 0) {
                m.appendReplacement(sb, "");
                continue;
            }
            String replacement;
            if (isNull) {
                char[] zeros = new char[count];
                Arrays.fill(zeros, '\0');
                replacement = new String(zeros);
            } else {
                Random r = new Random();
                StringBuilder s = new StringBuilder(count);
                for (int i = 0; i < count; i++) {
                    s.append(r.nextInt(10));
                }
                replacement = s.toString();
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private byte[] buildBodyBytesWithTags(String body, Charset charsetForText) {
        if (body == null || body.isEmpty())
            return new byte[0];
        if (!body.contains("{{")) {
            return body.getBytes(charsetForText);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int idx = 0;
        while (idx < body.length()) {
            Matcher m1 = TAG_DIRTY.matcher(body);
            Matcher m2 = TAG_DIRTY_NULL.matcher(body);
            boolean f1 = m1.find(idx);
            boolean f2 = m2.find(idx);

            if (!f1 && !f2) {
                writeText(out, body.substring(idx), charsetForText);
                break;
            }

            Matcher chosen;
            boolean isNull;
            if (f1 && f2) {
                if (m1.start() <= m2.start()) {
                    chosen = m1;
                    isNull = false;
                } else {
                    chosen = m2;
                    isNull = true;
                }
            } else if (f1) {
                chosen = m1;
                isNull = false;
            } else {
                chosen = m2;
                isNull = true;
            }

            int start = chosen.start();
            int end = chosen.end();
            if (start > idx) {
                writeText(out, body.substring(idx, start), charsetForText);
            }

            int count;
            try {
                count = Integer.parseInt(chosen.group(1));
            } catch (Exception e) {
                count = 0;
            }
            if (count > 0) {
                if (isNull)
                    writeNullBytes(out, count);
                else
                    writeRandomDigits(out, count);
            }
            idx = end;
        }

        return out.toByteArray();
    }

    private void writeText(ByteArrayOutputStream out, String s, Charset cs) {
        if (s == null || s.isEmpty())
            return;
        try {
            out.write(s.getBytes(cs));
        } catch (Exception ignored) {
        }
    }

    private void writeNullBytes(ByteArrayOutputStream out, int count) {
        if (count <= 0)
            return;
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    private void writeRandomDigits(ByteArrayOutputStream out, int count) {
        if (count <= 0)
            return;
        Random r = new Random();
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            for (int i = 0; i < n; i++)
                buf[i] = (byte) ('0' + r.nextInt(10));
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    // --- History ---
    static class HistoryEntry {
        int id;
        short status;
        int length;
        String time;
        String method;
        String path;
        long durationMs;
        byte[] requestBytes;
        byte[] responseBytes;
        IHttpRequestResponse requestResponse;
        /** "Burp" / "Raw"，用于区分发送通道 */
        String sender = "Burp";
    }

    class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = { "#", "Sender", "Method", "Path", "Status", "Length", "Time(ms)", "Clock" };

        @Override
        public int getRowCount() {
            return historyEntries.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int col) {
            return columns[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            HistoryEntry e = historyEntries.get(row);
            switch (col) {
                case 0:
                    return e.id;
                case 1:
                    return e.sender != null ? e.sender : "Burp";
                case 2:
                    return e.method != null ? e.method : "";
                case 3:
                    return e.path != null ? (e.path.length() > 40 ? e.path.substring(0, 37) + "..." : e.path) : "";
                case 4:
                    return e.status;
                case 5:
                    return e.length;
                case 6:
                    return e.durationMs;
                case 7:
                    return e.time;
                default:
                    return "";
            }
        }
    }
}
