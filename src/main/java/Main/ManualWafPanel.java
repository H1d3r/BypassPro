package Main;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
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
import java.util.Random;
import java.util.Stack;
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
    private byte[] lastSavedState = new byte[0];

    private JTextField hostField;
    private JTextField portField;
    private JCheckBox httpsCheckBox;
    private JCheckBox followRedirectCheckBox;
    private JButton sendBtn;
    private JButton cancelBtn;
    private JLabel statusLabel;
    private volatile boolean isCancelled = false;
    private volatile Thread sendThread = null;

    private static final Pattern TAG_DIRTY = Pattern.compile("\\{\\{\\s*dirty\\((\\d+)\\)\\s*\\}\\}");
    private static final Pattern TAG_DIRTY_NULL = Pattern.compile("\\{\\{\\s*dirtynull\\((\\d+)\\)\\s*\\}\\}");

    public ManualWafPanel() {
        setLayout(new BorderLayout());

        JPanel toolbar = createToolbar();

        // Request | Response
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.5);

        JPanel requestPanel = new JPanel(new BorderLayout());
        JLabel reqLabel = new JLabel("  Request (Raw/Hex)");
        reqLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        reqLabel.setBorder(new EmptyBorder(5, 0, 5, 0));
        requestViewer = Utils.callbacks.createMessageEditor(this, true);
        requestPanel.add(reqLabel, BorderLayout.NORTH);
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        JLabel respLabel = new JLabel("  Response (Raw/Hex/Render)");
        respLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        respLabel.setBorder(new EmptyBorder(5, 0, 5, 0));
        responseViewer = Utils.callbacks.createMessageEditor(this, false);
        responsePanel.add(respLabel, BorderLayout.NORTH);
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        mainSplit.setLeftComponent(requestPanel);
        mainSplit.setRightComponent(responsePanel);

        // Bottom: Tools | History
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplit.setResizeWeight(0.6);
        bottomSplit.setLeftComponent(createTransformPanel());
        bottomSplit.setRightComponent(createHistoryPanel());
        bottomSplit.setPreferredSize(new Dimension(0, 180));

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(mainSplit);
        verticalSplit.setBottomComponent(bottomSplit);
        verticalSplit.setResizeWeight(0.7);

        add(toolbar, BorderLayout.NORTH);
        add(verticalSplit, BorderLayout.CENTER);
        add(createStatusPanel(), BorderLayout.SOUTH);

        setupShortcuts();
    }

    private JPanel createStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusPanel.setBorder(BorderFactory.createEtchedBorder());
        statusLabel = new JLabel("Ready");
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
        sendBtn.addActionListener(e -> sendRequest());

        cancelBtn = new JButton("Cancel");
        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> cancelRequest());

        JButton undoBtn = new JButton("←");
        JButton redoBtn = new JButton("→");
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
        left.add(cancelBtn);
        left.add(Box.createHorizontalStrut(10));
        left.add(undoBtn);
        left.add(redoBtn);
        left.add(resetBtn);
        left.add(Box.createHorizontalStrut(10));
        left.add(followRedirectCheckBox);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        right.add(new JLabel("Host:"));
        hostField = new JTextField(16);
        right.add(hostField);
        right.add(new JLabel("Port:"));
        portField = new JTextField(5);
        right.add(portField);
        httpsCheckBox = new JCheckBox("HTTPS");
        right.add(httpsCheckBox);

        toolbar.add(left, BorderLayout.WEST);
        toolbar.add(right, BorderLayout.EAST);
        return toolbar;
    }

    private void cancelRequest() {
        isCancelled = true;
        if (sendThread != null) {
            sendThread.interrupt();
        }
        SwingUtilities.invokeLater(() -> {
            if (sendBtn != null) {
                sendBtn.setEnabled(true);
                sendBtn.setText("Send");
            }
            if (cancelBtn != null) {
                cancelBtn.setEnabled(false);
            }
            if (statusLabel != null) {
                statusLabel.setText("Cancelled");
            }
        });
    }

    private void setupShortcuts() {
        if (requestViewer == null) return;
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

    private JPanel createTransformPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Transform Tools"));

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
        inner.setBorder(new EmptyBorder(5, 5, 5, 5));

        inner.add(createBlock("Encoding", "选中文本后编码/解码",
                createBtn("URL Enc", this::urlEncode),
                createBtn("URL Dec", this::urlDecode),
                createBtn("Double URL", this::doubleUrlEncode),
                createBtn("Base64", this::base64Encode),
                createBtn("Base64 Dec", this::base64Decode),
                createBtn("Hex", this::hexEncode),
                createBtn("\\uXXXX", this::toUnicodeEscape)
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Case", "选中文本后大小写转换",
                createBtn("UPPER", this::toUpper),
                createBtn("lower", this::toLower),
                createBtn("RaNdOm", this::toRandomCase)
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Unicode", "选中文本后 Unicode 变形",
                createBtn("Fullwidth", this::toFullwidth),
                createBtn("Homoglyph", this::toHomoglyph)
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("SQL Bypass", "选中 SQL 关键字后变形",
                createBtn("/**/包裹", this::sqlCommentWrap),
                createBtn("/*!50000*/", this::mysqlVersionComment),
                createBtn("Null分割", this::nullByteSplit)
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Path", "路径遍历变形",
                createBtn("....//", () -> transformSelection(s -> s.replace("../", "....//"))),
                createBtn("..%252f", () -> transformSelection(s -> s.replace("../", "..%252f"))),
                createBtn("..%c0%af", () -> transformSelection(s -> s.replace("../", "..%c0%af"))),
                createBtn("..\\\\", () -> transformSelection(s -> s.replace("../", "..\\\\")))
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Insert", "在选中文本之前插入字符",
                createBtn("%09", () -> insertAt("%09")),
                createBtn("%0a", () -> insertAt("%0a")),
                createBtn("%0d", () -> insertAt("%0d")),
                createBtn("%00", () -> insertAt("%00")),
                createBtn("/**/", () -> wrapWith("/**/", ""))
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Dirty Data", "插入占位符（发送时展开）",
                createBtn("Dirty(N)", this::insertDirtyData),
                createBtn("Null(N)", this::insertNullBytes)
        ));

        inner.add(Box.createVerticalStrut(8));
        inner.add(createBlock("Request", "对整个请求 Body 变换",
                createBtn("Gzip", this::gzipBody),
                createBtn("To Multipart", this::toMultipart),
                createBtn("UTF-16", () -> encodeBodyWithCharset("UTF-16")),
                createBtn("UTF-16BE", () -> encodeBodyWithCharset("UTF-16BE")),
                createBtn("UTF-16LE", () -> encodeBodyWithCharset("UTF-16LE")),
                createBtn("UTF-32", () -> encodeBodyWithCharset("UTF-32")),
                createBtn("UTF-32LE", () -> encodeBodyWithCharset("UTF-32LE")),
                createBtn("IBM037", () -> encodeBodyWithCharset("IBM037")),
                createBtn("cp290", () -> encodeBodyWithCharset("cp290")),
                createBtn("HTTP/1.0", this::switchToHttp10)
        ));

        inner.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(inner);
        scrollPane.setBorder(null);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createBlock(String title, String desc, JButton... buttons) {
        JPanel block = new JPanel();
        block.setLayout(new BoxLayout(block, BoxLayout.Y_AXIS));
        block.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                new EmptyBorder(2, 5, 5, 5)
        ));
        block.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel descLabel = new JLabel(desc);
        descLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        descLabel.setForeground(Color.GRAY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        block.add(descLabel);
        block.add(Box.createVerticalStrut(5));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 3));
        btnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (JButton btn : buttons) btnPanel.add(btn);
        block.add(btnPanel);

        return block;
    }

    private JButton createBtn(String text, Runnable action) {
        JButton btn = new JButton(text);
        btn.setMargin(new Insets(2, 6, 2, 6));
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.addActionListener(e -> {
            saveState();
            action.run();
        });
        return btn;
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
        if (!evt.isPopupTrigger()) return;
        int row = historyTable.rowAtPoint(evt.getPoint());
        if (row < 0) return;
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
        if (index < 0 || index >= historyEntries.size()) return;
        HistoryEntry entry = historyEntries.get(index);
        if (entry.requestBytes != null && entry.requestBytes.length > 0) {
            saveState();
            setRequestBytes(entry.requestBytes);
            if (statusLabel != null) {
                statusLabel.setText("已加载历史请求 #" + entry.id);
            }
        }
    }

    // --- Transform ---

    private void urlEncode() {
        transformSelection(s -> {
            try {
                return URLEncoder.encode(s, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return s;
            }
        });
    }

    private void urlDecode() {
        transformSelection(s -> {
            try {
                return URLDecoder.decode(s, "UTF-8");
            } catch (Exception e) {
                return s;
            }
        });
    }

    private void doubleUrlEncode() {
        transformSelection(s -> {
            try {
                return URLEncoder.encode(URLEncoder.encode(s, "UTF-8"), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return s;
            }
        });
    }

    private void base64Encode() {
        transformSelection(s -> Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)));
    }

    private void base64Decode() {
        transformSelection(s -> {
            try {
                return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
            } catch (Exception e) {
                return s;
            }
        });
    }

    private void hexEncode() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
                sb.append(String.format("%%%02X", b));
            }
            return sb.toString();
        });
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

    private void sqlCommentWrap() {
        transformSelection(s -> s.replaceAll("\\s+", "/**/"));
    }

    private void mysqlVersionComment() {
        transformSelection(s -> "/*!50000" + s + "*/");
    }

    private void nullByteSplit() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                sb.append(s.charAt(i));
                if (i < s.length() - 1) sb.append("%00");
            }
            return sb.toString();
        });
    }

    private void insertDirtyData() {
        String input = JOptionPane.showInputDialog(this, "输入脏数据长度（数字字符数量）:", "Dirty Data", JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty()) return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, "请输入大于 0 的数字", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertIntoSelectionOrWarn(("{{dirty(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1), true);
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "请输入有效数字", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void insertNullBytes() {
        String input = JOptionPane.showInputDialog(this, "输入 Null 字节数量:", "Null Bytes", JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty()) return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, "请输入大于 0 的数字", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertIntoSelectionOrWarn(("{{dirtynull(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1), true);
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "请输入有效数字", "错误", JOptionPane.ERROR_MESSAGE);
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
        if (bodyStart < 0) return null;
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
            if (sb.length() > 0) sb.append(lineEnd);
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
                    if (sb.length() > 0) sb.append(lineEnd);
                    sb.append(headerName).append(": ").append(headerValue);
                    found = true;
                }
                continue;
            }
            if (sb.length() > 0) sb.append(lineEnd);
            sb.append(line);
        }
        if (!found) {
            if (sb.length() > 0) sb.append(lineEnd);
            sb.append(headerName).append(": ").append(headerValue);
        }
        return sb.toString();
    }

    private boolean hasHeaderContains(String headers, String headerName, String needle) {
        if (headers == null) return false;
        String[] lines = headers.split("\\r?\\n", -1);
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                return line.toLowerCase().contains(needle.toLowerCase());
            }
        }
        return false;
    }

    private boolean looksBinaryBody(String body) {
        if (body == null || body.isEmpty()) return false;
        int sampleLen = Math.min(body.length(), 4096);
        int suspicious = 0;
        for (int i = 0; i < sampleLen; i++) {
            char c = body.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t') continue;
            if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) suspicious++;
        }
        return suspicious > (sampleLen * 0.10);
    }

    private void gzipBody() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, "请求体为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // 1) Header 检查
            for (String h : headers) {
                String hl = h.toLowerCase();
                if (hl.startsWith("content-encoding:") && hl.contains("gzip")) {
                    JOptionPane.showMessageDialog(this, "Header 显示已是 Gzip 格式，取消操作。", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }

            // 2) Magic bytes 检查：1F 8B
            if (body.length >= 2 && body[0] == (byte) 0x1F && body[1] == (byte) 0x8B) {
                int ret = JOptionPane.showConfirmDialog(
                        this,
                        "检测到 Body 似乎已经是 Gzip 格式 (Magic Bytes 1F 8B)。\n是否继续强制压缩？(可能导致双重压缩)",
                        "警告",
                        JOptionPane.YES_NO_OPTION
                );
                if (ret != JOptionPane.YES_OPTION) return;
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
            requestViewer.setMessage(newRequest, true);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Gzip 错误: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toMultipart() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, "请求内容为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }

            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, "请求体为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // 检查当前 Content-Type
            String currentCT = "";
            for (String h : headers) {
                if (h.toLowerCase().startsWith("content-type:")) {
                    currentCT = h.substring("content-type:".length()).trim().toLowerCase();
                    break;
                }
            }

            if (currentCT.contains("multipart/form-data")) {
                JOptionPane.showMessageDialog(this, "当前请求已是 Multipart 格式", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // 生成 boundary
            String boundary = "----BypassProBoundary" + System.currentTimeMillis();

            // 只有 application/x-www-form-urlencoded 才做真正的转换
            if (currentCT.contains("application/x-www-form-urlencoded")) {
                byte[] multipartBody = convertFormToMultipart(body, boundary, headers);
                if (multipartBody == null) {
                    JOptionPane.showMessageDialog(this, "转换失败：无法解析表单数据", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // 更新 Headers
                removeHeaderIgnoreCase(headers, "Content-Type");
                headers.add("Content-Type: multipart/form-data; boundary=" + boundary);
                removeHeaderIgnoreCase(headers, "Transfer-Encoding");
                removeHeaderIgnoreCase(headers, "Content-Length");
                headers.add("Content-Length: " + multipartBody.length);

                byte[] newRequest = Utils.helpers.buildHttpMessage(headers, multipartBody);
                requestViewer.setMessage(newRequest, true);
            } else {
                // 非 form-urlencoded：只做 Header 欺骗（保持原 body）
                int ret = JOptionPane.showConfirmDialog(
                        this,
                        "当前 Content-Type 不是 application/x-www-form-urlencoded。\n" +
                                "只能进行 Header 欺骗（修改 Content-Type 头但保留原始 Body）。\n\n" +
                                "是否继续？",
                        "Header 欺骗",
                        JOptionPane.YES_NO_OPTION
                );
                if (ret != JOptionPane.YES_OPTION) return;

                removeHeaderIgnoreCase(headers, "Content-Type");
                headers.add("Content-Type: multipart/form-data; boundary=" + boundary);
                removeHeaderIgnoreCase(headers, "Transfer-Encoding");
                removeHeaderIgnoreCase(headers, "Content-Length");
                headers.add("Content-Length: " + body.length);

                byte[] newRequest = Utils.helpers.buildHttpMessage(headers, body);
                requestViewer.setMessage(newRequest, true);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Multipart 转换错误: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private byte[] convertFormToMultipart(byte[] body, String boundary, List<String> headers) {
        try {
            // 提取 charset
            Charset cs = StandardCharsets.UTF_8;
            for (String h : headers) {
                if (h.toLowerCase().startsWith("content-type:")) {
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?i)charset\\s*=\\s*([^;\\r\\n]+)").matcher(h);
                    if (m.find()) {
                        try {
                            cs = Charset.forName(m.group(1).trim());
                        } catch (Exception ignored) {
                        }
                    }
                    break;
                }
            }

            String bodyStr = new String(body, cs);
            if (bodyStr.trim().isEmpty()) return null;

            String[] pairs = bodyStr.split("&");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (String pair : pairs) {
                if (pair == null || pair.isEmpty()) continue;
                String[] kv = pair.split("=", 2);
                String key = URLDecoder.decode(kv[0], cs.name());
                String value = kv.length > 1 ? URLDecoder.decode(kv[1], cs.name()) : "";

                out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(("Content-Disposition: form-data; name=\"" + key + "\"\r\n").getBytes(StandardCharsets.UTF_8));
                out.write(("Content-Type: text/plain; charset=" + cs.name() + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(value.getBytes(cs));
                out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            }
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private void encodeBodyWithCharset(String charsetName) {
        String text = getRequestTextISO();
        try {
            RequestParts parts = splitRequestText(text);
            if (parts == null) {
                JOptionPane.showMessageDialog(this, "未找到请求体", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String lineEnd = parts.lineEnd;
            String headers = parts.headers;
            String body = expandInlineTags(parts.body);

            if (body.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请求体为空", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (looksBinaryBody(body)) {
                JOptionPane.showMessageDialog(this, "当前请求体看起来已是二进制/已编码数据，请先 Reset 再进行字符集编码", "提示", JOptionPane.INFORMATION_MESSAGE);
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
                        if (sb.length() > 0) sb.append(lineEnd);
                        sb.append(normalized);
                        ctDone = true;
                    } else {
                        if (sb.length() > 0) sb.append(lineEnd);
                        sb.append(line);
                    }
                }
                newHeaders = sb.toString();
            }
            newHeaders = removeHeaderLine(newHeaders, "Transfer-Encoding", lineEnd);
            newHeaders = upsertHeaderLine(newHeaders, "Content-Length", String.valueOf(encoded.length), lineEnd);

            String newRequest = newHeaders + lineEnd + lineEnd + new String(encoded, StandardCharsets.ISO_8859_1);
            setRequestTextISO(newRequest);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "编码错误: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toUpper() { transformSelection(String::toUpperCase); }
    private void toLower() { transformSelection(String::toLowerCase); }

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
                if (c >= '!' && c <= '~') sb.append((char) (c - '!' + '！'));
                else if (c == ' ') sb.append('　');
                else sb.append(c);
            }
            return sb.toString();
        });
    }

    private void toHomoglyph() {
        transformSelection(s -> s.replace('a', 'а').replace('e', 'е').replace('o', 'о')
                .replace('p', 'р').replace('c', 'с').replace('x', 'х'));
    }

    private void insertAt(String text) {
        insertIntoSelectionOrWarn(text.getBytes(StandardCharsets.ISO_8859_1), true);
    }

    private void wrapWith(String before, String after) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中要包裹的文本", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        byte[] beforeB = before.getBytes(StandardCharsets.ISO_8859_1);
        byte[] afterB = after.getBytes(StandardCharsets.ISO_8859_1);
        byte[] replacement = new byte[beforeB.length + sel.length + afterB.length];
        System.arraycopy(beforeB, 0, replacement, 0, beforeB.length);
        System.arraycopy(sel, 0, replacement, beforeB.length, sel.length);
        System.arraycopy(afterB, 0, replacement, beforeB.length + sel.length, afterB.length);
        replaceOccurrenceInRequest(sel, replacement);
    }

    private void switchToHttp10() {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) return;

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
        requestViewer.setMessage(newRequest, true);
    }

    private void transformSelection(java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中要变换的文本", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = new String(sel, StandardCharsets.ISO_8859_1);
        String replaced = transformer.apply(selected);
        replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.ISO_8859_1));
    }

    // --- Undo/Redo ---
    private void saveState() {
        byte[] current = getRequestBytes();
        if (lastSavedState != null && Arrays.equals(current, lastSavedState)) return;

        undoStack.push(lastSavedState == null ? new byte[0] : lastSavedState);
        if (undoStack.size() > MAX_UNDO_STEPS) {
            undoStack.remove(0);
        }

        lastSavedState = Arrays.copyOf(current, current.length);
        redoStack.clear();
    }

    private void undo() {
        if (!undoStack.isEmpty()) {
            redoStack.push(getRequestBytes());
            if (redoStack.size() > MAX_REDO_STEPS) {
                redoStack.remove(0);
            }
            byte[] prev = undoStack.pop();
            lastSavedState = prev;
            setRequestBytes(prev);
        }
    }

    private void redo() {
        if (!redoStack.isEmpty()) {
            undoStack.push(getRequestBytes());
            if (undoStack.size() > MAX_UNDO_STEPS) {
                undoStack.remove(0);
            }
            byte[] next = redoStack.pop();
            lastSavedState = next;
            setRequestBytes(next);
        }
    }

    private void reset() {
        if (originalRequest != null && originalRequest.length > 0) {
            saveState();
            setRequestBytes(originalRequest);
            lastSavedState = Arrays.copyOf(originalRequest, originalRequest.length);
        }
    }

    // --- Send ---
    private void sendRequest() {
        String host = hostField == null ? "" : hostField.getText().trim();
        String portStr = portField == null ? "" : portField.getText().trim();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Host 不能为空", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "端口号必须是数字", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String protocol = (httpsCheckBox != null && httpsCheckBox.isSelected()) ? "https" : "http";
        IHttpService targetService = Utils.helpers.buildHttpService(host, port, protocol);
        currentHttpService = targetService;

        byte[] rawReq = getRequestBytes();
        if (rawReq == null || rawReq.length == 0) {
            JOptionPane.showMessageDialog(this, "请求内容为空", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        final boolean followRedirect = followRedirectCheckBox != null && followRedirectCheckBox.isSelected();
        isCancelled = false;

        long startNs = System.nanoTime();
        if (statusLabel != null) {
            statusLabel.setText("Sending...");
        }

        if (sendBtn != null) {
            sendBtn.setEnabled(false);
            sendBtn.setText("Sending...");
        }
        if (cancelBtn != null) {
            cancelBtn.setEnabled(true);
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
                    if (isCancelled) break;

                    respBytes = (resp == null) ? null : resp.getResponse();
                    if (respBytes == null) break;

                    // 检查是否需要跟随重定向
                    if (followRedirect) {
                        short statusCode = Utils.helpers.analyzeResponse(respBytes).getStatusCode();
                        if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) {
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
                                        if ((currentTarget.getProtocol().equals("http") && currentTarget.getPort() != 80) ||
                                                (currentTarget.getProtocol().equals("https") && currentTarget.getPort() != 443)) {
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
                                    if (newPath == null || newPath.isEmpty()) newPath = "/";
                                    if (redirectUrl.getQuery() != null) {
                                        newPath += "?" + redirectUrl.getQuery();
                                    }

                                    currentTarget = Utils.helpers.buildHttpService(newHost, newPort, newProtocol);

                                    // 303 强制 GET，其他保持方法
                                    String method = (statusCode == 303) ? "GET" : Utils.helpers.analyzeRequest(finalBytes).getMethod();
                                    List<String> newHeaders = new ArrayList<>();
                                    newHeaders.add(method + " " + newPath + " HTTP/1.1");
                                    newHeaders.add("Host: " + newHost + (newPort != 80 && newPort != 443 ? ":" + newPort : ""));

                                    // 复制原有 headers（除了 Host）
                                    List<String> oldHeaders = Utils.helpers.analyzeRequest(finalBytes).getHeaders();
                                    for (int i = 1; i < oldHeaders.size(); i++) {
                                        String h = oldHeaders.get(i);
                                        if (!h.toLowerCase().startsWith("host:") && !h.toLowerCase().startsWith("content-length:")) {
                                            newHeaders.add(h);
                                        }
                                    }

                                    // 303 不带 body
                                    byte[] body = (statusCode == 303) ? new byte[0] :
                                            Arrays.copyOfRange(finalBytes, Utils.helpers.analyzeRequest(finalBytes).getBodyOffset(), finalBytes.length);

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

                if (isCancelled) return;

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
                                    finalRedirectCount > 0 ? " | Redirects: " + finalRedirectCount : ""
                            );
                        } else {
                            statusText = String.format(
                                    "Status: (none) | Time: %dms | Req: %s | Resp: 0B",
                                    durationMs,
                                    formatSize(finalReqBytes.length)
                            );
                        }
                        statusLabel.setText(statusText);
                    }
                });
            } catch (Exception ex) {
                if (isCancelled) return;
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
                        sendBtn.setText("Send");
                    }
                    if (cancelBtn != null) {
                        cancelBtn.setEnabled(false);
                    }
                });
            }
        });
        sendThread.start();
    }

    private String getHeaderValue(byte[] response, String headerName) {
        if (response == null) return null;
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
        if (size < 1024) return size + "B";
        if (size < 1024 * 1024) return String.format("%.1fKB", size / 1024.0);
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
            if (respBytes == null) return;
            short statusCode = Utils.helpers.analyzeResponse(respBytes).getStatusCode();
            String title = Utils.getBodyTitle(new String(respBytes, StandardCharsets.UTF_8));
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
                    "WAF Bypass (Manual)"
            ));
        } catch (Exception ignored) {
        }
    }

    private void showHistoryEntry(int index) {
        if (index < 0 || index >= historyEntries.size()) return;
        byte[] resp = historyEntries.get(index).responseBytes;
        if (resp == null) resp = new byte[0];
        currentResponseBytes = resp;
        responseViewer.setMessage(resp, false);
    }

    // --- Public API ---
    public void loadRequest(IHttpRequestResponse requestResponse) {
        if (requestResponse == null) return;
        currentHttpService = requestResponse.getHttpService();
        if (currentHttpService != null) {
            if (hostField != null) hostField.setText(currentHttpService.getHost());
            if (portField != null) portField.setText(String.valueOf(currentHttpService.getPort()));
            if (httpsCheckBox != null) httpsCheckBox.setSelected("https".equalsIgnoreCase(currentHttpService.getProtocol()));
        }

        byte[] req = requestResponse.getRequest();
        if (req != null) {
            requestViewer.setMessage(req, true);
            originalRequest = req;
            lastSavedState = Arrays.copyOf(req, req.length);
            undoStack.clear();
            redoStack.clear();
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
        if (msg == null) msg = new byte[0];
        if (requestViewer != null) requestViewer.setMessage(msg, true);
    }

    private String getRequestTextISO() {
        return new String(getRequestBytes(), StandardCharsets.ISO_8859_1);
    }

    private void setRequestTextISO(String text) {
        if (text == null) text = "";
        setRequestBytes(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private byte[] getSelectedRequestBytes() {
        if (requestViewer == null) return new byte[0];
        byte[] sel = requestViewer.getSelectedData();
        return sel == null ? new byte[0] : sel;
    }

    private void replaceOccurrenceInRequest(byte[] target, byte[] replacement) {
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, target);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "未找到选中文本在请求中的位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        if (positions.size() == 1) {
            replaceAtIndex(msg, positions.get(0), target.length, replacement);
            return;
        }

        // 多处匹配，让用户选择
        String[] options = new String[positions.size() + 1];
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i);
            String context = getContextSnippet(msg, pos, target.length, 20);
            options[i] = "第 " + (i + 1) + " 处: ..." + context + "...";
        }
        options[positions.size()] = "全部替换 (" + positions.size() + " 处)";

        Object choice = JOptionPane.showInputDialog(
                this,
                "请求中有 " + positions.size() + " 处相同内容，请选择要替换的位置：",
                "多处匹配",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == null) return;

        String choiceStr = choice.toString();
        if (choiceStr.startsWith("全部替换")) {
            replaceAllOccurrences(msg, positions, target.length, replacement);
        } else {
            for (int i = 0; i < positions.size(); i++) {
                if (choiceStr.equals(options[i])) {
                    replaceAtIndex(msg, positions.get(i), target.length, replacement);
                    break;
                }
            }
        }
    }

    private void replaceAtIndex(byte[] msg, int idx, int targetLen, byte[] replacement) {
        byte[] out = new byte[msg.length - targetLen + replacement.length];
        System.arraycopy(msg, 0, out, 0, idx);
        System.arraycopy(replacement, 0, out, idx, replacement.length);
        System.arraycopy(msg, idx + targetLen, out, idx + replacement.length, msg.length - (idx + targetLen));
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
            System.arraycopy(current, pos + targetLen, out, pos + replacement.length, current.length - (pos + targetLen));
            current = out;
        }
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
            if (found < 0) break;
            result.add(found);
            idx = found + needle.length; // 不允许重叠匹配
        }
        return result;
    }

    private static int indexOfFrom(byte[] haystack, byte[] needle, int fromIndex) {
        if (haystack == null || needle == null || needle.length == 0) return -1;
        outer:
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private String getContextSnippet(byte[] msg, int pos, int targetLen, int contextLen) {
        int start = Math.max(0, pos - contextLen);
        int end = Math.min(msg.length, pos + targetLen + contextLen);

        StringBuilder sb = new StringBuilder();
        if (start > 0) sb.append("");
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
        if (end < msg.length) sb.append("");
        return sb.toString();
    }

    private char safeChar(byte b) {
        int c = b & 0xFF;
        if (c == '\r') return '↵';
        if (c == '\n') return '↓';
        if (c == '\t') return '→';
        if (c < 0x20 || c >= 0x7F) return '·';
        return (char) c;
    }

    private void insertIntoSelectionOrWarn(byte[] insert, boolean beforeSelection) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, "请先选中插入位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, sel);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "未找到选中文本在请求中的位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int chosenIdx;
        if (positions.size() == 1) {
            chosenIdx = positions.get(0);
        } else {
            // 多处匹配，让用户选择
            String[] options = new String[positions.size()];
            for (int i = 0; i < positions.size(); i++) {
                int pos = positions.get(i);
                String context = getContextSnippet(msg, pos, sel.length, 20);
                options[i] = "第 " + (i + 1) + " 处: ..." + context + "...";
            }

            Object choice = JOptionPane.showInputDialog(
                    this,
                    "请求中有 " + positions.size() + " 处相同内容，请选择插入位置：",
                    "多处匹配",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]
            );

            if (choice == null) return;

            chosenIdx = -1;
            String choiceStr = choice.toString();
            for (int i = 0; i < positions.size(); i++) {
                if (choiceStr.equals(options[i])) {
                    chosenIdx = positions.get(i);
                    break;
                }
            }
            if (chosenIdx < 0) return;
        }

        int insertPos = beforeSelection ? chosenIdx : (chosenIdx + sel.length);
        byte[] out = new byte[msg.length + insert.length];
        System.arraycopy(msg, 0, out, 0, insertPos);
        System.arraycopy(insert, 0, out, insertPos, insert.length);
        System.arraycopy(msg, insertPos, out, insertPos + insert.length, msg.length - insertPos);
        setRequestBytes(out);
    }

    // --- Dirty tags ---
    private byte[] buildRequestBytesForSending(byte[] originalRequestBytes) {
        if (originalRequestBytes == null) return new byte[0];

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
        byte[] bodyExpanded = buildBodyBytesWithTags(bodyStr, binary ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_8);

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
        if (headers == null) return false;
        String[] lines = headers.split("\\r?\\n", -1);
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) return true;
        }
        return false;
    }

    private boolean isContentLengthTampered(byte[] requestBytes) {
        SplitBytes split = splitRequestBytes(requestBytes);
        if (split == null) return false;
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
        if (declared < 0) return false; // 没有 CL
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
        if (requestBytes == null) return null;
        int idx = indexOfBytes(requestBytes, new byte[]{'\r', '\n', '\r', '\n'});
        byte[] delimiter;
        String lineEnd;
        int sepLen;
        if (idx >= 0) {
            delimiter = new byte[]{'\r', '\n', '\r', '\n'};
            lineEnd = "\r\n";
            sepLen = 4;
        } else {
            idx = indexOfBytes(requestBytes, new byte[]{'\n', '\n'});
            if (idx < 0) return null;
            delimiter = new byte[]{'\n', '\n'};
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
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length) return -1;
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private void updateOrAddHeader(List<String> headers, String name, String value) {
        if (headers == null || headers.isEmpty()) return;
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
        if (headers == null || headers.size() <= 1) return;
        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i);
            if (h.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                headers.remove(i);
            }
        }
    }

    private String expandInlineTags(String input) {
        if (input == null || input.isEmpty()) return input;
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
        if (body == null || body.isEmpty()) return new byte[0];
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
                if (isNull) writeNullBytes(out, count);
                else writeRandomDigits(out, count);
            }
            idx = end;
        }

        return out.toByteArray();
    }

    private void writeText(ByteArrayOutputStream out, String s, Charset cs) {
        if (s == null || s.isEmpty()) return;
        try {
            out.write(s.getBytes(cs));
        } catch (Exception ignored) {
        }
    }

    private void writeNullBytes(ByteArrayOutputStream out, int count) {
        if (count <= 0) return;
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    private void writeRandomDigits(ByteArrayOutputStream out, int count) {
        if (count <= 0) return;
        Random r = new Random();
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            for (int i = 0; i < n; i++) buf[i] = (byte) ('0' + r.nextInt(10));
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
    }

    class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Method", "Path", "Status", "Length", "Time(ms)", "Clock"};
        @Override public int getRowCount() { return historyEntries.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Object getValueAt(int row, int col) {
            HistoryEntry e = historyEntries.get(row);
            switch (col) {
                case 0: return e.id;
                case 1: return e.method != null ? e.method : "";
                case 2: return e.path != null ? (e.path.length() > 40 ? e.path.substring(0, 37) + "..." : e.path) : "";
                case 3: return e.status;
                case 4: return e.length;
                case 5: return e.durationMs;
                case 6: return e.time;
                default: return "";
            }
        }
    }
}

