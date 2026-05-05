package Main.ghostbits;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ghost Bits 引擎，负责：
 *  1. atom 候选查询（配置里有就用配置，没有就在 0x00..0xFF 范围枚举）
 *  2. sequence 引用展开
 *  3. template pattern 占位符展开
 *  4. 把任意 ASCII 字符 fold 模拟（(byte) ch 行为）方便预览
 *
 * 占位符语法：
 *   {{atom:CHAR}}        - 用 atoms 表里 CHAR 对应的第一个候选 Unicode 字符
 *   {{atom:CHAR:N}}      - 用第 N 个候选（0 起算），越界回退到 0
 *   {{seq:NAME}}         - 直接展开 sequences 里命名的序列
 *   {{repeat:NAME:N}}    - 把 sequences 里的 NAME 重复 N 次（不加分隔符）
 *   {{url:CHAR}}         - 把 CHAR 做 URL percent-encoding（只支持单字节 ASCII）
 *
 * CHAR 中可使用转义 \r / \n / \t / \\ ，避免 YAML 引号嵌套。
 */
public class GhostBitsEngine {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{\\s*([^{}]+?)\\s*\\}\\}");

    private final GhostBitsRule rule;

    public GhostBitsEngine(GhostBitsRule rule) {
        this.rule = rule == null ? new GhostBitsRule(null, null, null) : rule;
    }

    public GhostBitsRule getRule() {
        return rule;
    }

    // ------------------------------------------------------------------
    // 公共 API
    // ------------------------------------------------------------------

    /**
     * 取目标 ASCII 字符的候选 Unicode 列表。配置里没有则全量枚举 0x00..0xFF（高字节
     * 跳过 0x00 自身，避免返回 ASCII 字符本身；同时跳过 surrogate range）。
     */
    public List<String> findCandidates(String targetChar) {
        if (targetChar == null || targetChar.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> configured = rule.getAtomCandidates(targetChar);
        if (!configured.isEmpty()) {
            return new ArrayList<>(configured);
        }
        return enumerateCandidates(targetChar.charAt(0));
    }

    /**
     * 全量枚举给定低 8 位的所有有效 Unicode 候选字符（仅 BMP 内，跳过 ASCII 段和 surrogate）。
     */
    public List<String> enumerateCandidates(char targetByte) {
        List<String> result = new ArrayList<>();
        int low = targetByte & 0xFF;
        // 高字节从 0x01 开始，避免返回 ASCII 字符本身
        for (int high = 0x01; high <= 0xFF; high++) {
            int code = (high << 8) | low;
            // 跳过 surrogate range，避免组合出非法字符
            if (code >= 0xD800 && code <= 0xDFFF) {
                continue;
            }
            result.add(String.valueOf((char) code));
        }
        return result;
    }

    /**
     * 模拟 Java 的 (byte) ch 折叠。返回字节数组，每个 char 取低 8 位。
     */
    public static byte[] foldToBytes(String s) {
        if (s == null) {
            return new byte[0];
        }
        byte[] out = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            out[i] = (byte) (s.charAt(i) & 0xFF);
        }
        return out;
    }

    /**
     * 等价于 foldToBytes(s) 然后用 ISO-8859-1 解出来的字符串，用于"低 8 位还原后等价 ASCII"预览。
     */
    public static String foldToAscii(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            sb.append((char) (s.charAt(i) & 0xFF));
        }
        return sb.toString();
    }

    /**
     * 渲染指定模板。模板不存在或 pattern 为空时返回空字符串。
     */
    public String renderTemplate(String templateId) {
        GhostBitsRule.Template t = rule.getTemplate(templateId);
        if (t == null) {
            return "";
        }
        return renderPattern(t.getPattern());
    }

    /**
     * 渲染任意带占位符的字符串。
     */
    public String renderPattern(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return "";
        }
        Matcher m = PLACEHOLDER.matcher(pattern);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String body = m.group(1).trim();
            String replacement = expandToken(body);
            // quoteReplacement 防止 \ 和 $ 被特殊解析
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // 占位符展开
    // ------------------------------------------------------------------

    private String expandToken(String token) {
        if (token == null || token.isEmpty()) {
            return "";
        }
        // 形如 atom:.  atom:.:0  seq:dot_u002e  repeat:dot_u002e:6  url:d
        int firstColon = token.indexOf(':');
        if (firstColon < 0) {
            // 没有冒号当作未知占位符，原样保留
            return "{{" + token + "}}";
        }
        String kind = token.substring(0, firstColon).trim().toLowerCase();
        String rest = token.substring(firstColon + 1);

        switch (kind) {
            case "atom":
                return expandAtom(rest);
            case "seq":
                return expandSeq(rest);
            case "repeat":
                return expandRepeat(rest);
            case "url":
                return expandUrl(rest);
            default:
                return "{{" + token + "}}";
        }
    }

    private String expandAtom(String rest) {
        // rest 形如 ".":0 / "." / "\r"
        int idx = 0;
        String charPart = rest;
        int lastColon = rest.lastIndexOf(':');
        if (lastColon >= 0) {
            // 注意：转义字符里也不会出现 :，所以最后一个冒号才是 index 分隔符
            String maybeIdx = rest.substring(lastColon + 1).trim();
            try {
                int parsed = Integer.parseInt(maybeIdx);
                idx = parsed;
                charPart = rest.substring(0, lastColon);
            } catch (NumberFormatException ignored) {
                // 不是数字，整段当作字符
            }
        }
        String target = unescape(charPart.trim());
        if (target.isEmpty()) {
            return "";
        }
        List<String> candidates = findCandidates(target);
        if (candidates.isEmpty()) {
            return target;
        }
        if (idx < 0 || idx >= candidates.size()) {
            idx = 0;
        }
        return candidates.get(idx);
    }

    private String expandSeq(String rest) {
        String name = rest.trim();
        String value = rule.getSequence(name);
        return value == null ? "" : value;
    }

    private String expandRepeat(String rest) {
        // rest 形如 NAME:N
        int colon = rest.lastIndexOf(':');
        if (colon < 0) {
            return "";
        }
        String name = rest.substring(0, colon).trim();
        int n;
        try {
            n = Integer.parseInt(rest.substring(colon + 1).trim());
        } catch (NumberFormatException e) {
            return "";
        }
        if (n <= 0) {
            return "";
        }
        String value = rule.getSequence(name);
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(value);
        }
        return sb.toString();
    }

    private String expandUrl(String rest) {
        String target = unescape(rest.trim());
        if (target.isEmpty()) {
            return "";
        }
        // 强制按字节 percent-encoding（URLEncoder 会把字母数字保留，不符合需要）
        try {
            byte[] bytes = target.getBytes("UTF-8");
            StringBuilder sb = new StringBuilder(bytes.length * 3);
            for (byte b : bytes) {
                sb.append(String.format("%%%02X", b & 0xFF));
            }
            return sb.toString();
        } catch (UnsupportedEncodingException e) {
            // UTF-8 一定可用，这里只是 API 强制要求 catch
            return target;
        }
    }

    /**
     * 解析常见转义。让 YAML 里写起来更短，例如 atom:\r、atom:\n、atom:\\
     */
    private static String unescape(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        // 去掉外层引号（YAML 里有时为了表达 ":" 会带引号）
        if (s.length() >= 2
                && ((s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"')
                || (s.charAt(0) == '\'' && s.charAt(s.length() - 1) == '\''))) {
            s = s.substring(1, s.length() - 1);
        }
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i == s.length() - 1) {
                sb.append(c);
                continue;
            }
            char next = s.charAt(++i);
            switch (next) {
                case 'r': sb.append('\r'); break;
                case 'n': sb.append('\n'); break;
                case 't': sb.append('\t'); break;
                case '0': sb.append('\0'); break;
                case '\\': sb.append('\\'); break;
                case '"': sb.append('"'); break;
                case '\'': sb.append('\''); break;
                default:
                    sb.append('\\').append(next);
            }
        }
        return sb.toString();
    }
}
