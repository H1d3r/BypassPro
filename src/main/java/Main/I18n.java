package Main;

import java.util.HashMap;
import java.util.Map;

/**
 * 轻量级国际化工具类。
 *
 * <p>设计目标：
 * <ul>
 *   <li>启动时根据 YAML general.lang 选择 zh / en，默认 zh</li>
 *   <li>所有 UI 文案通过 {@link #t(String)} 查表，找不到 key 时回退到 key 本身</li>
 *   <li>双 Map 静态注册，运行期不动 IO，零开销</li>
 * </ul>
 *
 * <p>切换语言需要重启插件（或重新调用 {@link #setLang(String)}），调用方不需要监听变化。
 */
public final class I18n {

    public static final String ZH = "zh";
    public static final String EN = "en";

    private static final Map<String, String> ZH_MAP = new HashMap<>(1024);
    private static final Map<String, String> EN_MAP = new HashMap<>(1024);

    private static volatile String currentLang = ZH;

    static {
        I18nKeys.register();
    }

    private I18n() {}

    /**
     * 注册一条双语条目。重复 key 后注册的值生效。
     */
    public static void put(String key, String zh, String en) {
        if (key == null) {
            return;
        }
        if (zh != null) {
            ZH_MAP.put(key, zh);
        }
        if (en != null) {
            EN_MAP.put(key, en);
        }
    }

    /**
     * 设置当前语言。仅接受 "zh" / "en"，其他值回退到 zh。
     */
    public static void setLang(String lang) {
        if (EN.equalsIgnoreCase(lang)) {
            currentLang = EN;
        } else {
            currentLang = ZH;
        }
    }

    public static String getLang() {
        return currentLang;
    }

    /**
     * 翻译。找不到 key 时返回 key 本身，便于发现遗漏。
     */
    public static String t(String key) {
        if (key == null) {
            return "";
        }
        Map<String, String> map = EN.equals(currentLang) ? EN_MAP : ZH_MAP;
        String v = map.get(key);
        if (v != null) {
            return v;
        }
        // 当前语言缺失时尝试另一种语言兜底，避免整段空白
        Map<String, String> fallback = EN.equals(currentLang) ? ZH_MAP : EN_MAP;
        String f = fallback.get(key);
        return f != null ? f : key;
    }

    /**
     * 带参数的翻译，使用 {@link String#format(String, Object...)} 渲染。
     */
    public static String t(String key, Object... args) {
        String tpl = t(key);
        if (args == null || args.length == 0) {
            return tpl;
        }
        try {
            return String.format(tpl, args);
        } catch (Exception e) {
            return tpl;
        }
    }

    /**
     * 由按钮/行标签的稳定文本生成稳定的 i18n key 后缀。规则：
     * <ul>
     *   <li>A-Z 转小写、a-z/0-9 保留</li>
     *   <li>空格、连字符、斜杠转下划线</li>
     *   <li>其余字符（中文、特殊符号等）忽略</li>
     * </ul>
     * 该方法是 ManualWafPanel 中按钮/行标签查找 i18n 的唯一来源，
     * 同时供 I18nKeys 在注册时复用，确保注册 key 与查找 key 完全一致。
     */
    public static String slug(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                sb.append((char) (c + 32));
            } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                sb.append(c);
            } else if (c == ' ' || c == '-' || c == '/') {
                sb.append('_');
            }
        }
        return sb.toString();
    }
}
