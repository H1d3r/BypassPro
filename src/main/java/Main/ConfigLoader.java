package Main;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConfigLoader {
    private static final String CONFIG_DIR_NAME = ".config/BypassPro";
    private static final String CONFIG_FILE_NAME = "BypassPro-config.yaml";
    private static final String CLASSPATH_RESOURCE = "BypassPro-config.yaml";

    private final Yaml yaml;
    private final String configDirPath;
    private final String configFilePath;

    public ConfigLoader() {
        this.yaml = createSecureYaml();
        this.configDirPath = determineConfigDirPath();
        this.configFilePath = this.configDirPath + File.separator + CONFIG_FILE_NAME;

        File dir = new File(this.configDirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            dir.mkdirs();
        }

        File cfg = new File(this.configFilePath);
        if (!cfg.exists() || !cfg.isFile()) {
            initConfig();
        }
    }

    public String getConfigFilePath() {
        return configFilePath;
    }

    public Map<String, Object> loadConfig() {
        Path p = Paths.get(configFilePath);
        if (!Files.exists(p)) {
            return Collections.emptyMap();
        }

        try (InputStream in = Files.newInputStream(p)) {
            Map<String, Object> m = yaml.load(in);
            return m == null ? Collections.emptyMap() : m;
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public boolean initConfig() {
        return copyDefaultConfigToFile(this.configFilePath);
    }

    public String readConfigText() {
        Path p = Paths.get(configFilePath);
        if (!Files.exists(p)) {
            return "";
        }
        try {
            byte[] bytes = Files.readAllBytes(p);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 保存 general 配置
     */
    public boolean saveGeneralConfig(int threads, double similarityThreshold) {
        return saveGeneralConfig(threads, readExistingMaxRedirects(), similarityThreshold, null);
    }

    /**
     * 保存 general 配置（含语言）。lang 为 null 时不修改语言字段。
     */
    public boolean saveGeneralConfig(int threads, double similarityThreshold, String lang) {
        return saveGeneralConfig(threads, readExistingMaxRedirects(), similarityThreshold, lang);
    }

    /**
     * 保存 general 配置（含 Follow Redirect 最大跳转次数）。
     */
    public boolean saveGeneralConfig(int threads, int maxRedirects, double similarityThreshold, String lang) {
        try {
            String raw = readConfigText();
            if (raw == null || raw.isEmpty()) {
                Map<String, Object> config = loadConfig();
                if (config.isEmpty()) {
                    config = new LinkedHashMap<>();
                }
                Map<String, Object> general = new LinkedHashMap<>();
                general.put("threads", threads);
                general.put("max_redirects", maxRedirects);
                general.put("similarity_threshold", similarityThreshold);
                if (lang != null && !lang.isEmpty()) {
                    general.put("lang", lang);
                }
                config.put("general", general);
                return writeConfig(config);
            }
            String patched = patchGeneralSection(raw, threads, maxRedirects, similarityThreshold, lang);
            return writeConfigText(patched);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 保存 WAF Options 到配置文件
     * @param options WAF 的 options Map
     * @return 是否保存成功
     */
    @SuppressWarnings("unchecked")
    public boolean saveWafOptions(Map<String, Object> options) {
        try {
            String raw = readConfigText();
            if (raw == null || raw.isEmpty()) {
                // 文件为空时退化为结构化写入
                Map<String, Object> config = loadConfig();
                if (config.isEmpty()) {
                    config = new LinkedHashMap<>();
                }
                Object profilesObj = config.get("profiles");
                Map<String, Object> profiles = profilesObj instanceof Map ? (Map<String, Object>) profilesObj : new LinkedHashMap<>();
                config.put("profiles", profiles);
                Object wafObj = profiles.get(Utils.PROFILE_AUTO_WAF_BYPASS);
                Map<String, Object> waf = wafObj instanceof Map ? (Map<String, Object>) wafObj : new LinkedHashMap<>();
                profiles.put(Utils.PROFILE_AUTO_WAF_BYPASS, waf);
                waf.put("options", options);
                return writeConfig(config);
            }
            String patched = patchWafOptionsSection(raw, options);
            if (patched == null) {
                return false;
            }
            return writeConfigText(patched);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 写入配置到文件
     */
    private boolean writeConfig(Map<String, Object> config) {
        try {
            // 使用更漂亮的格式
            DumperOptions dop = new DumperOptions();
            dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            dop.setPrettyFlow(true);
            dop.setIndent(2);
            dop.setIndicatorIndent(2);
            dop.setIndentWithIndicator(true);

            Representer representer = new Representer(dop);
            Yaml yamlWriter = new Yaml(representer, dop);

            try (FileWriter writer = new FileWriter(configFilePath)) {
                yamlWriter.dump(config, writer);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean writeConfigText(String text) {
        try {
            Path p = Paths.get(configFilePath);
            Files.write(p, text.getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private String patchGeneralSection(String raw, int threads, int maxRedirects, double similarityThreshold, String lang) {
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int generalIdx = findTopLevelKey(lines, "general");
        if (generalIdx < 0) {
            StringBuilder sb = new StringBuilder(raw.length() + 128);
            sb.append("general:\n");
            sb.append("  threads: ").append(threads).append("\n");
            sb.append("  max_redirects: ").append(maxRedirects).append("\n");
            sb.append("  similarity_threshold: ").append(similarityThreshold).append("\n");
            if (lang != null && !lang.isEmpty()) {
                sb.append("  lang: ").append(lang).append("\n");
            }
            sb.append("\n");
            sb.append(raw);
            return sb.toString();
        }

        int end = findTopLevelSectionEnd(lines, generalIdx);
        patchScalarInSection(lines, generalIdx + 1, end, 2, "threads", String.valueOf(threads));
        patchScalarAfterKeyInSection(lines, generalIdx + 1, end, 2,
                "max_redirects", String.valueOf(maxRedirects), "threads");
        patchScalarInSection(lines, generalIdx + 1, end, 2, "similarity_threshold", String.valueOf(similarityThreshold));
        if (lang != null && !lang.isEmpty()) {
            patchScalarInSection(lines, generalIdx + 1, end, 2, "lang", lang);
        }
        return String.join("\n", lines);
    }

    @SuppressWarnings("unchecked")
    private int readExistingMaxRedirects() {
        try {
            Map<String, Object> config = loadConfig();
            Object generalObj = config.get("general");
            if (generalObj instanceof Map) {
                Object maxObj = ((Map<String, Object>) generalObj).get("max_redirects");
                if (maxObj instanceof Number) {
                    int value = ((Number) maxObj).intValue();
                    if (value >= 1 && value <= 10) {
                        return value;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return 3;
    }

    private String patchWafOptionsSection(String raw, Map<String, Object> options) {
        if (options == null || options.isEmpty()) {
            return raw;
        }
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int profilesIdx = findTopLevelKey(lines, "profiles");
        if (profilesIdx < 0) {
            return null;
        }
        int profilesEnd = findTopLevelSectionEnd(lines, profilesIdx);
        int wafIdx = findChildKey(lines, profilesIdx + 1, profilesEnd, 2, Utils.PROFILE_AUTO_WAF_BYPASS);
        if (wafIdx < 0) {
            return null;
        }
        int wafEnd = findSectionEndByIndent(lines, wafIdx, 2);
        int optionsIdx = findChildKey(lines, wafIdx + 1, wafEnd, 4, "options");
        if (optionsIdx < 0) {
            return null;
        }
        int optionsEnd = findSectionEndByIndent(lines, optionsIdx, 4);

        // 只更新已知开关（保持注释/格式）：body_charset/body_transform/content_type_spoof/ghost_bits
        Map<String, Object> bodyCharset = safeMap(options.get("body_charset"));
        Map<String, Object> bodyTransform = safeMap(options.get("body_transform"));
        Map<String, Object> contentTypeSpoof = safeMap(options.get("content_type_spoof"));
        Map<String, Object> ghostBits = safeMap(options.get("ghost_bits"));

        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "body_charset", 6, bodyCharset);
        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "body_transform", 6, bodyTransform);
        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "content_type_spoof", 6, contentTypeSpoof);
        ensureGhostBitsOptionsSection(lines, optionsIdx, ghostBits);
        optionsEnd = findSectionEndByIndent(lines, optionsIdx, 4);
        patchGhostBitsOptions(lines, optionsIdx + 1, optionsEnd, ghostBits);

        return String.join("\n", lines);
    }

    private void ensureGhostBitsOptionsSection(ArrayList<String> lines, int optionsIdx, Map<String, Object> ghostBits) {
        if (ghostBits == null || ghostBits.isEmpty()) return;
        int optionsEnd = findSectionEndByIndent(lines, optionsIdx, 4);
        if (findChildKey(lines, optionsIdx + 1, optionsEnd, 6, "ghost_bits") >= 0) {
            return;
        }
        int insertAt = Math.min(optionsEnd, lines.size());
        Map<String, Object> templates = safeMap(ghostBits.get("templates"));
        Map<String, Object> generic = safeMap(ghostBits.get("generic"));
        lines.add(insertAt++, "");
        lines.add(insertAt++, repeatSpace(6) + "# Ghost Bits 自动绕过（eq/parser 候选，非漏洞确认）");
        lines.add(insertAt++, repeatSpace(6) + "ghost_bits:");
        lines.add(insertAt++, repeatSpace(8) + "enabled: " + boolText(ghostBits.get("enabled"), false));
        lines.add(insertAt++, repeatSpace(8) + "raw_socket: " + boolText(ghostBits.get("raw_socket"), true));
        Object maxVariants = ghostBits.get("max_variants");
        lines.add(insertAt++, repeatSpace(8) + "max_variants: "
                + (maxVariants == null ? "10" : maxVariants.toString()));
        if (!templates.isEmpty()) {
            lines.add(insertAt++, "");
            lines.add(insertAt++, repeatSpace(8) + "templates:");
            for (Map.Entry<String, Object> e : templates.entrySet()) {
                if (e.getKey() == null) continue;
                lines.add(insertAt++, repeatSpace(10) + e.getKey() + ": " + boolText(e.getValue(), false));
            }
        }
        if (!generic.isEmpty()) {
            Map<String, Object> strategies = safeMap(generic.get("strategies"));
            lines.add(insertAt++, "");
            lines.add(insertAt++, repeatSpace(8) + "generic:");
            lines.add(insertAt++, repeatSpace(10) + "enabled: " + boolText(generic.get("enabled"), false));
            if (!strategies.isEmpty()) {
                lines.add(insertAt++, repeatSpace(10) + "strategies:");
                for (Map.Entry<String, Object> e : strategies.entrySet()) {
                    if (e.getKey() == null) continue;
                    lines.add(insertAt++, repeatSpace(12) + e.getKey() + ": " + boolText(e.getValue(), false));
                }
            }
            Object variantCount = generic.get("variant_count");
            lines.add(insertAt++, repeatSpace(10) + "variant_count: "
                    + (variantCount == null ? "3" : variantCount.toString()));
        }
    }

    private String boolText(Object value, boolean defaultValue) {
        if (value instanceof Boolean) {
            return ((Boolean) value) ? "true" : "false";
        }
        return defaultValue ? "true" : "false";
    }

    private void patchGhostBitsOptions(ArrayList<String> lines, int start, int end, Map<String, Object> ghostBits) {
        if (ghostBits == null || ghostBits.isEmpty()) return;
        int ghostIdx = findChildKey(lines, start, end, 6, "ghost_bits");
        if (ghostIdx < 0) return;
        int ghostEnd = findSectionEndByIndent(lines, ghostIdx, 6);

        patchBooleanScalar(lines, ghostIdx + 1, ghostEnd, 8, "enabled", ghostBits.get("enabled"));
        patchBooleanScalar(lines, ghostIdx + 1, ghostEnd, 8, "raw_socket", ghostBits.get("raw_socket"));
        Object maxVariants = ghostBits.get("max_variants");
        if (maxVariants instanceof Number) {
            patchScalarInSection(lines, ghostIdx + 1, ghostEnd, 8,
                    "max_variants", String.valueOf(((Number) maxVariants).intValue()));
        } else if (maxVariants != null) {
            patchScalarInSection(lines, ghostIdx + 1, ghostEnd, 8,
                    "max_variants", maxVariants.toString());
        }

        Map<String, Object> templates = safeMap(ghostBits.get("templates"));
        patchNestedBools(lines, ghostIdx + 1, ghostEnd, "templates", 10, templates);

        Map<String, Object> generic = safeMap(ghostBits.get("generic"));
        ensureGhostGenericSection(lines, ghostIdx, generic);
        ghostEnd = findSectionEndByIndent(lines, ghostIdx, 6);
        patchGhostGenericOptions(lines, ghostIdx + 1, ghostEnd, generic);
    }

    private void ensureGhostGenericSection(ArrayList<String> lines, int ghostIdx, Map<String, Object> generic) {
        if (generic == null || generic.isEmpty()) return;
        int ghostEnd = findSectionEndByIndent(lines, ghostIdx, 6);
        if (findChildKey(lines, ghostIdx + 1, ghostEnd, 8, "generic") >= 0) {
            return;
        }
        int insertAt = Math.min(ghostEnd, lines.size());
        Map<String, Object> strategies = safeMap(generic.get("strategies"));
        lines.add(insertAt++, "");
        lines.add(insertAt++, repeatSpace(8) + "generic:");
        lines.add(insertAt++, repeatSpace(10) + "enabled: " + boolText(generic.get("enabled"), false));
        if (!strategies.isEmpty()) {
            lines.add(insertAt++, repeatSpace(10) + "strategies:");
            for (Map.Entry<String, Object> e : strategies.entrySet()) {
                if (e.getKey() == null) continue;
                lines.add(insertAt++, repeatSpace(12) + e.getKey() + ": " + boolText(e.getValue(), false));
            }
        }
        Object variantCount = generic.get("variant_count");
        lines.add(insertAt++, repeatSpace(10) + "variant_count: "
                + (variantCount == null ? "3" : variantCount.toString()));
    }

    private void patchGhostGenericOptions(ArrayList<String> lines, int start, int end, Map<String, Object> generic) {
        if (generic == null || generic.isEmpty()) return;
        int genericIdx = findChildKey(lines, start, end, 8, "generic");
        if (genericIdx < 0) return;
        int genericEnd = findSectionEndByIndent(lines, genericIdx, 8);

        patchBooleanScalar(lines, genericIdx + 1, genericEnd, 10, "enabled", generic.get("enabled"));
        Map<String, Object> strategies = safeMap(generic.get("strategies"));
        patchNestedBools(lines, genericIdx + 1, genericEnd, "strategies", 12, strategies);
        Object variantCount = generic.get("variant_count");
        if (variantCount instanceof Number) {
            patchScalarInSection(lines, genericIdx + 1, genericEnd, 10,
                    "variant_count", String.valueOf(((Number) variantCount).intValue()));
        } else if (variantCount != null) {
            patchScalarInSection(lines, genericIdx + 1, genericEnd, 10,
                    "variant_count", variantCount.toString());
        }
    }

    private void patchBooleanScalar(ArrayList<String> lines, int start, int end, int indent, String key, Object value) {
        if (value instanceof Boolean) {
            patchScalarInSection(lines, start, end, indent, key, ((Boolean) value) ? "true" : "false");
        }
    }

    private void patchNestedBools(ArrayList<String> lines, int start, int end, String sectionKey, int childIndent, Map<String, Object> boolMap) {
        if (boolMap == null || boolMap.isEmpty()) return;
        int secIdx = findChildKey(lines, start, end, childIndent - 2, sectionKey);
        if (secIdx < 0) return;
        int secEnd = findSectionEndByIndent(lines, secIdx, childIndent - 2);
        for (Map.Entry<String, Object> e : boolMap.entrySet()) {
            String k = e.getKey();
            if (k == null) continue;
            Boolean v = (e.getValue() instanceof Boolean) ? (Boolean) e.getValue() : null;
            if (v == null) continue;
            patchScalarInSection(lines, secIdx + 1, secEnd, childIndent, k, v ? "true" : "false");
        }
    }

    private Map<String, Object> safeMap(Object o) {
        if (o instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) o;
            return m;
        }
        return Collections.emptyMap();
    }

    private static int findTopLevelKey(ArrayList<String> lines, String key) {
        String prefix = key + ":";
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static int findChildKey(ArrayList<String> lines, int start, int end, int indent, String key) {
        String prefix = repeatSpace(indent) + key + ":";
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static int findTopLevelSectionEnd(ArrayList<String> lines, int startIdx) {
        for (int i = startIdx + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.isEmpty() || line.startsWith("#")) continue;
            // 顶层 key：非空白开头且包含 ":"
            if (!Character.isWhitespace(line.charAt(0)) && line.contains(":")) {
                return i;
            }
        }
        return lines.size();
    }

    private static int findSectionEndByIndent(ArrayList<String> lines, int startIdx, int indent) {
        for (int i = startIdx + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.isEmpty()) continue;
            int leading = countLeadingSpaces(line);
            if (leading <= indent && !line.startsWith("#")) {
                return i;
            }
        }
        return lines.size();
    }

    private static void patchScalarInSection(ArrayList<String> lines, int start, int end, int indent, String key, String value) {
        Pattern p = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + key) + "\\s*:\\s*([^#]*)(.*)$");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            Matcher m = p.matcher(line);
            if (m.find()) {
                String tail = m.group(2) == null ? "" : m.group(2);
                lines.set(i, repeatSpace(indent) + key + ": " + value + tail);
                return;
            }
        }
        // 未找到：插入到 section 末尾前
        int insertAt = Math.min(end, lines.size());
        lines.add(insertAt, repeatSpace(indent) + key + ": " + value);
    }

    private static void patchScalarAfterKeyInSection(ArrayList<String> lines, int start, int end, int indent,
                                                     String key, String value, String afterKey) {
        Pattern target = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + key) + "\\s*:\\s*([^#]*)(.*)$");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            Matcher m = target.matcher(line);
            if (m.find()) {
                String tail = m.group(2) == null ? "" : m.group(2);
                lines.set(i, repeatSpace(indent) + key + ": " + value + tail);
                return;
            }
        }

        Pattern anchor = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + afterKey) + "\\s*:");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line != null && anchor.matcher(line).find()) {
                lines.add(i + 1, repeatSpace(indent) + key + ": " + value);
                return;
            }
        }
        int insertAt = Math.min(end, lines.size());
        lines.add(insertAt, repeatSpace(indent) + key + ": " + value);
    }

    private static int countLeadingSpaces(String s) {
        int c = 0;
        while (c < s.length() && s.charAt(c) == ' ') c++;
        return c;
    }

    private static String repeatSpace(int n) {
        if (n <= 0) return "";
        char[] buf = new char[n];
        for (int i = 0; i < n; i++) buf[i] = ' ';
        return new String(buf);
    }

    private Yaml createSecureYaml() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setProcessComments(false);
        loaderOptions.setAllowRecursiveKeys(false);

        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

        Representer representer = new Representer(dop);
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private String determineConfigDirPath() {
        String userConfigPath = System.getProperty("user.home") + File.separator + CONFIG_DIR_NAME;
        if (isValidConfigDir(userConfigPath)) {
            return userConfigPath;
        }

        String jarConfigPath = getJarConfigPath();
        if (jarConfigPath != null && isValidConfigDir(jarConfigPath)) {
            return jarConfigPath;
        }

        return userConfigPath;
    }

    private static boolean isValidConfigDir(String path) {
        File f = new File(path);
        return f.exists() && f.isDirectory();
    }

    private String getJarConfigPath() {
        try {
            URL location = Utils.class.getProtectionDomain().getCodeSource().getLocation();
            if (location == null) {
                return null;
            }
            URI uri = location.toURI();
            File base = new File(uri);
            File dir = base.isDirectory() ? base : base.getParentFile();
            if (dir == null) {
                return null;
            }
            return dir.getAbsolutePath() + File.separator + CONFIG_DIR_NAME;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean copyDefaultConfigToFile(String targetFilePath) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(CLASSPATH_RESOURCE);
        if (inputStream == null) {
            return false;
        }
        File targetFile = new File(targetFilePath);

        try (InputStream in = inputStream; OutputStream out = new FileOutputStream(targetFile)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
