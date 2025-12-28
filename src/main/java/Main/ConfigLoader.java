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
        try {
            String raw = readConfigText();
            if (raw == null || raw.isEmpty()) {
                // 文件为空时退化为结构化写入
                Map<String, Object> config = loadConfig();
                if (config.isEmpty()) {
                    config = new LinkedHashMap<>();
                }
                Map<String, Object> general = new LinkedHashMap<>();
                general.put("threads", threads);
                general.put("similarity_threshold", similarityThreshold);
                config.put("general", general);
                return writeConfig(config);
            }
            String patched = patchGeneralSection(raw, threads, similarityThreshold);
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
                Object wafObj = profiles.get("waf");
                Map<String, Object> waf = wafObj instanceof Map ? (Map<String, Object>) wafObj : new LinkedHashMap<>();
                profiles.put("waf", waf);
                waf.put("options", options);
                return writeConfig(config);
            }
            String patched = patchWafOptionsSection(raw, options);
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

    private String patchGeneralSection(String raw, int threads, double similarityThreshold) {
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int generalIdx = findTopLevelKey(lines, "general");
        if (generalIdx < 0) {
            // 直接在文件头追加 general（保守）
            StringBuilder sb = new StringBuilder(raw.length() + 128);
            sb.append("general:\n");
            sb.append("  threads: ").append(threads).append("\n");
            sb.append("  similarity_threshold: ").append(similarityThreshold).append("\n\n");
            sb.append(raw);
            return sb.toString();
        }

        int end = findTopLevelSectionEnd(lines, generalIdx);
        patchScalarInSection(lines, generalIdx + 1, end, 2, "threads", String.valueOf(threads));
        patchScalarInSection(lines, generalIdx + 1, end, 2, "similarity_threshold", String.valueOf(similarityThreshold));
        return String.join("\n", lines);
    }

    private String patchWafOptionsSection(String raw, Map<String, Object> options) {
        if (options == null || options.isEmpty()) {
            return raw;
        }
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int profilesIdx = findTopLevelKey(lines, "profiles");
        if (profilesIdx < 0) {
            // 不做结构插入，避免大改用户文件；退化为原样返回
            return raw;
        }
        int profilesEnd = findTopLevelSectionEnd(lines, profilesIdx);
        int wafIdx = findChildKey(lines, profilesIdx + 1, profilesEnd, 2, "waf");
        if (wafIdx < 0) {
            return raw;
        }
        int wafEnd = findSectionEndByIndent(lines, wafIdx, 2);
        int optionsIdx = findChildKey(lines, wafIdx + 1, wafEnd, 4, "options");
        if (optionsIdx < 0) {
            return raw;
        }
        int optionsEnd = findSectionEndByIndent(lines, optionsIdx, 4);

        // 只更新已知开关（保持注释/格式）：body_charset/body_transform/content_type_spoof
        Map<String, Object> bodyCharset = safeMap(options.get("body_charset"));
        Map<String, Object> bodyTransform = safeMap(options.get("body_transform"));
        Map<String, Object> contentTypeSpoof = safeMap(options.get("content_type_spoof"));

        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "body_charset", 6, bodyCharset);
        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "body_transform", 6, bodyTransform);
        patchNestedBools(lines, optionsIdx + 1, optionsEnd, "content_type_spoof", 6, contentTypeSpoof);

        return String.join("\n", lines);
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


