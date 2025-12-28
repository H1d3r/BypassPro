package Main;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class Utils {

    static boolean gotBurp = false;
    public static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    @SuppressWarnings("unused")
    private static PrintWriter stderr;
    static MainPanel panel;
    public static long count = 0;
    // Auto Scan 开关
    public static boolean isProxySelected = false;
    public static Map<String, Object> configMap = null;
    private static ConfigLoader configLoader;
    private static volatile ExecutorService sharedExecutor;
    private static volatile int sharedExecutorThreads = -1;

    public static void setConfigLoader(ConfigLoader loader) {
        configLoader = loader;
    }

    public static ConfigLoader getConfigLoader() {
        return configLoader;
    }

    public static void setConfigMap(Map<String, Object> config) {

        if (config == null) {
            Utils.configMap = Collections.emptyMap();
            System.out.println("!! config为null,已清空当前规则");
            return;
        }
        Utils.configMap = config;
        if (config.isEmpty()) {
            System.out.println("!! config内容为空,已清空当前规则");
        }

    }

    /**
     * 兼容两种配置结构：
     * 1) 旧版：顶层就是 suffix/prefix/headers
     * 2) 新版：profiles: { access_control: {suffix/prefix/headers}, waf: {...} }
     */
    public static Map<String, Object> getProfileConfig(String profile) {
        if (configMap == null) {
            return Collections.emptyMap();
        }

        Object profilesObj = configMap.get("profiles");
        if (profilesObj instanceof Map) {
            Map<?, ?> profiles = (Map<?, ?>) profilesObj;
            Object p = profiles.get(profile);
            if (p instanceof Map) {
                return castStringObjectMap(p);
            }
            Object ac = profiles.get("access_control");
            if (ac instanceof Map) {
                return castStringObjectMap(ac);
            }
        }

        return configMap;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castStringObjectMap(Object o) {
        return (Map<String, Object>) o;
    }

    /**
     * 获取指定 profile 的 options
     * @param profile profile 名称（access_control / waf）
     * @return options Map，如果不存在返回 emptyMap
     */
    public static Map<String, Object> getProfileOptions(String profile) {
        Map<String, Object> profileConfig = getProfileConfig(profile);
        if (profileConfig == null || profileConfig.isEmpty()) {
            return Collections.emptyMap();
        }

        Object optionsObj = profileConfig.get("options");
        if (optionsObj instanceof Map) {
            return castStringObjectMap(optionsObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 body_charset 配置
     * @return body_charset Map，包含各种字符集的 true/false
     */
    public static Map<String, Object> getWafBodyCharsetOptions() {
        Map<String, Object> options = getProfileOptions("waf");
        Object charsetObj = options.get("body_charset");
        if (charsetObj instanceof Map) {
            return castStringObjectMap(charsetObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 body_transform 配置
     * @return body_transform Map
     */
    public static Map<String, Object> getWafBodyTransformOptions() {
        Map<String, Object> options = getProfileOptions("waf");
        Object transformObj = options.get("body_transform");
        if (transformObj instanceof Map) {
            return castStringObjectMap(transformObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 content_type_spoof 配置
     * @return content_type_spoof Map
     */
    public static Map<String, Object> getWafContentTypeSpoofOptions() {
        Map<String, Object> options = getProfileOptions("waf");
        Object ctObj = options.get("content_type_spoof");
        if (ctObj instanceof Map) {
            return castStringObjectMap(ctObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 general 配置
     */
    public static Map<String, Object> getGeneralConfig() {
        if (configMap == null) {
            return Collections.emptyMap();
        }
        Object generalObj = configMap.get("general");
        if (generalObj instanceof Map) {
            return castStringObjectMap(generalObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取配置的线程数
     */
    public static int getConfigThreads(int defaultValue) {
        Map<String, Object> general = getGeneralConfig();
        Object threadsObj = general.get("threads");
        if (threadsObj instanceof Number) {
            return ((Number) threadsObj).intValue();
        }
        return defaultValue;
    }

    /**
     * 获取配置的相似度阈值
     */
    public static double getConfigSimilarityThreshold(double defaultValue) {
        Map<String, Object> general = getGeneralConfig();
        Object thresholdObj = general.get("similarity_threshold");
        if (thresholdObj instanceof Number) {
            return ((Number) thresholdObj).doubleValue();
        }
        return defaultValue;
    }

    /**
     * 获取 access_control 的 ignore_extensions 列表
     */
    @SuppressWarnings("unchecked")
    public static List<String> getIgnoreExtensions() {
        Map<String, Object> ac = getProfileConfig("access_control");
        Object extObj = ac.get("ignore_extensions");
        if (extObj instanceof List) {
            return (List<String>) extObj;
        }
        return Collections.emptyList();
    }

    public static void setBurpPresent(IBurpExtenderCallbacks incallbacks) {
        gotBurp = true;
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    public static void out(String message) {
        if (gotBurp) {
            stdout.println(message);
        }
        else {
            System.out.println(message);
        }

    }

    public static void setPanel(MainPanel inpanel) {
        panel = inpanel;
    }

    /**
     * 全局共享线程池（避免每次扫描创建大量线程池导致资源耗尽）
     */
    public static synchronized ExecutorService getSharedExecutor(int threads) {
        int n = threads;
        if (n <= 0) {
            n = 1;
        }
        if (sharedExecutor == null || sharedExecutor.isShutdown() || sharedExecutor.isTerminated() || sharedExecutorThreads != n) {
            ExecutorService old = sharedExecutor;
            sharedExecutor = Executors.newFixedThreadPool(n, new ThreadFactory() {
                private final AtomicInteger idx = new AtomicInteger(1);

                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r);
                    t.setName("BypassPro-" + idx.getAndIncrement());
                    return t;
                }
            });
            sharedExecutorThreads = n;
            if (old != null) {
                try {
                    old.shutdown();
                } catch (Exception ignored) {}
            }
        }
        return sharedExecutor;
    }

    public static synchronized void shutdownSharedExecutor() {
        if (sharedExecutor != null) {
            try {
                sharedExecutor.shutdownNow();
            } catch (Exception ignored) {}
            sharedExecutor = null;
            sharedExecutorThreads = -1;
        }
    }


    public static String getBodyTitle(String s) {
        String regex;
        String title = "";
        final List<String> list = new ArrayList<String>();
        regex = "<title>.*?</title>";
        final Pattern pa = Pattern.compile(regex, Pattern.CANON_EQ);
        final Matcher ma = pa.matcher(s);
        while (ma.find()) {
            list.add(ma.group());
        }

        for (int i = 0; i < list.size(); i++) {
            title = title + list.get(i);
        }

        return title.replaceAll("<.*?>", "");
    }
    public static Map<String, Object> loadConfig(String filename){
        if (configLoader != null) {
            return configLoader.loadConfig();
        }
        Map<String, Object> yamlMap=null;
        // 读取YAML文件
        try {
            InputStream inputStream = BypassMain.class.getResourceAsStream(filename);

            Yaml yaml = new Yaml();
            // 将YAML文件的内容加载为Map对象
            yamlMap = yaml.load(inputStream);
            inputStream.close();
        } catch (Exception exception) {
            System.out.println("配置文件加载失败，请检查配置文件 BypassPro-config.yaml");
            exception.printStackTrace();
        }
        return yamlMap;

    }


}
