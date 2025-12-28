package burp;

import Main.*;
import java.io.PrintWriter;
import java.util.Map;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private PrintWriter stdout;
    public static IBurpExtenderCallbacks callbacks;
    private MainPanel panel;
    private String NAME = "BypassPro";
    private String VERSION = "4.0";


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {


        BurpExtender.callbacks = callbacks;
        Utils.setBurpPresent(callbacks);


        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("BypassPro");

        // 加载配置
        ConfigLoader configLoader = new ConfigLoader();
        Utils.setConfigLoader(configLoader);
        Map<String, Object> config = configLoader.loadConfig();
        Utils.setConfigMap(config);

        this.panel = new MainPanel();
        Utils.setPanel(this.panel);
        callbacks.addSuiteTab(this.panel);

        BypassMain bypassMain = new BypassMain();

        callbacks.registerContextMenuFactory(bypassMain);
        callbacks.registerProxyListener(bypassMain);
        callbacks.registerExtensionStateListener(this);

        banner();

    }

    @Override
    public void extensionUnloaded() {
        // 释放全局线程池，避免 Burp 资源泄漏
        Utils.shutdownSharedExecutor();
    }

    private void banner() {
        this.stdout.println("===================================");
        this.stdout.println(String.format("%s loaded success", NAME));
        this.stdout.println(String.format("version: %s", VERSION));
        this.stdout.println("hooray195,  0cat");
        this.stdout.println("===================================");
    }

}