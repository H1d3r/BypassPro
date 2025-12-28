package Main;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.zip.GZIPOutputStream;

public class BypassMain implements IContextMenuFactory ,IProxyListener{

    // 重定向最大跳数
    private static final int MAX_REDIRECT_HOPS = 2;

    private static synchronized long nextId() {
        return Utils.count++;
    }


    /**
     * 生成 payload 变体
     * @param path 原始路径
     * @param profile 配置 profile 名称
     * @param method 原始请求方法（GET/POST/PUT 等）
     */
    public List<BaseRequest> make_payload_v2(String path, String profile, String method) {
        if (path == null || path.isEmpty()) {
            path = "";
        }
        // 兼容非标准请求：仅在以 "/" 开头时才去掉首字符
        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        Boolean isEnd = false;

        if(!path.isEmpty() && path.endsWith("/")) {
            path = path.substring(0, path.length()-1);
            isEnd = true;
        }
        String[] paths = path.isEmpty() ? new String[0] : path.split("/");

        Map<String, Object> profileConfig = Utils.getProfileConfig(profile);
        List<BaseRequest> allRequests = new ArrayList<>();
        List<String> suffixList = safeStringList(profileConfig.get("suffix"));
        if(isEnd) {
            allRequests.addAll(makeRequestSuffix(suffixList, path, method));
            allRequests.addAll(makeRequestSuffix(suffixList, path + "/", method));
        } else {
            allRequests.addAll(makeRequestSuffix(suffixList, path, method));
        }

        // prefix 规则：对每层目录前置变形
        List<String> prefixList = safeStringList(profileConfig.get("prefix"));
        if( paths.length > 1) {
            int paths_len = paths.length;
            if (isEnd) {
                allRequests.addAll(makeRequestPrefix(prefixList, paths, paths_len, "/", method));
            } else {
                allRequests.addAll(makeRequestPrefix(prefixList, paths, paths_len, "", method));
            }
        }

        // 对每一级目录边界进行插入FUZZ（一次只插入一个边界，避免组合爆炸）
        List<String> insertList = safeStringList(profileConfig.get("boundary_insert"));
        if (!insertList.isEmpty() && paths.length > 1) {
            allRequests.addAll(makeRequestBoundaryInsert(insertList, paths, isEnd ? "/" : "", method));
        }

        // headers 规则：Header 伪造变体
        List<?> headersList = safeList(profileConfig.get("headers"));
        allRequests.addAll(makeRequestHeader(headersList, path, method));

        return deduplicateRequests(allRequests);

    }

    private static List<?> safeList(Object o) {
        if (o instanceof List) {
            return (List<?>) o;
        }
        return Collections.emptyList();
    }

    private static List<String> safeStringList(Object o) {
        if (!(o instanceof List)) {
            return Collections.emptyList();
        }
        List<?> in = (List<?>) o;
        List<String> out = new ArrayList<>(in.size());
        for (Object x : in) {
            if (x == null) continue;
            out.add(String.valueOf(x));
        }
        return out;
    }

    private static List<BaseRequest> deduplicateRequests(List<BaseRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return requests;
        }

        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<BaseRequest> out = new ArrayList<>(requests.size());
        for (BaseRequest r : requests) {
            if (r == null) {
                continue;
            }
            String key = buildDedupKey(r);
            if (seen.add(key)) {
                out.add(r);
            }
        }
        return out;
    }

    private static String buildDedupKey(BaseRequest r) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.valueOf(r.method)).append(' ').append(String.valueOf(r.path));
        Map<String, String> h = r.headers;
        if (h == null || h.isEmpty()) {
            sb.append(" H:{}");
            return sb.toString();
        }
        ArrayList<String> pairs = new ArrayList<>(h.size());
        for (Map.Entry<String, String> e : h.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            if (k == null) continue;
            pairs.add(k.trim().toLowerCase() + "=" + String.valueOf(v));
        }
        Collections.sort(pairs);
        sb.append(" H:{").append(StringUtils.join(pairs, ";")).append('}');
        return sb.toString();
    }


    public static List<BaseRequest> makeRequestSuffix(List<String> suffixList, String path, String method){
        List<BaseRequest> baseRequestList = new ArrayList<>();

        for (String item : suffixList) {
            baseRequestList.add(new BaseRequest(method, "/" + path + item, null));
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestPrefix(List<String> prefixList, String[] paths, int paths_len, String end, String method){
        List<BaseRequest> baseRequestList = new ArrayList<>();
        for (String item : prefixList) {
            for (int i=0; i < paths_len; i++) {
                String _target = paths[i];
                String new_path = "";

                paths[i] = item + _target;
                new_path = StringUtils.join(paths, "/") + end;
                baseRequestList.add(new BaseRequest(method, "/" + new_path, null));
                paths[i] = _target;
            }
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestHeader(List<?> headerList, String path, String method){
        List<BaseRequest> baseRequestList = new ArrayList<>();
        for (Object item : headerList) {
            if(item instanceof Map){
                @SuppressWarnings("unchecked")
                Map<String, String> headers = (Map<String, String>) ((HashMap<String, String>) item).clone();
                baseRequestList.add(new BaseRequest(method, "/" + path, headers));
            }
        }
        return baseRequestList;
    }

    /**
     * 在目录边界插入标记（一次只改一个边界）：
     * a/b/c  + ";"  => a;/b/c、a/b;/c
     */
    public static List<BaseRequest> makeRequestBoundaryInsert(List<String> insertList, String[] paths, String end, String method) {
        List<BaseRequest> baseRequestList = new ArrayList<>();
        if (insertList == null || insertList.isEmpty() || paths == null || paths.length < 2) {
            return baseRequestList;
        }

        int pathsLen = paths.length;
        for (String insert : insertList) {
            if (insert == null || insert.isEmpty()) {
                continue;
            }
            for (int i = 0; i < pathsLen - 1; i++) {
                String original = paths[i];
                paths[i] = original + insert;
                String newPath = StringUtils.join(paths, "/") + end;
                baseRequestList.add(new BaseRequest(method, "/" + newPath, null));
                paths[i] = original;
            }
        }

        return baseRequestList;
    }



    class Run_request implements Runnable {
        private BaseRequest baseRequest;
        private IHttpRequestResponse iHttpRequestResponse;
        private String tool;

        public Run_request(BaseRequest baseRequest, IHttpRequestResponse iHttpRequestResponse, String tool) {
            this.baseRequest = baseRequest;
            this.iHttpRequestResponse = iHttpRequestResponse;
            this.tool=tool;
        }

        @Override
        public void run() {

            String method = baseRequest.method;
            String path = baseRequest.path;
            Map<String, String> headers = baseRequest.headers;

            try {
                byte[] oldRequestBytes = iHttpRequestResponse.getRequest();
                if (oldRequestBytes == null) {
                    Utils.panel.addErrorRequestNum(1);
                    return;
                }

                IRequestInfo requestInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), oldRequestBytes);
                List<String> newHeaders = new ArrayList<>(requestInfo.getHeaders());
                if (newHeaders.isEmpty()) {
                    Utils.panel.addErrorRequestNum(1);
                    return;
                }

                // 请求行：METHOD path HTTP/x.x
                String requestLine = newHeaders.get(0);
                String[] parts = requestLine.split(" ", 3);
                if (parts.length < 3) {
                    Utils.panel.addErrorRequestNum(1);
                    return;
                }

                String httpVersion = parts[2];
                if (headers != null && headers.containsKey("HTTP-Version")) {
                    httpVersion = headers.get("HTTP-Version");
                }

                String newRequestLine = method + " " + path + " " + httpVersion;

                // 只改请求行，不清空原始请求头
                newHeaders.set(0, newRequestLine);
                if (headers != null) {
                    for (Map.Entry<String, String> e : headers.entrySet()) {
                        String key = e.getKey();
                        String value = e.getValue();
                        if (key == null || value == null || "HTTP-Version".equals(key)) {
                            continue;
                        }

                        int idx = findHeaderIndex(newHeaders, key);
                        if (idx >= 0) {
                            newHeaders.set(idx, key + ": " + value);
                        } else {
                            newHeaders.add(key + ": " + value);
                        }
                    }
                }

                int bodyOffset = requestInfo.getBodyOffset();
                byte[] body = null;
                if (bodyOffset >= 0 && bodyOffset < oldRequestBytes.length) {
                    body = Arrays.copyOfRange(oldRequestBytes, bodyOffset, oldRequestBytes.length);
                }
                byte[] newRequestBytes = Utils.helpers.buildHttpMessage(newHeaders, body);

                IHttpRequestResponse firstResponse = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newRequestBytes);
                IHttpRequestResponse finalResponse = followRedirectsIfNeeded(firstResponse, newRequestBytes, iHttpRequestResponse.getHttpService(), MAX_REDIRECT_HOPS);

                byte[] oldResponseBytes = iHttpRequestResponse.getResponse();
                byte[] finalResponseBytes = (finalResponse == null) ? null : finalResponse.getResponse();

                short oldStatus = getStatusSafe(oldResponseBytes);
                short newStatus = getStatusSafe(finalResponseBytes);
                String newMime = getMimeSafe(finalResponseBytes);

                String oldBody = extractBodyAsString(oldResponseBytes);
                String newBody = extractBodyAsString(finalResponseBytes);
                double threshold = Utils.panel.getSimilarityThreshold();
                double ratio = DiffPage.getRatio(oldBody, newBody, newMime);
                boolean statusClassChanged = (oldStatus > 0 && newStatus > 0) && (oldStatus / 100 != newStatus / 100);

                boolean shouldLog = isCandidateStatus(newStatus) && (ratio < threshold || statusClassChanged);

                //Utils.panel.addFinishRequestNum(1);
                addFinishRequestNum(1);

                if (finalResponse != null && finalResponseBytes != null && shouldLog) {
                    String title = Utils.getBodyTitle(new String(finalResponseBytes, "utf-8"));
                    addLog(finalResponse, 0, 0, 0, title, tool);
                }


            }catch(Throwable ee) {
                Utils.panel.addErrorRequestNum(1);

            }
        }
    }

    private static boolean isCandidateStatus(short statusCode) {
        return statusCode == 200 || statusCode == 206 || statusCode == 304
                || statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
                || statusCode == 405 || statusCode == 415;
    }

    private static boolean isRedirectStatus(short statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private static short getStatusSafe(byte[] responseBytes) {
        if (responseBytes == null) {
            return -1;
        }
        try {
            return Utils.helpers.analyzeResponse(responseBytes).getStatusCode();
        } catch (Exception e) {
            return -1;
        }
    }

    private static String getMimeSafe(byte[] responseBytes) {
        if (responseBytes == null) {
            return "";
        }
        try {
            return Utils.helpers.analyzeResponse(responseBytes).getStatedMimeType();
        } catch (Exception e) {
            return "";
        }
    }

    private static String extractBodyAsString(byte[] responseBytes) {
        if (responseBytes == null) {
            return "";
        }
        try {
            IResponseInfo info = Utils.helpers.analyzeResponse(responseBytes);
            int offset = info.getBodyOffset();
            if (offset < 0 || offset >= responseBytes.length) {
                return "";
            }
            byte[] body = Arrays.copyOfRange(responseBytes, offset, responseBytes.length);
            return new String(body, "utf-8");
        } catch (Exception e) {
            return "";
        }
    }

    private static String findHeaderValue(List<String> headers, String name) {
        if (headers == null || name == null) {
            return null;
        }
        for (String h : headers) {
            if (h == null) continue;
            if (h.regionMatches(true, 0, name, 0, name.length()) && h.length() > name.length() && h.charAt(name.length()) == ':') {
                return h.substring(name.length() + 1).trim();
            }
        }
        return null;
    }

    private IHttpRequestResponse followRedirectsIfNeeded(IHttpRequestResponse firstResponse, byte[] originalRequestBytes, IHttpService service, int maxHops) {
        if (firstResponse == null || firstResponse.getResponse() == null || service == null) {
            return firstResponse;
        }

        IHttpRequestResponse current = firstResponse;
        java.util.HashSet<String> visited = new java.util.HashSet<>();

        for (int i = 0; i < maxHops; i++) {
            byte[] resp = current.getResponse();
            if (resp == null) {
                return current;
            }
            short code = getStatusSafe(resp);
            if (!isRedirectStatus(code)) {
                return current;
            }

            List<String> headers = Utils.helpers.analyzeResponse(resp).getHeaders();
            String location = findHeaderValue(headers, "Location");
            if (location == null || location.isEmpty()) {
                return current;
            }

            try {
                URL base = Utils.helpers.analyzeRequest(service, originalRequestBytes).getUrl();
                URL next = new URL(base, location);
                if (!service.getHost().equalsIgnoreCase(next.getHost())) {
                    return current;
                }
                String protocol = next.getProtocol();
                if (protocol != null && !protocol.equalsIgnoreCase(service.getProtocol())) {
                    return current;
                }
                String key = next.toString();
                if (!visited.add(key)) {
                    return current;
                }

                String method = (code == 307 || code == 308) ? Utils.helpers.analyzeRequest(service, originalRequestBytes).getMethod() : "GET";
                byte[] nextReq = buildFollowRequest(originalRequestBytes, service, next, method);
                current = Utils.callbacks.makeHttpRequest(service, nextReq);
                if (current == null) {
                    return null;
                }
            } catch (Exception e) {
                return current;
            }
        }

        return current;
    }

    private byte[] buildFollowRequest(byte[] originalRequestBytes, IHttpService service, URL nextUrl, String method) {
        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(service, originalRequestBytes);
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        if (headers.isEmpty()) {
            return originalRequestBytes;
        }

        String requestLine = headers.get(0);
        String[] parts = requestLine.split(" ", 3);
        String httpVersion = parts.length >= 3 ? parts[2] : "HTTP/1.1";
        String path = nextUrl.getFile();
        headers.set(0, method + " " + path + " " + httpVersion);

        // 307/308 保留原 body，其它情况默认不带 body
        byte[] body = null;
        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            int bodyOffset = requestInfo.getBodyOffset();
            if (bodyOffset >= 0 && bodyOffset < originalRequestBytes.length) {
                body = Arrays.copyOfRange(originalRequestBytes, bodyOffset, originalRequestBytes.length);
            }
        }

        // method 变更/重定向跟随时，清理与 body 强相关的头，避免 GET 还带旧 Content-Length 导致异常
        if (body == null) {
            removeHeadersIgnoreCase(headers, "Content-Length", "Transfer-Encoding", "Content-Type", "Content-Encoding", "Expect");
        } else {
            removeHeadersIgnoreCase(headers, "Transfer-Encoding", "Expect");
            updateOrAddHeader(headers, "Content-Length", String.valueOf(body.length));
        }
        return Utils.helpers.buildHttpMessage(headers, body);
    }

    private void removeHeadersIgnoreCase(List<String> headers, String... names) {
        if (headers == null || headers.size() <= 1 || names == null || names.length == 0) {
            return;
        }
        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i);
            if (h == null) continue;
            int colon = h.indexOf(':');
            if (colon <= 0) continue;
            String n = h.substring(0, colon).trim();
            for (String name : names) {
                if (name == null) continue;
                if (n.equalsIgnoreCase(name)) {
                    headers.remove(i);
                    break;
                }
            }
        }
    }


    /**
     * 右键菜单：Send to BypassPro (Access Control / WAF)
     */
    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<JMenuItem>();

        if(invocation != null && invocation.getSelectedMessages() != null && invocation.getSelectedMessages()[0] != null && invocation.getSelectedMessages()[0].getHttpService() != null) {
            JMenuItem acMenuItem = new JMenuItem("Send to BypassPro (Access Control)");
            JMenuItem wafMenuItem = new JMenuItem("Send to BypassPro (WAF)");
            JMenuItem manualWafMenuItem = new JMenuItem("Send to BypassPro (Manual WAF)");

            acMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {

                    new Thread(() -> {
                        IHttpRequestResponse[] iHttpRequestResponses = invocation.getSelectedMessages();
                        processHttp(iHttpRequestResponses, "Auth Bypass (Auto)", "access_control");
                    }).start();

                }
            });

            wafMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    new Thread(() -> {
                        IHttpRequestResponse[] iHttpRequestResponses = invocation.getSelectedMessages();
                        // WAF 模式：若配置未提供 waf profile，会回退到 access_control
                        processHttp(iHttpRequestResponses, "WAF Bypass (Auto)", "waf");
                    }).start();
                }
            });

            manualWafMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    SwingUtilities.invokeLater(() -> {
                        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                        if (messages != null && messages.length > 0) {
                            // 加载到 Manual WAF 面板
                            Utils.panel.getManualWafPanel().loadRequest(messages[0]);
                        }
                    });
                }
            });

            list.add(acMenuItem);
            list.add(wafMenuItem);
            list.add(manualWafMenuItem);
        }
        return list;
    }

    private void addLog(IHttpRequestResponse messageInfo, int toolFlag, long time, int row, String title, String tool) {
        // 入表写 UI：放到 EDT 串行执行，避免并发写 ArrayList 造成数据竞争
        try {
            short statusCode = Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode();
            if (statusCode == 200 || statusCode == 405 || statusCode == 415) {
                Utils.panel.getBypassTableModel().addBypass(new Bypass(
                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                        Utils.helpers.analyzeRequest(messageInfo).getMethod(),
                        String.valueOf(messageInfo.getResponse().length),
                        Utils.callbacks.saveBuffersToTempFiles(messageInfo),
                        Utils.helpers.analyzeRequest(messageInfo).getUrl(),
                        Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode(),
                        Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType(),
                        title,
                        nextId(), tool));
            }
        } catch (Exception ignored) {}
    }

    private static int findHeaderIndex(List<String> headers, String headerName) {
        if (headers == null || headerName == null) return -1;
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null) continue;
            int colon = h.indexOf(':');
            if (colon <= 0) continue;
            String name = h.substring(0, colon).trim();
            if (name.equalsIgnoreCase(headerName)) {
                return i;
            }
        }
        return -1;
    }


    private static synchronized void addAllRequestNum(int num) {
        Utils.panel.addAllRequestNum(num);
    }
    private static synchronized  void addFinishRequestNum(int num) {
        Utils.panel.addFinishRequestNum(num);
    }
//    public void setThread_num(int number) {
//        thread_num = number;
//    }

    public void processHttp(IHttpRequestResponse[] iHttpRequestResponses, String tool, String profile) {

        for(IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponses) {
            IRequestInfo reqInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse);
            String old_path = reqInfo.getUrl().getPath();
            String originalMethod = reqInfo.getMethod();  // 获取原始请求方法
            // response 可能为空（例如主动扫描选中未返回的请求），避免这里直接 NPE

            List<BaseRequest> allRequests;
            allRequests = make_payload_v2(old_path, profile, originalMethod);

            int thread_num = Utils.panel.getThreadNum();

            Utils.out("start thread, number: " + String.valueOf(thread_num) + " path: " + old_path);
            ExecutorService es = Utils.getSharedExecutor(thread_num);

            // 更新请求计数
            addAllRequestNum(allRequests.size());
            for(BaseRequest baseRequest: allRequests) {
                es.submit(new BypassMain.Run_request(baseRequest, iHttpRequestResponse, tool));
            }

            // WAF 模式：额外生成 Body 编码变体（仅 POST/PUT/PATCH）
            if ("waf".equals(profile)) {
                byte[] requestBytes = iHttpRequestResponse.getRequest();
                if (requestBytes != null) {
                    IRequestInfo wafReqInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), requestBytes);
                    String wafMethod = wafReqInfo.getMethod();

                    if (hasBody(wafMethod, requestBytes, wafReqInfo)) {
                        List<byte[]> bodyEncodedRequests = generateBodyEncodedRequests(requestBytes, wafReqInfo, iHttpRequestResponse.getHttpService());
                        addAllRequestNum(bodyEncodedRequests.size());

                        for (byte[] encodedRequest : bodyEncodedRequests) {
                            es.submit(new Run_body_encoded_request(encodedRequest, iHttpRequestResponse, tool));
                        }
                    }
                }
            }

            // 使用全局共享线程池：不在此处 shutdown
        }

    }

    /**
     * 判断请求是否有 Body
     */
    private boolean hasBody(String method, byte[] requestBytes, IRequestInfo reqInfo) {
        // 不依赖 HTTP Method：只要存在 bodyOffset 就认为“有 Body”
        int bodyOffset = reqInfo.getBodyOffset();
        return bodyOffset > 0 && bodyOffset < requestBytes.length;
    }

    /**
     * 生成 Body 编码变体请求
     */
    private List<byte[]> generateBodyEncodedRequests(byte[] originalRequest, IRequestInfo reqInfo, IHttpService service) {
        List<byte[]> result = new ArrayList<>();

        int bodyOffset = reqInfo.getBodyOffset();
        byte[] originalBody = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);
        List<String> originalHeaders = new ArrayList<>(reqInfo.getHeaders());

        // 如果原始请求是 chunked 传输，则 body 区域很可能包含 chunk framing，直接做编码/压缩/类型欺骗会破坏语义
        // 这里保守处理：跳过所有 body 变体（避免发送格式错误的请求）
        if (hasHeaderToken(originalHeaders, "Transfer-Encoding", "chunked")) {
            return result;
        }

        String originalContentType = getOriginalContentType(originalHeaders);

        Map<String, Object> charsetOptions = Utils.getWafBodyCharsetOptions();
        Map<String, Object> transformOptions = Utils.getWafBodyTransformOptions();
        Map<String, Object> ctOptions = Utils.getWafContentTypeSpoofOptions();

        // Body Charset 变体（仅对文本类 body 生效；二进制/已 gzip 会跳过）
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16be"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16BE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16be"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16le"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16LE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16le"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32be"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32BE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32be"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32le"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32LE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32le"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("ibm037"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "IBM037", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "ibm037"));
            }
        }

        // Gzip 变体（避免重复 gzip：原始已 gzip 则跳过）
        if (Boolean.TRUE.equals(transformOptions.get("gzip")) && !hasHeaderToken(originalHeaders, "Content-Encoding", "gzip")) {
            byte[] gzipped = gzipBody(originalBody);
            if (gzipped != null) {
                result.add(buildRequestWithGzipBody(originalHeaders, gzipped));
            }
        }

        // Content-Type Spoof 变体
        if (Boolean.TRUE.equals(ctOptions.get("form_urlencoded"))) {
            if (!originalContentType.toLowerCase().contains("x-www-form-urlencoded")) {
                result.add(buildRequestWithContentType(originalHeaders, originalBody, "application/x-www-form-urlencoded"));
            }
        }
        if (Boolean.TRUE.equals(ctOptions.get("multipart"))) {
            if (!originalContentType.toLowerCase().contains("multipart")) {
                String boundary = generateRandomBoundary();
                // A) 完美转换：仅对 x-www-form-urlencoded 生效
                byte[] cleanMultipartBody = smartWrapBodyAsMultipart(originalBody, boundary, originalHeaders);
                if (cleanMultipartBody != null) {
                    result.add(buildRequestWithMultipart(originalHeaders, cleanMultipartBody, boundary));
                } else {
                    // B) Header 欺骗：对 JSON/XML 等保持原 Body，只改 Content-Type
                    List<String> spoofHeaders = new ArrayList<>(originalHeaders);
                    removeHeadersIgnoreCase(spoofHeaders, "Content-Type");
                    spoofHeaders.add("Content-Type: multipart/form-data; boundary=" + boundary);
                    // buildHttpMessage 构造实体 body：强制移除 TE 并同步 CL
                    removeHeadersIgnoreCase(spoofHeaders, "Transfer-Encoding");
                    updateOrAddHeader(spoofHeaders, "Content-Length", String.valueOf(originalBody.length));
                    result.add(Utils.helpers.buildHttpMessage(spoofHeaders, originalBody));
                }
            }
        }
        if (Boolean.TRUE.equals(ctOptions.get("text_plain"))) {
            if (!originalContentType.toLowerCase().contains("text/plain")) {
                result.add(buildRequestWithContentType(originalHeaders, originalBody, "text/plain"));
            }
        }

        return result;
    }

    /**
     * 获取原始 Content-Type（去除 charset 参数）
     */
    private String getOriginalContentType(List<String> headers) {
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h != null && h.toLowerCase().startsWith("content-type:")) {
                String value = h.substring("content-type:".length()).trim();
                int semicolon = value.indexOf(';');
                if (semicolon > 0) {
                    return value.substring(0, semicolon).trim();
                }
                return value;
            }
        }
        return "application/octet-stream"; // 默认
    }

    /**
     * 构建带 charset 的请求（保留原始 Content-Type）
     */
    private byte[] buildRequestWithCharset(List<String> originalHeaders, byte[] encodedBody, String contentType, String charset) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeaderWithCharset(newHeaders, contentType, charset);
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(encodedBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, encodedBody);
    }

    /**
     * 用指定字符集编码 Body
     */
    private byte[] encodeBodyWithCharset(byte[] body, String charsetName, String contentType, List<String> originalHeaders) {
        try {
            // 非文本类 content-type 或已 gzip 的 body，不做字符集转码（避免破坏二进制）
            if (!isTextualContentType(contentType)) {
                return null;
            }
            if (hasHeaderToken(originalHeaders, "Content-Encoding", "gzip")) {
                return null;
            }

            // 严格 UTF-8 解码：遇到非法字节直接放弃，避免 U+FFFD 替换导致 payload 损坏
            CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            String bodyStr = dec.decode(ByteBuffer.wrap(body)).toString();
            Charset charset = Charset.forName(charsetName);
            return bodyStr.getBytes(charset);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isTextualContentType(String contentType) {
        if (contentType == null) return false;
        String ct = contentType.toLowerCase();
        return ct.contains("json")
                || ct.contains("xml")
                || ct.contains("text")
                || ct.contains("x-www-form-urlencoded")
                || ct.contains("javascript")
                || ct.contains("html");
    }

    private boolean hasHeaderToken(List<String> headers, String name, String token) {
        if (headers == null || name == null || token == null) return false;
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null) continue;
            int colon = h.indexOf(':');
            if (colon <= 0) continue;
            String n = h.substring(0, colon).trim();
            if (!n.equalsIgnoreCase(name)) continue;
            String v = h.substring(colon + 1).trim().toLowerCase();
            return v.contains(token.toLowerCase());
        }
        return false;
    }

    /**
     * Gzip 压缩 Body
     */
    private byte[] gzipBody(byte[] body) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            GZIPOutputStream gzos = new GZIPOutputStream(baos);
            gzos.write(body);
            gzos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 构建带 Gzip Body 的请求
     */
    private byte[] buildRequestWithGzipBody(List<String> originalHeaders, byte[] gzippedBody) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Encoding", "gzip");
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(gzippedBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, gzippedBody);
    }

    /**
     * 构建带指定 Content-Type 的请求
     */
    private byte[] buildRequestWithContentType(List<String> originalHeaders, byte[] body, String contentType) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Type", contentType);
        // buildHttpMessage 构造的是非 chunked 的实体 body：移除 Transfer-Encoding，并同步 Content-Length
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(body == null ? 0 : body.length));
        return Utils.helpers.buildHttpMessage(newHeaders, body);
    }

    /**
     * 生成随机 boundary
     */
    private String generateRandomBoundary() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder("----WebKitFormBoundary");
        Random random = new Random();
        for (int i = 0; i < 16; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * 将 Body 包装成 multipart 格式
     */
    private byte[] wrapBodyAsMultipart(byte[] originalBody, String boundary) {
        try {
            // 直接操作 byte[]，避免把二进制 body 误当 UTF-8 文本导致损坏
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("Content-Disposition: form-data; name=\"data\"\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(originalBody);
            out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * form-urlencoded -> multipart/form-data
     * 非表单类型返回 null
     */
    private byte[] smartWrapBodyAsMultipart(byte[] originalBody, String boundary, List<String> headers) {
        try {
            String originalContentType = getOriginalContentType(headers).toLowerCase();
            if (!originalContentType.contains("application/x-www-form-urlencoded")) {
                return null;
            }
            if (originalBody == null || originalBody.length == 0) {
                return null;
            }
            Charset cs = extractCharsetFromContentType(headers);
            String bodyStr = new String(originalBody, cs);
            if (bodyStr.trim().isEmpty()) {
                return null;
            }

            String[] pairs = bodyStr.split("&");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (String pair : pairs) {
                if (pair == null || pair.isEmpty()) continue;
                String[] kv = pair.split("=", 2);
                String key = URLDecoder.decode(kv[0], cs.name());
                String value = kv.length > 1 ? URLDecoder.decode(kv[1], cs.name()) : "";

                out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(("Content-Disposition: form-data; name=\"" + key + "\"\r\n").getBytes(StandardCharsets.UTF_8));
                // 显式声明字段字符集，提升后端兼容性
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

    private Charset extractCharsetFromContentType(List<String> headers) {
        String ct = null;
        if (headers != null) {
            for (int i = 1; i < headers.size(); i++) {
                String h = headers.get(i);
                if (h == null) continue;
                int colon = h.indexOf(':');
                if (colon <= 0) continue;
                String n = h.substring(0, colon).trim();
                if (!n.equalsIgnoreCase("Content-Type")) continue;
                ct = h.substring(colon + 1).trim();
                break;
            }
        }
        if (ct == null || ct.isEmpty()) {
            return StandardCharsets.UTF_8;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?i)charset\\s*=\\s*([^;\\r\\n]+)").matcher(ct);
        if (!m.find()) {
            return StandardCharsets.UTF_8;
        }
        String name = m.group(1);
        if (name == null) {
            return StandardCharsets.UTF_8;
        }
        name = name.trim();
        if (name.startsWith("\"") && name.endsWith("\"") && name.length() >= 2) {
            name = name.substring(1, name.length() - 1).trim();
        }
        try {
            return Charset.forName(name);
        } catch (Exception ignored) {
            return StandardCharsets.UTF_8;
        }
    }

    /**
     * 构建 multipart 请求
     */
    private byte[] buildRequestWithMultipart(List<String> originalHeaders, byte[] multipartBody, String boundary) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Type", "multipart/form-data; boundary=" + boundary);
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(multipartBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, multipartBody);
    }

    private void updateOrAddHeaderWithCharset(List<String> headers, String fallbackContentType, String charset) {
        // 优先修改已有 Content-Type：仅替换/追加 charset，保留其它参数
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null) continue;
            int colon = h.indexOf(':');
            if (colon <= 0) continue;
            String n = h.substring(0, colon).trim();
            if (!n.equalsIgnoreCase("Content-Type")) continue;

            String v = h.substring(colon + 1).trim();
            // 去掉已有 charset=...
            v = v.replaceAll("(?i);\\s*charset\\s*=\\s*[^;\\r\\n]+", "");
            v = v.trim();
            // 追加 charset
            if (!v.isEmpty()) {
                v = v + "; charset=" + charset;
            } else if (fallbackContentType != null && !fallbackContentType.isEmpty()) {
                v = fallbackContentType + "; charset=" + charset;
            } else {
                v = "application/octet-stream; charset=" + charset;
            }
            headers.set(i, "Content-Type: " + v);
            return;
        }
        // 没有 Content-Type 时补一个
        String ct = (fallbackContentType == null || fallbackContentType.isEmpty()) ? "application/octet-stream" : fallbackContentType;
        headers.add("Content-Type: " + ct + "; charset=" + charset);
    }

    /**
     * 更新或添加 Header
     */
    private void updateOrAddHeader(List<String> headers, String name, String value) {
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h != null) {
                int colon = h.indexOf(':');
                if (colon > 0) {
                    String n = h.substring(0, colon).trim();
                    if (n.equalsIgnoreCase(name)) {
                        headers.set(i, name + ": " + value);
                        return;
                    }
                }
            }
        }
        headers.add(name + ": " + value);
    }

    

    /**
     * 处理 Body 编码变体请求的 Runnable
     */
    class Run_body_encoded_request implements Runnable {
        private final byte[] requestBytes;
        private final IHttpRequestResponse originalReqResp;
        private final String tool;

        public Run_body_encoded_request(byte[] requestBytes, IHttpRequestResponse originalReqResp, String tool) {
            this.requestBytes = requestBytes;
            this.originalReqResp = originalReqResp;
            this.tool = tool;
        }

        @Override
        public void run() {
            try {
                IHttpRequestResponse firstResponse = Utils.callbacks.makeHttpRequest(
                        originalReqResp.getHttpService(), requestBytes);
                
                IHttpRequestResponse finalResponse = followRedirectsIfNeeded(
                        firstResponse, requestBytes, originalReqResp.getHttpService(), MAX_REDIRECT_HOPS);

                byte[] oldResponseBytes = originalReqResp.getResponse();
                byte[] finalResponseBytes = (finalResponse == null) ? null : finalResponse.getResponse();

                short oldStatus = getStatusSafe(oldResponseBytes);
                short newStatus = getStatusSafe(finalResponseBytes);
                String newMime = getMimeSafe(finalResponseBytes);

                String oldBody = extractBodyAsString(oldResponseBytes);
                String newBody = extractBodyAsString(finalResponseBytes);
                double threshold = Utils.panel.getSimilarityThreshold();
                double ratio = DiffPage.getRatio(oldBody, newBody, newMime);
                boolean statusClassChanged = (oldStatus > 0 && newStatus > 0) && (oldStatus / 100 != newStatus / 100);

                boolean shouldLog = isCandidateStatus(newStatus) && (ratio < threshold || statusClassChanged);

                addFinishRequestNum(1);

                if (finalResponse != null && finalResponseBytes != null && shouldLog) {
                    String title = Utils.getBodyTitle(new String(finalResponseBytes, "utf-8"));
                    addLog(finalResponse, 0, 0, 0, title, tool);
                }
            } catch (Throwable e) {
                Utils.panel.addErrorRequestNum(1);
            }
        }
    }

    public void processHttp(IHttpRequestResponse[] iHttpRequestResponses, String tool) {
        processHttp(iHttpRequestResponses, tool, "access_control");
    }

    /**
     * Auto Scan：Proxy 响应监听，命中条件自动触发扫描
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

            if (Utils.isProxySelected && !messageIsRequest) {
                IHttpRequestResponse httpRequestResponse = message.getMessageInfo();
                byte[] old_response  = httpRequestResponse.getResponse();
                if(old_response != null) {
                    short old_status = Utils.helpers.analyzeResponse(old_response).getStatusCode();
                    String path = Utils.helpers.analyzeRequest(httpRequestResponse).getUrl().getPath();
                    IHttpRequestResponse[] iHttpRequestResponses = new IHttpRequestResponse[]{httpRequestResponse};

                    if (old_status == 401 || old_status == 403) {
                        int lastSlash = path.lastIndexOf('/');
                        int lastDot = path.lastIndexOf('.');
                        if (lastDot > lastSlash && lastDot >= 0 && lastDot < path.length() - 1) {
                            String extension = path.substring(lastDot + 1).toLowerCase();
                            if (!extension.isEmpty() && Utils.getIgnoreExtensions().contains(extension)) {
                                return;
                            }
                        }
                            new Thread(() ->
                            {
                                processHttp(iHttpRequestResponses, "Auto Scan", "access_control");
                            }).start();

                    }

                }
            }

    }

}
