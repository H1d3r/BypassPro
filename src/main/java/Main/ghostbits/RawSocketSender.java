package Main.ghostbits;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * 原始字节级别的 HTTP/HTTPS 发送器。
 *
 * 设计目标：让用户编辑器里的 byte[] 不经任何字符串中转直接进 socket，专门用于
 * 复现 Ghost Bits 这类对 wire 字节流敏感的漏洞。
 *
 * 关键约束：
 *  1. 入口 send(...) 接收 byte[]，内部 OutputStream.write(bytes)。
 *  2. 不依赖 Burp callbacks，不依赖 IExtensionHelpers。
 *  3. HTTPS 默认 TrustAll，方便本地 CTF/测试环境（UI 上要明确标识）。
 */
public class RawSocketSender {

    /** 16 MB 响应上限，防止超大下载阻塞 UI 线程 */
    private static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
    private static final int READ_BUFFER_SIZE = 8192;

    /**
     * 发送原始字节并返回响应。会一直读到对端关闭连接 / 读超时 / 命中 16MB 上限为止。
     *
     * @param host        目标主机
     * @param port        目标端口
     * @param https       是否启用 TLS
     * @param requestBytes 请求字节流（必须包含完整 HTTP 头 + 空行 + body）
     * @param connectTimeoutMs 连接超时（毫秒）
     * @param readTimeoutMs    读超时（毫秒），到点没新数据就视为响应结束
     * @return 原始字节响应封装
     */
    public RawResponse send(String host, int port, boolean https,
                            byte[] requestBytes,
                            int connectTimeoutMs, int readTimeoutMs) throws IOException {
        if (host == null || host.isEmpty()) {
            throw new IOException("host is empty");
        }
        if (requestBytes == null || requestBytes.length == 0) {
            throw new IOException("request bytes is empty");
        }

        long startNs = System.nanoTime();
        Socket socket = null;
        try {
            socket = createSocket(host, port, https, connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs <= 0 ? 5000 : readTimeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write(requestBytes);
            out.flush();

            byte[] response = readResponse(socket.getInputStream());
            long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
            return new RawResponse(response, requestBytes, durationMs, host, port, https);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception ignored) {}
            }
        }
    }

    private Socket createSocket(String host, int port, boolean https, int connectTimeoutMs) throws IOException {
        if (!https) {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            return s;
        }
        try {
            SSLSocketFactory factory = trustAllSocketFactory();
            // 必须先建立 TCP 再 SSL 握手，否则没法做 connect 超时
            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            SSLSocket ssl = (SSLSocket) factory.createSocket(plain, host, port, true);
            // 设置 SNI（兼容大多数虚拟主机），同时禁用主机名校验
            SSLParameters params = ssl.getSSLParameters();
            params.setEndpointIdentificationAlgorithm(null);
            ssl.setSSLParameters(params);
            ssl.startHandshake();
            return ssl;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("TLS init failed: " + e.getMessage(), e);
        }
    }

    private SSLSocketFactory trustAllSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] tms = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {}
                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {}
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tms, new SecureRandom());
        return ctx.getSocketFactory();
    }

    /**
     * 静态获取一个 always-true HostnameVerifier，便于 UI 层共用。
     */
    public static HostnameVerifier trustAllHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    /**
     * 读响应字节。流程：
     *  1. 先读到 \r\n\r\n（响应头结束）。
     *  2. 解析 Content-Length / Transfer-Encoding。
     *  3. 命中 Content-Length: 精确再读 N 字节就返回。
     *     命中 chunked: 按 chunk 协议读到 0\r\n\r\n。
     *     都没有: 兜底读到对端关闭 / 读超时 / 命中 16MB 上限。
     *
     * 这样对启用 keep-alive 的服务器也能立刻返回，不用每次傻等 SoTimeout。
     */
    private byte[] readResponse(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(READ_BUFFER_SIZE);

        // 1) 读响应头
        int headerEnd = readUntilHeaderEnd(in, buf);
        if (headerEnd < 0) {
            // 没拿到完整头，直接返回已读字节
            return buf.toByteArray();
        }

        byte[] current = buf.toByteArray();
        long contentLength = parseContentLength(current, headerEnd);
        boolean chunked = isChunked(current, headerEnd);

        if (chunked) {
            readChunkedBody(in, buf, headerEnd);
        } else if (contentLength >= 0) {
            readFixedBody(in, buf, headerEnd, contentLength);
        } else {
            // 没 CL 也没 chunked: 读到 close
            readUntilClose(in, buf);
        }
        return buf.toByteArray();
    }

    private int readUntilHeaderEnd(InputStream in, ByteArrayOutputStream buf) throws IOException {
        byte[] chunk = new byte[READ_BUFFER_SIZE];
        while (true) {
            int n;
            try {
                n = in.read(chunk);
            } catch (java.net.SocketTimeoutException e) {
                return -1;
            }
            if (n < 0) return -1;
            buf.write(chunk, 0, n);
            if (buf.size() >= MAX_RESPONSE_BYTES) return -1;

            byte[] cur = buf.toByteArray();
            int idx = indexOfHeaderEnd(cur);
            if (idx >= 0) return idx; // 含分隔符末尾偏移
        }
    }

    private static int indexOfHeaderEnd(byte[] bytes) {
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

    private static long parseContentLength(byte[] bytes, int headerEnd) {
        String headers = new String(bytes, 0, headerEnd - 1, java.nio.charset.StandardCharsets.ISO_8859_1);
        for (String line : headers.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim();
            if (!name.equalsIgnoreCase("Content-Length")) continue;
            String value = line.substring(colon + 1).trim();
            try {
                long v = Long.parseLong(value);
                return v < 0 ? -1 : v;
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    private static boolean isChunked(byte[] bytes, int headerEnd) {
        String headers = new String(bytes, 0, headerEnd - 1, java.nio.charset.StandardCharsets.ISO_8859_1);
        for (String line : headers.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim();
            if (!name.equalsIgnoreCase("Transfer-Encoding")) continue;
            return line.substring(colon + 1).toLowerCase().contains("chunked");
        }
        return false;
    }

    private void readFixedBody(InputStream in, ByteArrayOutputStream buf,
                               int headerEnd, long contentLength) throws IOException {
        long bodyAlready = buf.size() - headerEnd;
        long need = contentLength - bodyAlready;
        if (need <= 0) return;

        byte[] chunk = new byte[READ_BUFFER_SIZE];
        while (need > 0 && buf.size() < MAX_RESPONSE_BYTES) {
            int wanted = (int) Math.min(chunk.length, need);
            int n;
            try {
                n = in.read(chunk, 0, wanted);
            } catch (java.net.SocketTimeoutException e) {
                return;
            }
            if (n < 0) return;
            buf.write(chunk, 0, n);
            need -= n;
        }
    }

    private void readChunkedBody(InputStream in, ByteArrayOutputStream buf,
                                 int headerEnd) throws IOException {
        // 简易 chunked 解析。已经读了一部分 body（缓存在 buf 里），先消化它，再继续读流。
        byte[] chunk = new byte[READ_BUFFER_SIZE];
        while (buf.size() < MAX_RESPONSE_BYTES) {
            byte[] cur = buf.toByteArray();
            ChunkParseState state = parseChunked(cur, headerEnd);
            if (state.terminated) return;
            // 还没读完，继续从 socket 拉
            int n;
            try {
                n = in.read(chunk);
            } catch (java.net.SocketTimeoutException e) {
                return;
            }
            if (n < 0) return;
            buf.write(chunk, 0, n);
        }
    }

    private static class ChunkParseState {
        boolean terminated;
    }

    /**
     * 扫描 chunked body 是否已经收到最后一个 chunk。
     * 不剥离 chunk header，但按 chunk-size 行推进，兼容 0;ext=value 和 trailer headers。
     */
    private static ChunkParseState parseChunked(byte[] bytes, int headerEnd) {
        ChunkParseState st = new ChunkParseState();
        if (bytes.length <= headerEnd) return st;

        int pos = headerEnd;
        while (pos < bytes.length) {
            int lineEnd = findLineEnd(bytes, pos);
            if (lineEnd < 0) return st;

            String line = new String(bytes, pos, lineEnd - pos, java.nio.charset.StandardCharsets.ISO_8859_1).trim();
            int semicolon = line.indexOf(';');
            if (semicolon >= 0) {
                line = line.substring(0, semicolon).trim();
            }
            if (line.isEmpty()) return st;

            long chunkSize;
            try {
                chunkSize = Long.parseLong(line, 16);
            } catch (NumberFormatException e) {
                return st;
            }
            if (chunkSize < 0 || chunkSize > MAX_RESPONSE_BYTES) {
                return st;
            }

            int sizeSepLen = lineSeparatorLength(bytes, lineEnd);
            if (sizeSepLen <= 0) return st;
            int afterSizeLine = lineEnd + sizeSepLen;
            if (chunkSize == 0) {
                if (findChunkTrailerEnd(bytes, afterSizeLine) >= 0) {
                    st.terminated = true;
                }
                return st;
            }

            long afterDataLong = afterSizeLine + chunkSize;
            if (afterDataLong > Integer.MAX_VALUE) return st;
            int afterData = (int) afterDataLong;
            if (afterData >= bytes.length) return st;

            int dataSepLen = lineSeparatorLength(bytes, afterData);
            if (dataSepLen <= 0) return st;
            pos = afterData + dataSepLen;
        }
        return st;
    }

    private static int findLineEnd(byte[] bytes, int from) {
        for (int i = from; i < bytes.length; i++) {
            if (bytes[i] == '\r') {
                if (i + 1 < bytes.length && bytes[i + 1] == '\n') return i;
                return -1;
            }
            if (bytes[i] == '\n') return i;
        }
        return -1;
    }

    private static int lineSeparatorLength(byte[] bytes, int lineEnd) {
        if (lineEnd < 0 || lineEnd >= bytes.length) return -1;
        if (bytes[lineEnd] == '\r') {
            if (lineEnd + 1 < bytes.length && bytes[lineEnd + 1] == '\n') return 2;
            return -1;
        }
        return bytes[lineEnd] == '\n' ? 1 : -1;
    }

    private static int findChunkTrailerEnd(byte[] bytes, int from) {
        if (from >= bytes.length) return -1;
        for (int i = from; i < bytes.length; i++) {
            if (bytes[i] == '\r'
                    && i + 1 < bytes.length && bytes[i + 1] == '\n') {
                if (i == from) return i + 2;
                if (i >= from + 2 && bytes[i - 2] == '\r' && bytes[i - 1] == '\n') {
                    return i + 2;
                }
            } else if (bytes[i] == '\n') {
                if (i == from) return i + 1;
                if (i >= from + 1 && bytes[i - 1] == '\n') {
                    return i + 1;
                }
            }
        }
        return -1;
    }

    private void readUntilClose(InputStream in, ByteArrayOutputStream buf) throws IOException {
        byte[] chunk = new byte[READ_BUFFER_SIZE];
        while (buf.size() < MAX_RESPONSE_BYTES) {
            int n;
            try {
                n = in.read(chunk);
            } catch (java.net.SocketTimeoutException e) {
                return;
            }
            if (n < 0) return;
            buf.write(chunk, 0, n);
        }
    }

    // ------------------------------------------------------------------
    // 响应封装
    // ------------------------------------------------------------------

    public static class RawResponse {
        private final byte[] responseBytes;
        private final byte[] requestBytesActuallySent;
        private final long durationMs;
        private final String host;
        private final int port;
        private final boolean https;

        public RawResponse(byte[] responseBytes, byte[] requestBytesActuallySent,
                           long durationMs, String host, int port, boolean https) {
            this.responseBytes = responseBytes == null ? new byte[0] : responseBytes;
            this.requestBytesActuallySent = requestBytesActuallySent == null ? new byte[0] : requestBytesActuallySent;
            this.durationMs = durationMs;
            this.host = host;
            this.port = port;
            this.https = https;
        }

        public byte[] getResponseBytes() { return responseBytes; }
        public byte[] getRequestBytesActuallySent() { return requestBytesActuallySent; }
        public long getDurationMs() { return durationMs; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public boolean isHttps() { return https; }

        /**
         * 简易解析 HTTP 状态码。失败返回 0。
         * 不依赖 Burp helpers，保持 RawSocketSender 在 Burp 缺席时也能跑（方便单测）。
         */
        public int getStatusCode() {
            if (responseBytes.length < 12) return 0;
            // 期望形如 "HTTP/1.1 200 OK\r\n"
            int spaceIdx = -1;
            for (int i = 0; i < Math.min(responseBytes.length, 64); i++) {
                if (responseBytes[i] == ' ') {
                    spaceIdx = i;
                    break;
                }
            }
            if (spaceIdx < 0 || spaceIdx + 4 > responseBytes.length) return 0;
            try {
                String code = new String(responseBytes, spaceIdx + 1, 3, "ISO-8859-1");
                return Integer.parseInt(code.trim());
            } catch (Exception e) {
                return 0;
            }
        }

        /**
         * 取 header 行末偏移（响应中第一个 \r\n\r\n 之后的位置）。
         */
        public int getBodyOffset() {
            for (int i = 0; i + 3 < responseBytes.length; i++) {
                if (responseBytes[i] == '\r' && responseBytes[i + 1] == '\n'
                        && responseBytes[i + 2] == '\r' && responseBytes[i + 3] == '\n') {
                    return i + 4;
                }
            }
            // 退化：找 \n\n
            for (int i = 0; i + 1 < responseBytes.length; i++) {
                if (responseBytes[i] == '\n' && responseBytes[i + 1] == '\n') {
                    return i + 2;
                }
            }
            return responseBytes.length;
        }
    }
}
