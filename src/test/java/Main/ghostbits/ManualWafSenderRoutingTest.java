package Main.ghostbits;

import org.junit.Test;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * 验证 ManualWafPanel 的 AUTO 路由只看请求行/头部，不看 body。
 *
 * 因为 ManualWafPanel 直接 new 出来会触发 Burp callbacks/IMessageEditor 等
 * Burp 运行时依赖，这里只用反射拿 private static 的 findHeaderEnd 工具方法
 * 来覆盖 header end 切分逻辑。AUTO 行为通过 findHeaderEnd + 简单循环组合
 * 在测试里独立验证一遍。
 */
public class ManualWafSenderRoutingTest {

    @Test
    public void findHeaderEndCrlf() throws Exception {
        byte[] req = ("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody").getBytes(StandardCharsets.UTF_8);
        int end = invokeFindHeaderEnd(req);
        assertEquals(req.length - 4, end); // "body" 长 4，分隔符末尾正好在 body 起始
        assertEquals('b', (char) (req[end] & 0xFF));
    }

    @Test
    public void findHeaderEndLfOnly() throws Exception {
        byte[] req = ("GET / HTTP/1.1\nHost: x\n\nbody").getBytes(StandardCharsets.UTF_8);
        int end = invokeFindHeaderEnd(req);
        assertEquals(req.length - 4, end);
    }

    @Test
    public void findHeaderEndNotFoundReturnsNegative() throws Exception {
        byte[] req = "no header end".getBytes(StandardCharsets.UTF_8);
        int end = invokeFindHeaderEnd(req);
        assertEquals(-1, end);
    }

    /**
     * AUTO 模式只在请求行/头部检测非 ASCII，body 中文不应触发。
     */
    @Test
    public void autoModeSkipsBodyNonAscii() throws Exception {
        byte[] req = ("POST /api HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 32\r\n"
                + "\r\n"
                + "{\"name\":\"中文\"}").getBytes(StandardCharsets.UTF_8);
        assertFalse("body 中文不应让 AUTO 走 Raw", autoNeedsRaw(req));
    }

    @Test
    public void autoModeTriggersOnPathNonAscii() throws Exception {
        byte[] req = ("GET /阮严灵丰丰甲来/etc/passwd HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        assertTrue("path 含非 ASCII 必须走 Raw", autoNeedsRaw(req));
    }

    @Test
    public void autoModeTriggersOnHeaderNonAscii() throws Exception {
        byte[] req = ("GET / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "X-Bypass: 阮\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        assertTrue("header value 含非 ASCII 必须走 Raw", autoNeedsRaw(req));
    }

    @Test
    public void autoModeIgnoresGzipBody() throws Exception {
        // 模拟 gzip body：高位字节大量出现，但都在 body 部分
        byte[] header = "POST / HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\n\r\n"
                .getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[]{(byte) 0x1F, (byte) 0x8B, 0x08, 0x00, (byte) 0xE9, (byte) 0x98, (byte) 0xAE};
        byte[] req = new byte[header.length + body.length];
        System.arraycopy(header, 0, req, 0, header.length);
        System.arraycopy(body, 0, req, header.length, body.length);
        assertFalse("gzip body 不应让 AUTO 走 Raw", autoNeedsRaw(req));
    }

    // ------------------------------------------------------------------
    // 复制 ManualWafPanel.shouldUseRawSocket 的 AUTO 逻辑用于独立测试
    // ------------------------------------------------------------------
    private static boolean autoNeedsRaw(byte[] requestBytes) throws Exception {
        if (requestBytes == null) return false;
        int headerEnd = invokeFindHeaderEnd(requestBytes);
        int upper = headerEnd > 0 ? headerEnd : requestBytes.length;
        for (int i = 0; i < upper; i++) {
            if ((requestBytes[i] & 0xFF) > 0x7F) return true;
        }
        return false;
    }

    private static int invokeFindHeaderEnd(byte[] bytes) throws Exception {
        Class<?> cls = Class.forName("Main.ManualWafPanel");
        Method m = cls.getDeclaredMethod("findHeaderEnd", byte[].class);
        m.setAccessible(true);
        return (Integer) m.invoke(null, (Object) bytes);
    }
}
