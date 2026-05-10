package Main;

/**
 * I18n 字符串集中注册。所有 UI 文案的中英文版本在这里统一维护，
 * 避免散落在业务代码中影响阅读。
 *
 * <p>命名规范：
 * <ul>
 *   <li>btn.{name}            按钮文本</li>
 *   <li>row.{name}            addToolRow 行标签</li>
 *   <li>sec.{name}            section 分隔线标题</li>
 *   <li>tab.{name}            Tab / 子 Tab 标题</li>
 *   <li>label.{name}          一般 JLabel</li>
 *   <li>tooltip.{name}.title  tooltip 第一行</li>
 *   <li>tooltip.{name}.desc   tooltip 描述（多行用 \n 分隔）</li>
 *   <li>status.{name}         状态栏消息</li>
 *   <li>dialog.{name}         弹窗消息（含 .title 后缀表标题）</li>
 *   <li>config.{name}         ConfigPanel 文案</li>
 * </ul>
 */
final class I18nKeys {

    private I18nKeys() {}

    static void register() {
        registerLabels();
        registerTooltips();
        registerStatus();
        registerDialogs();
        registerConfig();
    }

    // =========================================================
    // 按钮 / 行标签 / Section / Tab / 普通 Label
    // =========================================================
    private static void registerLabels() {
        // ---- Top-level UI ----
        I18n.put("label.host", "Host:", "Host:");
        I18n.put("label.port", "Port:", "Port:");
        I18n.put("label.noise_target", "Noise 作用方式:", "Noise placement:");
        I18n.put("label.history_border", "History", "History");
        I18n.put("label.bypass_tools_border", "Bypass Tools", "Bypass Tools");

        // Bypass Tools 子 Tab（保持英文，技术术语）
        // 这些不翻译：Obfuscation & Noise / Data Encoding / Char Mutation / Header Bypass / Body Bypass / Gh0st Bits
        // 但提供 key 以便日后扩展

        // ---- Section separators ----
        I18n.put("sec.noise_atoms", "噪声原子", "Noise Atoms");
        I18n.put("sec.path_mutations", "路径变形", "Path Mutations");

        // ---- Row labels ----
        I18n.put("row.control_chars", "控制字符", "Control Chars");
        I18n.put("row.space_like", "类空格", "Space-like");
        I18n.put("row.wrappers", "包裹符", "Wrappers");
        I18n.put("row.generated", "生成", "Generated");

        I18n.put("row.traversal", "路径穿越", "Traversal");
        I18n.put("row.suffix", "后缀", "Suffix");
        I18n.put("row.segment", "段落", "Segment");
        I18n.put("row.boundary", "边界", "Boundary");

        I18n.put("row.client_ip", "客户端 IP", "Client IP");
        I18n.put("row.source_trust", "来源信任", "Source Trust");

        I18n.put("row.type_spoof", "类型伪装", "Type Spoof");
        I18n.put("row.body_convert", "Body 转换", "Body Convert");
        I18n.put("row.body_wrap", "Body 包装", "Body Wrap");

        I18n.put("row.url", "URL", "URL");
        I18n.put("row.base64", "Base64", "Base64");
        I18n.put("row.unicode_encoding", "Unicode 编码", "Unicode Encoding");
        I18n.put("row.ebcdic_encoding", "EBCDIC 编码", "EBCDIC Encoding");
        I18n.put("row.charset_params", "字符集参数", "Charset Params");

        I18n.put("row.unicode", "Unicode", "Unicode");
        I18n.put("row.case", "大小写", "Case");

        I18n.put("row.ghost_encode", "Ghost 编码", "Ghost Encode");
        I18n.put("row.fold_check", "Ghost 还原", "Ghost Restore");
        I18n.put("row.common_payload", "常用载荷", "Common Payload");
        I18n.put("row.parserbypass", "解析差异", "ParserBypass");
        I18n.put("row.json_parser", "JSON 解析", "JSON Parser");
        I18n.put("row.url_file_parser", "URL/文件解析", "URL/File Parser");
        I18n.put("row.templates", "模板", "Templates");

        // ---- Buttons ----
        // 注意：key 必须等于按钮文本经 I18n.slug() 后的结果
        // Noise Atoms - Generated
        I18n.put("btn.dirtyn", "脏数据(N)", "Dirty(N)");
        I18n.put("btn.nulln", "空字节(N)", "Null(N)");

        // Header Bypass - 大部分按钮文本就是 header 名，保持原样不翻译
        I18n.put("btn.referer_local", "Referer 本地", "Referer local");
        I18n.put("btn.x_host_local", "X-Host 本地", "X-Host local");
        I18n.put("btn.xf_host_local", "XF Host 本地", "XF Host local");

        // Body Bypass
        I18n.put("btn.to_form", "转 Form", "To Form");
        I18n.put("btn.to_multipart", "转 Multipart", "To Multipart");
        I18n.put("btn.to_json", "转 JSON", "To JSON");
        I18n.put("btn.gzip_body", "Gzip 压缩 Body", "Gzip body");

        // Data Encoding
        I18n.put("btn.url_encode", "URL 编码", "URL Encode");
        I18n.put("btn.path_encode", "Path 编码", "Path Encode");
        I18n.put("btn.double_url", "双重 URL", "Double URL");
        I18n.put("btn.mixed_encode", "混合编码", "Mixed Encode");
        I18n.put("btn.unicode_", "Unicode 转义", "Unicode Escape");
        I18n.put("btn.base64_encode", "Base64 编码", "Base64 Encode");
        I18n.put("btn.charset_first", "charset 在前", "charset first");
        I18n.put("btn.charset_last", "charset 在后", "charset last");

        // Char Mutation
        I18n.put("btn.fullwidth", "全角", "Fullwidth");
        I18n.put("btn.homoglyph", "同形字符", "Homoglyph");
        I18n.put("btn.zero_width", "零宽字符", "Zero Width");
        I18n.put("btn.upper", "大写", "Upper");
        I18n.put("btn.lower", "小写", "Lower");
        I18n.put("btn.random", "随机大小写", "Random");

        // Gh0st Bits - Encode
        I18n.put("btn.minimal", "最小集", "Minimal");
        I18n.put("btn.full", "全量", "Full");
        I18n.put("btn.letters", "字母", "Letters");
        I18n.put("btn.digits", "数字", "Digits");
        I18n.put("btn.symbols", "符号", "Symbols");
        I18n.put("btn.shuffle", "换组", "Shuffle");

        // Gh0st Bits - Inspect
        I18n.put("btn.preview", "预览", "Preview");
        I18n.put("btn.candidates", "候选", "Candidates");
        I18n.put("btn.jetty_2", "Jetty %2>", "Jetty %2>");
        I18n.put("btn.fastjson_x4", "fastjson \\x4_", "fastjson \\x4_");
        I18n.put("btn.fastjson_u", "fastjson \\u", "fastjson \\u");
        I18n.put("btn.jackson_u", "jackson \\u", "jackson \\u");
        I18n.put("btn.unicode_digits", "Unicode 数字", "Unicode Digits");
        I18n.put("btn.fullwidth_url", "全角 URL", "Fullwidth URL");
        I18n.put("btn.tomcat_hh", "Tomcat %HH", "Tomcat %HH");

        // Gh0st Bits - Templates fallback
        I18n.put("btn.no_templates", "无模板", "No templates");
        I18n.put("tooltip.no_templates",
                "YAML 中没有 profiles.manual_waf_bypass.ghost_bits.templates",
                "No profiles.manual_waf_bypass.ghost_bits.templates defined in YAML");

        // Inspector 行标签
        I18n.put("inspector.request", "Request", "Request");
        I18n.put("inspector.meta", "Meta", "Meta");
        I18n.put("inspector.flags", "Flags", "Flags");
        I18n.put("inspector.payload_hints", "Payload 提示", "Payload hints");
        I18n.put("inspector.diff", "Diff", "Diff");

        // Ghost 紧凑预览
        I18n.put("ghost.selection_fold", "Selection Fold", "Selection Fold");
        I18n.put("ghost.risk", "Risk", "Risk");
        I18n.put("ghost.risk.select", "select text to preview", "select text to preview");
        I18n.put("ghost.risk.unsupported", "unsupported binary selection", "unsupported binary selection");
    }

    // =========================================================
    // Tooltip
    // =========================================================
    private static void registerTooltips() {
        // ---------- Char Mutation ----------
        I18n.put("tooltip.fullwidth.title", "Fullwidth — 全角字符替换", "Fullwidth — Halfwidth to Fullwidth");
        I18n.put("tooltip.fullwidth.desc",
                "把选区内 ASCII 转成对应的全角 Unicode\n例如 admin -> ａｄｍｉｎ\n用于绕过基于 ASCII 字面量的关键字检测",
                "Convert selected ASCII to fullwidth Unicode equivalents\nExample: admin -> ａｄｍｉｎ\nBypass keyword filters that match raw ASCII");

        I18n.put("tooltip.homoglyph.title", "Homoglyph — 同形字符替换", "Homoglyph — Lookalike characters");
        I18n.put("tooltip.homoglyph.desc",
                "把选区中部分字母换成视觉相似的 Unicode 字符\n例如 a -> а (西里尔字母)\n用于绕过基于 ASCII 字面量的关键字检测",
                "Replace selected letters with visually similar Unicode chars\nExample: a -> а (Cyrillic)\nBypass ASCII-literal keyword filters");

        I18n.put("tooltip.zero_width.title", "Zero Width — 零宽字符插入", "Zero Width — Insert ZWSP");
        I18n.put("tooltip.zero_width.desc",
                "在选区每两个字符之间插入 U+200B 零宽空格\n例如 admin -> a\u200Bd\u200Bm\u200Bi\u200Bn\n用于关键词匹配和展示解析差异测试",
                "Insert U+200B ZWSP between every char of the selection\nExample: admin -> a\u200Bd\u200Bm\u200Bi\u200Bn\nFor keyword-match vs render-parse differential tests");

        I18n.put("tooltip.upper.title", "Upper — 转大写", "Upper — Uppercase");
        I18n.put("tooltip.upper.desc",
                "把选区转成大写\n用于大小写敏感规则差异测试",
                "Convert selection to uppercase\nFor case-sensitive rule differential tests");

        I18n.put("tooltip.lower.title", "Lower — 转小写", "Lower — Lowercase");
        I18n.put("tooltip.lower.desc",
                "把选区转成小写\n用于大小写敏感规则差异测试",
                "Convert selection to lowercase\nFor case-sensitive rule differential tests");

        I18n.put("tooltip.random.title", "Random Case — 随机大小写", "Random Case — Mixed case");
        I18n.put("tooltip.random.desc",
                "随机改变选区中字母大小写\n用于关键字大小写混淆",
                "Randomly toggle letter case in the selection\nObfuscate keywords by case mixing");

        // ---------- Ghost Bits Encode ----------
        I18n.put("tooltip.minimal.title",
                "Minimal — 只编码协议分隔符",
                "Minimal — Encode protocol separators only");
        I18n.put("tooltip.minimal.desc",
                "目标字符: . / \\ % @ : ; ? & = ' \" < > CR LF\n字母和数字保持原样；不会自动把 ../ 改写为 .%u002e\n操作: 先选中原始 ASCII/UTF-8 payload",
                "Targets: . / \\ % @ : ; ? & = ' \" < > CR LF\nLetters/digits unchanged; does not rewrite ../ into .%u002e\nUsage: select raw ASCII/UTF-8 payload first");

        I18n.put("tooltip.full.title",
                "Full — 编码全部 ASCII",
                "Full — Encode all ASCII");
        I18n.put("tooltip.full.desc",
                "选区内所有 ASCII 字符都转成 Ghost Unicode\nGhost 还原后仍等于原文，隐蔽性最强但更容易破坏解析链\n操作: 先选中原始 ASCII/UTF-8 payload",
                "Convert every ASCII char in the selection to Ghost Unicode\nRestores to the original low-byte text; most stealthy but more likely to break parser\nUsage: select raw ASCII/UTF-8 payload first");

        I18n.put("tooltip.letters.title",
                "Letters — 只编码字母",
                "Letters — Letters only");
        I18n.put("tooltip.letters.desc",
                "只 Ghost 化 a-z A-Z，数字和符号保持原样\n适合绕关键字检测: class / select / union / Runtime\n操作: 先选中原始 ASCII/UTF-8 payload",
                "Ghost-encode a-z A-Z only; digits and symbols unchanged\nGood for keyword bypass: class / select / union / Runtime\nUsage: select raw ASCII/UTF-8 payload first");

        I18n.put("tooltip.digits.title",
                "Digits — 只编码数字",
                "Digits — Digits only");
        I18n.put("tooltip.digits.desc",
                "只 Ghost 化 0-9，字母和符号保持原样\n适合版本号、参数值、\\uXXXX 数字段测试\n操作: 先选中原始 ASCII/UTF-8 payload",
                "Ghost-encode 0-9 only; letters and symbols unchanged\nGood for version numbers, param values, \\uXXXX hex digits\nUsage: select raw ASCII/UTF-8 payload first");

        I18n.put("tooltip.symbols.title",
                "Symbols — 只编码符号",
                "Symbols — Symbols only");
        I18n.put("tooltip.symbols.desc",
                "只 Ghost 化非字母非数字的 ASCII 符号\n包含空格、引号、斜杠、百分号、CR/LF 等\n操作: 先选中原始 ASCII/UTF-8 payload",
                "Ghost-encode ASCII symbols only (non-alnum)\nIncludes space, quotes, slash, percent, CR/LF, etc.\nUsage: select raw ASCII/UTF-8 payload first");

        I18n.put("tooltip.shuffle.title",
                "Shuffle — 换一组 Ghost 字符",
                "Shuffle — Pick another Ghost variant");
        I18n.put("tooltip.shuffle.desc",
                "先按低位还原结果重新随机选 Ghost Unicode\n同一 payload 换不同变体，多试几次碰运气\n操作: 先选中已 Ghost 化或待 Ghost 化文本",
                "Re-pick random Ghost Unicode by the low-byte restored text\nProduce different variants of the same payload; try multiple times\nUsage: select Ghost-encoded or to-be-encoded text first");

        I18n.put("tooltip.preview.title",
                "Preview — 查看 Ghost 还原结果",
                "Preview — See Ghost restore result");
        I18n.put("tooltip.preview.desc",
                "逐字符展示: U+XXXX -> low byte -> ASCII\n操作: 先选中 Ghost 化后的文本",
                "Per-char view: U+XXXX -> low byte -> ASCII\nUsage: select Ghost-encoded text first");

        I18n.put("tooltip.candidates.title",
                "Candidates — 查看候选字符",
                "Candidates — Show alternatives");
        I18n.put("tooltip.candidates.desc",
                "选中一个 ASCII 字符，列出所有可用的 Ghost Unicode 替代品\n批量变形请用上方 Ghost Encode 行按钮",
                "Pick one ASCII char to see all usable Ghost Unicode alternatives\nFor batch encoding use buttons in the Ghost Encode row above");

        I18n.put("tooltip.8_bit.title", "8-bit — ch & 0xFF (默认)", "8-bit — ch & 0xFF (default)");
        I18n.put("tooltip.8_bit.desc",
                "大多数场景: (byte)ch / baos.write(ch) / writeBytes\nGhost 还原时取 char 的低 8 位",
                "Most cases: (byte)ch / baos.write(ch) / writeBytes\nRestores to the low 8 bits of a char");

        I18n.put("tooltip.7_bit.title", "7-bit — ch & 0x7F (Tomcat)", "7-bit — ch & 0x7F (Tomcat)");
        I18n.put("tooltip.7_bit.desc",
                "少数场景: Tomcat RFC2231 filename* 的 hex 解析\nGhost 还原时取 char 的低 7 位",
                "Niche: Tomcat RFC2231 filename* hex parsing\nRestores to the low 7 bits of a char");

        // ---------- Ghost Common Payload ----------
        // 注意：tooltip key 必须 = "tooltip." + slug(按钮文本) + ".title|.desc"
        I18n.put("tooltip.u002e.title", ".%u002e", ".%u002e");
        I18n.put("tooltip.u002e.desc",
                "生成一个低 8 位还原后等于 .%u002e 的 Ghost 字符串；Unicode 输出不唯一\n后续 URL decode 可变成 ..\n放在 request path 时推荐 Raw Socket 发送\n操作: 先选中要替换的位置",
                "Generate a Ghost string whose low-8 restore is .%u002e; Unicode output is not unique\nA later URL decode may become ..\nRaw Socket recommended in request path\nUsage: select the target position first");

        I18n.put("tooltip.crlf.title", "CRLF", "CRLF");
        I18n.put("tooltip.crlf.desc",
                "生成一个低 8 位还原后等于 \\r\\n 的 Ghost 字符串；Unicode 输出不唯一\n用于 Header/SMTP/文本协议边界测试\n放在 header value 时推荐 Raw Socket 发送\n操作: 先选中 header value 或协议字段中的替换位置",
                "Generate a Ghost string whose low-8 restore is \\r\\n; Unicode output is not unique\nFor Header/SMTP/text-protocol boundary tests\nRaw Socket recommended in header value\nUsage: select position in header value / protocol field");

        I18n.put("tooltip.jsp.title", ".jsp", ".jsp");
        I18n.put("tooltip.jsp.desc",
                "生成一个低 8 位还原后等于 .jsp 的 Ghost 字符串；Unicode 输出不唯一\n这是裸字符 Ghost，和 Tomcat %HH 的 URL hex Ghost 不同\n操作: 先选中原扩展名或 filename 中要替换的位置",
                "Generate a Ghost string whose low-8 restore is .jsp; Unicode output is not unique\nThis is naked-char Ghost, different from Tomcat %HH URL-hex Ghost\nUsage: select original extension or position in filename");

        I18n.put("tooltip.type.title", "@type", "@type");
        I18n.put("tooltip.type.desc",
                "把 @type 转成低位等价 Unicode\n用于 fastjson/Jackson key 相关绕过构造\n操作: 先选中 JSON key 或待替换位置",
                "Encode @type into low-byte equivalent Unicode\nFor fastjson/Jackson key bypass payloads\nUsage: select JSON key or replacement position first");

        I18n.put("tooltip.jetty_2.title", "Jetty %2>", "Jetty %2>");
        I18n.put("tooltip.jetty_2.desc",
                "Jetty 非严格 hex 解析案例\n> 经 convertHexDigit 计算可变成 E，%2> 等价 %2E\n这是解析差异，不是标准 char & 0xFF\n操作: 选中 .、%2e，或包含这些 token 的路径片段",
                "Jetty loose hex parser case\n'>' goes through convertHexDigit and yields E, so %2> equals %2E\nParserBypass, not standard char & 0xFF\nUsage: select ., %2e, or a path fragment containing them");

        I18n.put("tooltip.class.title", "class", "class");
        I18n.put("tooltip.class.desc",
                "把 class 转成低位等价 Unicode\n用于 Spring/Java Bean path 关键字绕过构造\n操作: 先选中 class 或待替换位置",
                "Encode 'class' into low-byte equivalent Unicode\nFor Spring/Java bean path keyword bypass\nUsage: select 'class' or replacement position first");

        I18n.put("tooltip.fastjson_x4.title", "fastjson \\x4_", "fastjson \\x4_");
        I18n.put("tooltip.fastjson_x4.desc",
                "把 @type 里的 @ 改写为 \\x4J；J 在 fastjson 宽松 \\x 表里按 0 参与计算\n\\x4J 可解析为 @\n这是解析差异，不是标准 low-byte fold\n操作: 先选中 @type 或 JSON key 内容",
                "Rewrite @ in @type to \\x4J; J is treated as 0 by fastjson loose \\x parsing\n\\x4J may parse as @\nParserBypass, not standard low-byte fold\nUsage: select @type or JSON key content first");

        I18n.put("tooltip.fastjson_u.title", "fastjson \\u", "fastjson \\u");
        I18n.put("tooltip.fastjson_u.desc",
                "把选区转成 \\uXXXX，并把数字位替换为 Unicode 数字\n例如 @type -> \\u٠٠٤٠\\u٠٠٧٤...\n这是 Unicode digit 绕过，不是标准 low-byte fold\n操作: 先选中 @type 或 JSON key 内容",
                "Convert selection to \\uXXXX and replace numeric hex digits with Unicode digits\nExample: @type -> \\u٠٠٤٠\\u٠٠٧٤...\nUnicode digit parser bypass, not standard low-byte fold\nUsage: select @type or JSON key content first");

        I18n.put("tooltip.jackson_u.title", "jackson \\u", "jackson \\u");
        I18n.put("tooltip.jackson_u.desc",
                "把选区转成 \\uXXXX，并把 4 个 hex 位换成 Ghost 字符\n低位还原后仍是标准 \\uXXXX，给 Jackson charToHex(ch & 0xFF) 场景用\n只适合 ReaderBasedJsonParser / char[] 输入链\nSpringBoot 默认 UTF8StreamJsonParser 通常不触发\n操作: 先选中要转成 \\u Ghost escape 的 ASCII 文本",
                "Convert selection to \\uXXXX and replace the four hex digits with Ghost chars\nLow-byte restore is still standard \\uXXXX; for Jackson charToHex(ch & 0xFF)\nOnly fits ReaderBasedJsonParser / char[] input chains\nSpringBoot usually uses UTF8StreamJsonParser and does not trigger this\nUsage: select ASCII text first");

        I18n.put("tooltip.unicode_digits.title", "Unicode 数字", "Unicode Digits");
        I18n.put("tooltip.unicode_digits.desc",
                "把选区中的 ASCII 数字替换成 Unicode 数字字符\n适合先把 @type 转成 \\u0040type 后，再替换 0040 的数字位\n这是解析差异，不是标准 low-byte fold",
                "Replace ASCII digits in the selection with Unicode digit chars\nUse after converting @type to \\u0040type, then mutate the numeric digits\nParserBypass, not standard low-byte fold");

        I18n.put("tooltip.fullwidth_url.title", "全角 URL", "Fullwidth URL");
        I18n.put("tooltip.fullwidth_url.desc",
                "把选区中的 URL 编码字符转成全角形态，但保留 % 本身\n例如 %2e%2e%2f -> %２ｅ%２ｅ%２ｆ\n用于归一化/多阶段 URL 解析差异",
                "Convert URL-encoded chars in the selection to fullwidth form, keeping % unchanged\nExample: %2e%2e%2f -> %２ｅ%２ｅ%２ｆ\nFor normalization / multi-stage URL parser differential tests");

        I18n.put("tooltip.tomcat_hh.title", "Tomcat %HH", "Tomcat %HH");
        I18n.put("tooltip.tomcat_hh.desc",
                "把选区每个字符改成 %HH，但 H 用 7-bit Ghost 字符表示\n还原模式等价 ch & 0x7F，适合 Tomcat RFC2231 filename* hex 解析\n例如选中 j 可生成 %鸶繡 这类变体，后端可能解析为 j\n操作: 先选中 filename* 中要隐藏的原始字符，不要选 6a",
                "Convert every selected char to %HH, but each H is a 7-bit Ghost char\nEquivalent to ch & 0x7F; for Tomcat RFC2231 filename* hex parsing\nSelecting j may produce variants like %鸶繡, which may parse as j\nUsage: select raw chars inside filename*, not 6a");

        // ---------- Bypass Tools - 通用按钮 ----------
        I18n.put("tooltip.url_encode.title", "URL Encode — URL 编码", "URL Encode");
        I18n.put("tooltip.url_encode.desc",
                "把选区做标准 URL 编码\n用于 path/query/header value 中的特殊字符",
                "Standard URL encoding on the selection\nFor special chars in path / query / header value");

        I18n.put("tooltip.path_encode.title", "Path Encode — 路径编码", "Path Encode");
        I18n.put("tooltip.path_encode.desc",
                "针对 path 段的安全字符做编码\n保留 / : 等结构字符",
                "URL-encode path-safe chars only\nKeep / : etc. structural chars intact");

        I18n.put("tooltip.double_url.title", "Double URL — 双重编码", "Double URL");
        I18n.put("tooltip.double_url.desc",
                "对选区做两轮 URL 编码\n用于 WAF 和后端各解码一次的差异攻击",
                "Two passes of URL encoding\nExploit decode-count differential between WAF and backend");

        I18n.put("tooltip.mixed_encode.title", "Mixed Encode — 混合编码", "Mixed Encode");
        I18n.put("tooltip.mixed_encode.desc",
                "随机选择部分字符做 URL 编码\n破坏静态规则的精确字符串匹配",
                "Randomly URL-encode a subset of chars\nBreak exact-string rule matching");

        I18n.put("tooltip.unicode_.title", "Unicode 转义", "Unicode Escape");
        I18n.put("tooltip.unicode_.desc",
                "把选区转成 \\uXXXX 转义形式\n用于 JSON/JS 解析层后端解码差异测试",
                "Convert to \\uXXXX escapes\nFor JSON/JS parser decode differential tests");

        I18n.put("tooltip.base64_encode.title", "Base64 Encode", "Base64 Encode");
        I18n.put("tooltip.base64_encode.desc",
                "对选区做标准 Base64 编码",
                "Standard Base64 encoding on the selection");

        // ---------- Noise Atoms - Generated ----------
        I18n.put("tooltip.dirtyn.title", "Dirty(N) — 脏数据占位符", "Dirty(N) — Dirty placeholder");
        I18n.put("tooltip.dirtyn.desc",
                "插入 {{dirty(N)}} 占位符\n发送前展开为 N 个随机脏字符\n用于填充噪音、拉开特征、测试解析容忍度",
                "Insert {{dirty(N)}} placeholder\nExpands to N random dirty bytes before send\nPad noise, distort signatures, test parser tolerance");

        I18n.put("tooltip.nulln.title", "Null(N) — 空字节占位符", "Null(N) — Null placeholder");
        I18n.put("tooltip.nulln.desc",
                "插入 {{dirtynull(N)}} 占位符\n发送前展开为 N 个随机空字节/噪音字节\n用于测试截断、二进制噪音和解析差异",
                "Insert {{dirtynull(N)}} placeholder\nExpands to N random null/noise bytes before send\nTest truncation, binary noise and parser differentials");

        // ---------- Traversal / Path Mutations ----------
        I18n.put("tooltip.traversal.selection", "选区: %s -> %s", "Selection: %s -> %s");
        I18n.put("tooltip.traversal.no_selection", "无选区: 替换 path 中的 %s", "No selection: replace %s in the path");
        I18n.put("tooltip.traversal.u002e.usage", 
                "用途: %uXXXX Unicode dot, Jetty/IIS 解析后还原为 ..\n可组合 Gh0st Bits: 先变形再 Full 编码", 
                "Usage: %uXXXX Unicode dot, decodes to .. in Jetty/IIS\nCan compose with Gh0st Bits: mutate first then Full encode");
        I18n.put("tooltip.traversal.backslash.usage", 
                "用途: Windows / 反斜杠路径解析差异", 
                "Usage: Windows / backslash path parsing differences");

        // ---------- Header Bypass ----------
        I18n.put("tooltip.xff_127001.title", "X-Forwarded-For: 127.0.0.1", "X-Forwarded-For: 127.0.0.1");
        I18n.put("tooltip.xff_127001.desc",
                "添加或覆盖 X-Forwarded-For\n用于代理链 IP 信任、访问控制绕过测试",
                "Add or overwrite X-Forwarded-For\nFor proxy-chain IP trust and ACL bypass tests");

        I18n.put("tooltip.x_real_ip.title", "X-Real-IP: 127.0.0.1", "X-Real-IP: 127.0.0.1");
        I18n.put("tooltip.x_real_ip.desc",
                "添加或覆盖 X-Real-IP\nNginx/反代场景常见，用于真实客户端 IP 信任测试",
                "Add or overwrite X-Real-IP\nCommon in Nginx/reverse proxy; tests real client IP trust");

        I18n.put("tooltip.x_client_ip.title", "X-Client-IP: 127.0.0.1", "X-Client-IP: 127.0.0.1");
        I18n.put("tooltip.x_client_ip.desc",
                "添加或覆盖 X-Client-IP\n用于客户端 IP 伪造测试",
                "Add or overwrite X-Client-IP\nFor client IP spoof tests");

        I18n.put("tooltip.x_remote_addr.title", "X-Remote-Addr: 127.0.0.1", "X-Remote-Addr: 127.0.0.1");
        I18n.put("tooltip.x_remote_addr.desc",
                "添加或覆盖 X-Remote-Addr\n用于来源地址信任逻辑测试",
                "Add or overwrite X-Remote-Addr\nTest source-address trust logic");

        I18n.put("tooltip.cf_connecting_ip.title", "CF-Connecting-IP: 127.0.0.1", "CF-Connecting-IP: 127.0.0.1");
        I18n.put("tooltip.cf_connecting_ip.desc",
                "添加或覆盖 CF-Connecting-IP\nCloudflare 场景常见，用于边缘代理 IP 信任测试",
                "Add or overwrite CF-Connecting-IP\nCommon with Cloudflare; edge-proxy IP trust tests");

        I18n.put("tooltip.forwarded.title",
                "Forwarded: for=127.0.0.1;proto=http;host=127.0.0.1",
                "Forwarded: for=127.0.0.1;proto=http;host=127.0.0.1");
        I18n.put("tooltip.forwarded.desc",
                "添加或覆盖标准 Forwarded 头\n用于 RFC 7239 代理链解析和来源信任测试",
                "Add or overwrite the standard Forwarded header\nFor RFC 7239 proxy-chain parsing and source-trust tests");

        I18n.put("tooltip.x_custom_ip.title", "X-Custom-IP-Authorization: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1");
        I18n.put("tooltip.x_custom_ip.desc",
                "添加或覆盖 X-Custom-IP-Authorization\n用于部分框架/中间件的 IP 信任绕过测试",
                "Add or overwrite X-Custom-IP-Authorization\nFor framework/middleware IP-trust bypass tests");

        I18n.put("tooltip.referer_local.title", "Referer: http://127.0.0.1", "Referer: http://127.0.0.1");
        I18n.put("tooltip.referer_local.desc",
                "把 Referer 设置为本地地址\n用于来源校验、CSRF Referer 检查绕过测试",
                "Set Referer to a local address\nFor origin validation and CSRF Referer-check bypass tests");

        I18n.put("tooltip.x_host_local.title", "X-Host: 127.0.0.1", "X-Host: 127.0.0.1");
        I18n.put("tooltip.x_host_local.desc",
                "添加或覆盖 X-Host\n用于 Host 派生信任逻辑测试",
                "Add or overwrite X-Host\nFor host-derived trust logic tests");

        I18n.put("tooltip.xf_host_local.title", "X-Forwarded-Host: 127.0.0.1", "X-Forwarded-Host: 127.0.0.1");
        I18n.put("tooltip.xf_host_local.desc",
                "添加或覆盖 X-Forwarded-Host\n用于反代 Host 信任、后端路由和 URL 生成差异测试",
                "Add or overwrite X-Forwarded-Host\nFor proxy host trust, backend routing and URL generation diff tests");

        I18n.put("tooltip.x_original_url.title", "X-Original-URL: /", "X-Original-URL: /");
        I18n.put("tooltip.x_original_url.desc",
                "添加或覆盖 X-Original-URL\n用于 IIS/反代/重写链路中的原始 URL 解析差异测试",
                "Add or overwrite X-Original-URL\nFor IIS / reverse proxy / rewrite original-URL parser diff tests");

        I18n.put("tooltip.http10.title", "HTTP/1.0", "HTTP/1.0");
        I18n.put("tooltip.http10.desc",
                "把请求行协议版本改为 HTTP/1.0\n用于代理、连接复用、Host/TE 处理差异测试",
                "Change request-line protocol to HTTP/1.0\nFor proxy / keep-alive / Host & TE handling diffs");

        // ---------- Body type spoof ----------
        I18n.put("tooltip.form.title", "Content-Type: application/x-www-form-urlencoded",
                "Content-Type: application/x-www-form-urlencoded");
        I18n.put("tooltip.form.desc",
                "只修改请求 Content-Type\n不改 body，用于 WAF 和后端对 body 类型理解不一致的测试",
                "Modify Content-Type only; body unchanged\nFor WAF/backend body-type mismatch tests");

        I18n.put("tooltip.text.title", "Content-Type: text/plain", "Content-Type: text/plain");
        I18n.put("tooltip.text.desc",
                "只修改请求 Content-Type\n不改 body，用于让 WAF 按纯文本处理 body 的测试",
                "Modify Content-Type only; body unchanged\nMakes WAF treat the body as plain text");

        I18n.put("tooltip.json.title", "Content-Type: application/json", "Content-Type: application/json");
        I18n.put("tooltip.json.desc",
                "只修改请求 Content-Type\n不改 body，用于 JSON parser / WAF 类型识别差异测试",
                "Modify Content-Type only; body unchanged\nFor JSON parser / WAF type-detection diff tests");

        I18n.put("tooltip.xml.title", "Content-Type: application/xml", "Content-Type: application/xml");
        I18n.put("tooltip.xml.desc",
                "只修改请求 Content-Type\n不改 body，用于 XML parser / WAF 类型识别差异测试",
                "Modify Content-Type only; body unchanged\nFor XML parser / WAF type-detection diff tests");

        // ---------- Body Convert ----------
        I18n.put("tooltip.to_form.title", "To Form — 转 form-urlencoded", "To Form — Convert to form-urlencoded");
        I18n.put("tooltip.to_form.desc",
                "把当前 body 的普通参数转换成 x-www-form-urlencoded\n支持 form、multipart 文本字段、简单 JSON 对象\n会重写 body、Content-Type 和 Content-Length",
                "Convert current body params to x-www-form-urlencoded\nSupports form / multipart text fields / simple JSON objects\nRewrites body, Content-Type and Content-Length");

        I18n.put("tooltip.to_multipart.title", "To Multipart — 转 multipart/form-data", "To Multipart — Convert to multipart");
        I18n.put("tooltip.to_multipart.desc",
                "把当前 body 的普通参数转换成 multipart/form-data\n支持 form、multipart 文本字段、简单 JSON 对象\n跳过文件字段，会重写 body、boundary 和 Content-Length",
                "Convert current body params to multipart/form-data\nSupports form / multipart text fields / simple JSON objects\nSkips file parts; rewrites body, boundary and Content-Length");

        I18n.put("tooltip.to_json.title", "To JSON — 转 JSON 对象", "To JSON — Convert to JSON");
        I18n.put("tooltip.to_json.desc",
                "把当前 body 的普通参数转换成 JSON 对象\n支持 form、multipart 文本字段、简单 JSON 对象\n会重写 body、Content-Type 和 Content-Length",
                "Convert current body params to a JSON object\nSupports form / multipart text fields / simple JSON objects\nRewrites body, Content-Type and Content-Length");

        I18n.put("tooltip.gzip_body.title", "Gzip body — 压缩请求体", "Gzip body — Compress request body");
        I18n.put("tooltip.gzip_body.desc",
                "压缩请求 body 并设置 Content-Encoding: gzip\n用于 WAF 不解压、后端解压的差异测试",
                "Gzip the request body and set Content-Encoding: gzip\nFor WAF-doesn't-decode vs backend-decodes differential tests");

        // ---------- Charset ----------
        I18n.put("tooltip.charset_first.title", "charset first — charset 放最前", "charset first");
        I18n.put("tooltip.charset_first.desc",
                "重排 Content-Type 参数，把 charset 放在最前\n例如 multipart/form-data; charset=IBM037; boundary=xxx\n只改 header，不重编码 body",
                "Reorder Content-Type params: put charset first\nExample: multipart/form-data; charset=IBM037; boundary=xxx\nHeader-only change, body untouched");

        I18n.put("tooltip.charset_last.title", "charset last — charset 放最后", "charset last");
        I18n.put("tooltip.charset_last.desc",
                "重排 Content-Type 参数，把 charset 放在最后\n例如 multipart/form-data; boundary=xxx; charset=IBM037\n只改 header，不重编码 body",
                "Reorder Content-Type params: put charset last\nExample: multipart/form-data; boundary=xxx; charset=IBM037\nHeader-only change, body untouched");

        // ---------- Noise placement (RadioButtons) ----------
        I18n.put("tooltip.noise.selection.title", "光标处插入", "Insert at caret");
        I18n.put("tooltip.noise.selection.desc1",
                "点击 Noise Atom 后插入到当前光标位置",
                "Click a Noise Atom to insert at the current caret position");
        I18n.put("tooltip.noise.selection.desc2",
                "Hex 视图下回退为：选中文本前面（编辑器拿不到 caret）",
                "Hex view falls back to: before selected text (caret unavailable)");

        I18n.put("tooltip.noise.suffix.title", "Path 末尾", "Path suffix");
        I18n.put("tooltip.noise.suffix.desc1",
                "点击 Noise Atom 后追加到 request path 末尾",
                "Click a Noise Atom to append to the end of the request path");
        I18n.put("tooltip.noise.suffix.desc2",
                "如果有 query，会插在 ? 之前",
                "If a query string exists, the atom is inserted before '?'");

        I18n.put("tooltip.noise.seg_prefix.title", "每段前", "Per-segment prefix");
        I18n.put("tooltip.noise.seg_prefix.desc1",
                "点击 Noise Atom 后给每个非空 path segment 加前缀",
                "Click a Noise Atom to prefix every non-empty path segment");
        I18n.put("tooltip.noise.seg_prefix.desc2",
                "例如 /a/b -> /%00a/%00b",
                "Example: /a/b -> /%00a/%00b");

        I18n.put("tooltip.noise.seg_suffix.title", "每段后", "Per-segment suffix");
        I18n.put("tooltip.noise.seg_suffix.desc1",
                "点击 Noise Atom 后给每个非空 path segment 加后缀",
                "Click a Noise Atom to append to every non-empty path segment");
        I18n.put("tooltip.noise.seg_suffix.desc2",
                "例如 /a/b -> /a%00/b%00",
                "Example: /a/b -> /a%00/b%00");

        I18n.put("tooltip.noise.interleave.title", "字符间", "Interleave");
        I18n.put("tooltip.noise.interleave.desc1",
                "需要先选中文本",
                "Requires a selection first");
        I18n.put("tooltip.noise.interleave.desc2",
                "点击 Noise Atom 后插到选区每两个字符之间",
                "Click a Noise Atom to insert between every two chars of the selection");

        I18n.put("tooltip.noise.replace_space.title", "替换空格", "Replace spaces");
        I18n.put("tooltip.noise.replace_space.desc1",
                "有选区时替换选区里的空格",
                "When a selection exists, replace spaces inside the selection");
        I18n.put("tooltip.noise.replace_space.desc2",
                "没选区时只替换 request path 里的空格",
                "When nothing is selected, only spaces in the request path are replaced");
    }

    // =========================================================
    // 状态栏 / 弹窗消息
    // =========================================================
    private static void registerStatus() {
        I18n.put("status.ready", "Ready", "Ready");
        I18n.put("status.cancelled", "Cancelled", "Cancelled");
        I18n.put("status.history_loaded", "已加载历史请求 #%d", "Loaded history request #%d");
        I18n.put("status.applied_selection", "已对选区应用 %s", "Applied %s to selection");
        I18n.put("status.applied_body", "已对 body 应用 %s", "Applied %s to body");
        I18n.put("status.ghost_no_change",
                "Gh0st Bits: 当前策略未改变选区；可能已是 Ghost 形态，或没有匹配字符。可用 Shuffle 重新生成。",
                "Gh0st Bits: selection unchanged. Already encoded or no matching chars. Use Shuffle to retry.");
        I18n.put("status.ghost_shuffle_no_variant",
                "Gh0st Bits: Shuffle 未生成新变体，请再试一次或检查选区。",
                "Gh0st Bits: Shuffle produced no new variant. Try again or check the selection.");
        I18n.put("status.ghost_fold_mode_changed",
                "Gh0st Bits restore mode: %s",
                "Gh0st Bits restore mode: %s");
        I18n.put("status.fold_ok", "Ghost Restore OK: %s -> %s", "Ghost Restore OK: %s -> %s");
        I18n.put("status.raw_recommended", "Send: Raw Socket recommended", "Send: Raw Socket recommended");
        I18n.put("status.parser_diff",
                "Parser diff: %2> -> %2E -> . | Send: Burp OK",
                "Parser diff: %2> -> %2E -> . | Send: Burp OK");
        I18n.put("status.template_applied_path", "Template applied (path)", "Template applied (path)");
        I18n.put("status.template_applied_filename", "Template applied (filename)", "Template applied (filename)");
        I18n.put("status.template_applied_header", "Template applied (header %s)", "Template applied (header %s)");
        I18n.put("status.sending", "Sending...", "Sending...");
        I18n.put("status.send_error", "Error", "Error");

        I18n.put("status.no_selection",
                "未选中任何文本，请先在 Request 编辑器中选中 payload",
                "No selection. Select a payload in the Request editor first.");
        I18n.put("status.no_request", "Request 为空，请先加载请求", "Request is empty. Load a request first.");
    }

    // =========================================================
    // 弹窗
    // =========================================================
    private static void registerDialogs() {
        I18n.put("dialog.candidates.title", "候选字符", "Candidates");
        I18n.put("dialog.candidates.single_char_only",
                "Candidates 只支持单个 ASCII 字符。\n整段变形请使用 Ghost Encode 行的 Minimal / Full / Letters 等按钮。",
                "Candidates only supports a single ASCII char.\nFor whole-text encoding use Minimal / Full / Letters in the Ghost Encode row.");
        I18n.put("dialog.candidates.ascii_only",
                "Candidates 只接受 ASCII 原始字符。已 Ghost 化文本请使用 Preview 查看 Ghost 还原结果。",
                "Candidates only accepts raw ASCII. For Ghost-encoded text, use Preview to see the Ghost restore result.");
        I18n.put("dialog.tip.title", "提示", "Info");
        I18n.put("dialog.error.title", "错误", "Error");
        I18n.put("dialog.success.title", "成功", "Success");

        I18n.put("dialog.reinit.confirm",
                "确认重新初始化配置吗？此操作会覆盖你现有的配置文件。",
                "Reinitialize config? This will overwrite your existing config file.");
        I18n.put("dialog.reinit.title", "确认", "Confirm");
    }

    // =========================================================
    // ConfigPanel
    // =========================================================
    private static void registerConfig() {
        I18n.put("config.path_label", "Config Path:", "Config Path:");
        I18n.put("config.format.profiles", "Format: profiles", "Format: profiles");
        I18n.put("config.format.legacy", "Format: unsupported", "Format: unsupported");
        I18n.put("config.btn.reload", "重新加载", "Reload");
        I18n.put("config.btn.reinit", "恢复默认", "Reinit");
        I18n.put("config.btn.save_general", "保存通用配置", "Save General");
        I18n.put("config.btn.save_options", "保存选项", "Save Options");

        I18n.put("config.tab.general", "通用", "General");
        I18n.put("config.tab.access_control", "Auto-权限绕过", "Auto-Access Bypass");
        I18n.put("config.tab.waf", "Auto-WAF绕过", "Auto-WAF Bypass");
        I18n.put("config.tab.manual_waf", "Manual-WAF绕过", "Manual-WAF Bypass");
        I18n.put("config.tab.raw", "原始文件", "Raw");
        I18n.put("config.rules.access_control", "Rules: auto_access_bypass", "Rules: auto_access_bypass");
        I18n.put("config.rules.waf", "Rules: auto_waf_bypass", "Rules: auto_waf_bypass");
        I18n.put("config.rules.manual_waf", "Rules: manual_waf_bypass", "Rules: manual_waf_bypass");

        I18n.put("config.general.title", "通用配置", "General Options");
        I18n.put("config.general.threads", "线程数 (Threads):", "Threads:");
        I18n.put("config.general.max_redirects", "Max Redirects:", "Max Redirects:");
        I18n.put("config.general.max_redirects.hint",
                "(1-10，Dashboard 和 Manual WAF 的 Follow Redirect 共用)",
                "(1-10, shared by Dashboard and Manual WAF Follow Redirect)");
        I18n.put("config.general.threshold", "相似度阈值 (Diff Thresh):", "Similarity Threshold:");
        I18n.put("config.general.threshold.hint",
                "(0-1，值越大越\"宽松\"，更容易入表；值越小越\"严格\"，更少噪声)",
                "(0-1, larger = looser, more entries; smaller = stricter, less noise)");
        I18n.put("config.general.lang", "语言 (Language):", "Language:");
        I18n.put("config.general.lang.hint",
                "切换语言后保存并重新加载插件生效",
                "Save and reload the extension to apply language change");

        I18n.put("config.general.help",
                "说明：\n- 线程数：并发请求数，建议 3-10\n- Max Redirects：Follow Redirect 最大跳转次数，Dashboard 和 Manual WAF 共用\n- 相似度阈值：0-1 表示\"响应与原始响应的相似程度\"。\n  - 值越大：越容易入表（更宽松，噪声可能更多）\n  - 值越小：越不容易入表（更严格，只保留差异更大的响应）\n- 语言：切换 UI 语言（zh/en），保存后重启插件生效\n- 修改后点击 Save General 保存到配置文件\n- 保存后立即生效（Dashboard 不再单独维护阈值）",
                "Notes:\n- Threads: concurrent requests, recommended 3-10\n- Max Redirects: max Follow Redirect hops shared by Dashboard and Manual WAF\n- Similarity threshold: 0-1 = how similar the response is to the baseline.\n  - Larger: easier to record (looser, more noise)\n  - Smaller: harder to record (stricter, only big diffs kept)\n- Language: UI language (zh/en). Save then reload the extension to apply\n- Click Save General to persist changes\n- Effective immediately after save (Dashboard no longer keeps its own threshold)");

        I18n.put("config.waf.options.title",
                "Options (仅对 POST/PUT 等有 Body 的请求生效)",
                "Options (only for requests with body: POST/PUT/...)");
        I18n.put("config.waf.body_charset", "Body 字符集", "Body Charset");
        I18n.put("config.waf.body_transform", "Body 变换", "Body Transform");
        I18n.put("config.waf.content_type_spoof", "Content-Type 伪装", "Content-Type Spoof");
        I18n.put("config.waf.ghost_bits", "Ghost Bits 自动绕过", "Ghost Bits Auto Bypass");
        I18n.put("config.waf.ghost_enabled", "启用", "Enabled");
        I18n.put("config.waf.ghost_raw_socket", "Raw Socket", "Raw Socket");
        I18n.put("config.waf.ghost_max_variants", "最大变体:", "Max Variants:");
        I18n.put("config.waf.ghost_templates", "场景模板:", "Scenario Templates:");
        I18n.put("config.waf.ghost_generic", "等价变形:", "Equivalent Mutations:");
        I18n.put("config.waf.ghost_generic_enabled", "启用", "Enabled");
        I18n.put("config.waf.ghost_generic_variants", "每策略变体:", "Variants/strategy:");
        I18n.put("config.waf.help", "帮助", "Help");

        I18n.put("config.dialog.threads_range",
                "线程数应在 1-100 之间",
                "Threads must be between 1 and 100");
        I18n.put("config.dialog.max_redirects_range",
                "Max Redirects 应在 1-10 之间",
                "Max Redirects must be between 1 and 10");
        I18n.put("config.dialog.threshold_range",
                "相似度阈值应在 0-1 之间",
                "Threshold must be between 0 and 1");
        I18n.put("config.dialog.invalid_number", "请输入有效的数字", "Please enter a valid number");
        I18n.put("config.dialog.general_saved",
                "通用配置已保存",
                "General options saved successfully");
        I18n.put("config.dialog.general_save_failed",
                "保存通用配置失败",
                "Failed to save general options");
        I18n.put("config.dialog.options_saved",
                "选项已保存",
                "Options saved successfully");
        I18n.put("config.dialog.options_save_failed",
                "保存选项失败",
                "Failed to save options");
        I18n.put("config.dialog.no_loader",
                "ConfigLoader 不可用",
                "ConfigLoader not available");

        I18n.put("config.lang.restart_hint",
                "语言已切换，请重启 Burp 或重新加载插件以使所有界面更新。",
                "Language switched. Reload the extension or restart Burp to refresh all UI.");
    }
}
