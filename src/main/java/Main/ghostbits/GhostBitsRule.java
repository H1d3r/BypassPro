package Main.ghostbits;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Ghost Bits 配置规则模型，对应 YAML 中 profiles.manual_waf_bypass.ghost_bits 部分。
 *
 * 三层结构：
 *  - atoms     : 单字节查表，目标 ASCII 字符 -> 候选 Unicode 字符列表
 *  - sequences : 命名好的 Unicode 字符序列（直接组合 atoms 的结果）
 *  - templates : 漏洞-中间件级别的组合模板，带 category/cve/sender/notes 元字段
 *
 * 该类只承载数据，不解析占位符；解析交给 {@link GhostBitsEngine}。
 */
public class GhostBitsRule {

    /** key 为目标 ASCII 字符（单字符 String，避免 char 的 boxing/转义麻烦），value 为候选 Unicode 字符列表 */
    private final Map<String, List<String>> atoms;

    /** key 为序列名，value 为预组合好的 Unicode 字符串 */
    private final Map<String, String> sequences;

    /** key 为模板 id，value 为模板对象 */
    private final Map<String, Template> templates;

    public GhostBitsRule(Map<String, List<String>> atoms,
                         Map<String, String> sequences,
                         Map<String, Template> templates) {
        this.atoms = atoms == null ? new LinkedHashMap<>() : atoms;
        this.sequences = sequences == null ? new LinkedHashMap<>() : sequences;
        this.templates = templates == null ? new LinkedHashMap<>() : templates;
    }

    public Map<String, List<String>> getAtoms() {
        return Collections.unmodifiableMap(atoms);
    }

    public Map<String, String> getSequences() {
        return Collections.unmodifiableMap(sequences);
    }

    public Map<String, Template> getTemplates() {
        return Collections.unmodifiableMap(templates);
    }

    /**
     * 取 atom 的候选列表。配置里没有 key 时返回空列表（调用方应改走引擎兜底枚举）。
     */
    public List<String> getAtomCandidates(String targetChar) {
        if (targetChar == null) {
            return Collections.emptyList();
        }
        List<String> list = atoms.get(targetChar);
        return list == null ? Collections.emptyList() : Collections.unmodifiableList(list);
    }

    /**
     * 取已命名序列。不存在返回 null。
     */
    public String getSequence(String name) {
        return sequences.get(name);
    }

    /**
     * 取模板。不存在返回 null。
     */
    public Template getTemplate(String id) {
        return templates.get(id);
    }

    /**
     * 模板对象。
     */
    public static class Template {
        private final String id;
        private final String category;
        private final String cve;
        private final String label;
        private final String target;   // path / filename / header_value / selection
        private final String pattern;  // 占位符语法见 GhostBitsEngine
        private final String sender;   // raw / any
        private final String notes;

        public Template(String id, String category, String cve, String label,
                        String target, String pattern, String sender, String notes) {
            this.id = id;
            this.category = category == null ? "" : category;
            this.cve = cve == null ? "" : cve;
            this.label = label == null ? id : label;
            this.target = target == null ? "selection" : target;
            this.pattern = pattern == null ? "" : pattern;
            this.sender = sender == null ? "any" : sender;
            this.notes = notes == null ? "" : notes;
        }

        public String getId() { return id; }
        public String getCategory() { return category; }
        public String getCve() { return cve; }
        public String getLabel() { return label; }
        public String getTarget() { return target; }
        public String getPattern() { return pattern; }
        public String getSender() { return sender; }
        public String getNotes() { return notes; }

        public boolean requiresRawSender() {
            return "raw".equalsIgnoreCase(sender);
        }
    }

    // ------------------------------------------------------------------
    // YAML -> Rule 解析
    // ------------------------------------------------------------------

    /**
     * 从 SnakeYAML 加载出来的 Map（profiles.manual_waf_bypass.ghost_bits 子树）构造规则对象。
     *
     * 容错策略：单条配置项类型不对就跳过该项，不抛异常，避免破坏整个规则集加载。
     */
    @SuppressWarnings("unchecked")
    public static GhostBitsRule fromMap(Map<String, Object> ghostBitsMap) {
        if (ghostBitsMap == null || ghostBitsMap.isEmpty()) {
            return new GhostBitsRule(null, null, null);
        }

        Map<String, List<String>> atoms = new LinkedHashMap<>();
        Object atomsObj = ghostBitsMap.get("atoms");
        if (atomsObj instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) atomsObj).entrySet()) {
                if (!(e.getKey() instanceof String)) {
                    continue;
                }
                String key = (String) e.getKey();
                List<String> candidates = new ArrayList<>();
                if (e.getValue() instanceof List) {
                    for (Object item : (List<?>) e.getValue()) {
                        if (item != null) {
                            candidates.add(item.toString());
                        }
                    }
                }
                atoms.put(key, candidates);
            }
        }

        Map<String, String> sequences = new LinkedHashMap<>();
        Object seqObj = ghostBitsMap.get("sequences");
        if (seqObj instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) seqObj).entrySet()) {
                if (e.getKey() instanceof String && e.getValue() != null) {
                    sequences.put((String) e.getKey(), e.getValue().toString());
                }
            }
        }

        Map<String, Template> templates = new LinkedHashMap<>();
        Object tmplObj = ghostBitsMap.get("templates");
        if (tmplObj instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) tmplObj).entrySet()) {
                if (!(e.getKey() instanceof String) || !(e.getValue() instanceof Map)) {
                    continue;
                }
                String id = (String) e.getKey();
                Map<String, Object> body = (Map<String, Object>) e.getValue();
                Template t = new Template(
                        id,
                        asString(body.get("category")),
                        asString(body.get("cve")),
                        asString(body.get("label")),
                        asString(body.get("target")),
                        asString(body.get("pattern")),
                        asString(body.get("sender")),
                        asString(body.get("notes"))
                );
                templates.put(id, t);
            }
        }

        return new GhostBitsRule(atoms, sequences, templates);
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }
}
