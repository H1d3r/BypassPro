package Main.ghostbits;

/**
 * Auto WAF 中的一条 Ghost Bits 探测变体。
 */
public class GhostBitsAutoVariant {
    private final byte[] requestBytes;
    private final String templateId;
    private final String label;
    private final String target;
    private final boolean rawRequired;
    private final String reason;

    public GhostBitsAutoVariant(byte[] requestBytes,
                                String templateId,
                                String label,
                                String target,
                                boolean rawRequired,
                                String reason) {
        this.requestBytes = requestBytes == null ? new byte[0] : requestBytes;
        this.templateId = templateId == null ? "" : templateId;
        this.label = label == null ? "" : label;
        this.target = target == null ? "" : target;
        this.rawRequired = rawRequired;
        this.reason = reason == null ? "" : reason;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public String getTemplateId() {
        return templateId;
    }

    public String getLabel() {
        return label;
    }

    public String getTarget() {
        return target;
    }

    public boolean isRawRequired() {
        return rawRequired;
    }

    public String getReason() {
        return reason;
    }
}
