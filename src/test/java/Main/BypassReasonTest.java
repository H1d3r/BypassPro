package Main;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class BypassReasonTest {

    @Test
    public void includesSimilarityWhenBelowThreshold() {
        assertEquals(
                "status:403 -> 200; sim:0.42 < 0.85",
                BypassMain.buildAutoReason((short) 403, (short) 200, 0.42, 0.85, true));
    }

    @Test
    public void usesClassChangedWhenSimilarityDoesNotMatch() {
        assertEquals(
                "status:403 -> 200; class changed",
                BypassMain.buildAutoReason((short) 403, (short) 200, 0.90, 0.85, true));
    }

    @Test
    public void includesSimilarityWithoutClassChange() {
        assertEquals(
                "status:404 -> 404; sim:0.30 < 0.85",
                BypassMain.buildAutoReason((short) 404, (short) 404, 0.30, 0.85, false));
    }

    @Test
    public void rendersUnknownStatusAsQuestionMark() {
        assertEquals(
                "status:? -> 200; sim:0.10 < 0.85",
                BypassMain.buildAutoReason((short) -1, (short) 200, 0.10, 0.85, false));
    }

    @Test
    public void skipsNanSimilarityAndFallsBackToClassChanged() {
        assertEquals(
                "status:403 -> 200; class changed",
                BypassMain.buildAutoReason((short) 403, (short) 200, Double.NaN, 0.85, true));
    }

    @Test
    public void skipsNanSimilarityWithoutClassSignal() {
        assertEquals(
                "status:403 -> 200",
                BypassMain.buildAutoReason((short) 403, (short) 200, Double.NaN, 0.85, false));
    }

    @Test
    public void returnsEmptyWhenNoSignalExists() {
        assertEquals(
                "",
                BypassMain.buildAutoReason((short) -1, (short) -1, Double.NaN, 0.85, false));
    }
}
