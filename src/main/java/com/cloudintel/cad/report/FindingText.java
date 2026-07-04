package com.cloudintel.cad.report;

import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.engine.Hit;

/**
 * Shared rendering helpers: the auto-composed "why detected" line and {assetId}
 * interpolation. Used by both the issue reporter and the UI so the two stay consistent.
 */
public final class FindingText {

    private FindingText() {
    }

    /** Replace {@code {assetId}} occurrences with the finding's asset id. */
    public static String interpolate(String template, Finding f) {
        if (template == null) {
            return "";
        }
        return template.replace("{assetId}", f.key().assetId());
    }

    /**
     * Compose the real firing evidence, e.g.
     * "Matched host '.s3.amazonaws.com' (+40), header-name 'x-amz-request-id' (+30)".
     */
    public static String whyDetected(Finding f) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Hit h : f.evidence()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(h.indicatorId())
                    .append(" '")
                    .append(truncate(h.matchedText(), 80))
                    .append("' (+")
                    .append(h.weight())
                    .append(")");
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        String oneLine = s.replaceAll("\\s+", " ").trim();
        return oneLine.length() <= max ? oneLine : oneLine.substring(0, max) + "…";
    }
}
