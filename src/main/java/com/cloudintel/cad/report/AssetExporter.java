package com.cloudintel.cad.report;

import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.engine.Hit;

import java.util.List;

/**
 * Serializes discovered assets to JSON or CSV for hand-off. Dependency-free (hand-rolled)
 * so nothing extra needs to be shaded into the extension.
 */
public final class AssetExporter {

    private AssetExporter() {
    }

    /** All reported findings as a JSON array. */
    public static String toJson(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("  {\n");
            sb.append("    \"provider\": ").append(jstr(f.key().provider())).append(",\n");
            sb.append("    \"service\": ").append(jstr(f.service().name)).append(",\n");
            sb.append("    \"serviceId\": ").append(jstr(f.service().id)).append(",\n");
            sb.append("    \"assetId\": ").append(jstr(f.key().assetId())).append(",\n");
            sb.append("    \"band\": ").append(jstr(f.band())).append(",\n");
            sb.append("    \"score\": ").append(f.score()).append(",\n");
            sb.append("    \"threshold\": ").append(f.service().report_threshold).append(",\n");
            sb.append("    \"evidence\": [");
            List<Hit> ev = f.evidence();
            for (int j = 0; j < ev.size(); j++) {
                Hit h = ev.get(j);
                sb.append(jstr(h.indicatorId() + " (+" + h.weight() + "): " + h.matchedText()));
                if (j < ev.size() - 1) {
                    sb.append(", ");
                }
            }
            sb.append("],\n");
            sb.append("    \"relatedUrls\": [");
            List<String> urls = f.relatedUrls();
            for (int j = 0; j < urls.size(); j++) {
                sb.append(jstr(urls.get(j)));
                if (j < urls.size() - 1) {
                    sb.append(", ");
                }
            }
            sb.append("]\n");
            sb.append("  }").append(i < findings.size() - 1 ? "," : "").append("\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

    /** All reported findings as CSV (one row per asset). */
    public static String toCsv(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("provider,service,serviceId,assetId,band,score,threshold,evidenceCount,relatedUrls\n");
        for (Finding f : findings) {
            StringBuilder urls = new StringBuilder();
            List<String> u = f.relatedUrls();
            for (int i = 0; i < u.size(); i++) {
                urls.append(u.get(i));
                if (i < u.size() - 1) {
                    urls.append(" | ");
                }
            }
            sb.append(csv(f.key().provider())).append(",")
                    .append(csv(f.service().name)).append(",")
                    .append(csv(f.service().id)).append(",")
                    .append(csv(f.key().assetId())).append(",")
                    .append(csv(f.band())).append(",")
                    .append(f.score()).append(",")
                    .append(f.service().report_threshold).append(",")
                    .append(f.evidence().size()).append(",")
                    .append(csv(urls.toString())).append("\n");
        }
        return sb.toString();
    }

    private static String jstr(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    private static String csv(String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
