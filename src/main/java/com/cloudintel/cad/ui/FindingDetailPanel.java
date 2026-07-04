package com.cloudintel.cad.ui;

import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.engine.Hit;
import com.cloudintel.cad.registry.model.AttackVector;
import com.cloudintel.cad.registry.model.KnowledgeBase;
import com.cloudintel.cad.report.FindingText;

import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;

/**
 * Right-hand pane: renders the full knowledge base for the selected finding — band, score,
 * why-detected, attack vectors, verification steps, wordlists, and references.
 */
public final class FindingDetailPanel extends JPanel {

    private final JEditorPane editor = new JEditorPane();

    public FindingDetailPanel() {
        super(new BorderLayout());
        editor.setContentType("text/html");
        editor.setEditable(false);
        add(new JScrollPane(editor), BorderLayout.CENTER);
        showEmpty();
    }

    public void showEmpty() {
        editor.setText("<html><body style='font-family:sans-serif;padding:12px;color:#888;'>"
                + "Select a cloud asset on the left to see its evidence and attack surface."
                + "</body></html>");
        editor.setCaretPosition(0);
    }

    /** Render one finding. */
    public void show(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:sans-serif;padding:12px;'>");
        sb.append("<h2 style='margin-bottom:2px;'>").append(esc(f.service().name)).append("</h2>");
        sb.append("<div style='color:#666;margin-bottom:8px;'>")
                .append(esc(f.key().provider())).append(" &middot; ")
                .append(esc(f.service().category)).append("</div>");

        sb.append("<table cellpadding='3'>");
        row(sb, "Asset", esc(f.key().assetId()));
        row(sb, "Confidence", esc(f.band()) + " (score " + f.score()
                + ", threshold " + f.service().report_threshold + ")");
        row(sb, "Suggested severity", esc(f.service().severity));
        sb.append("</table>");

        sb.append("<h3>Why detected</h3><p>").append(esc(FindingText.whyDetected(f))).append("</p>");

        KnowledgeBase kb = f.service().knowledge_base;
        if (kb != null) {
            if (notBlank(kb.description)) {
                sb.append("<h3>Description</h3><p>").append(esc(kb.description)).append("</p>");
            }
            if (kb.attack_vectors != null && !kb.attack_vectors.isEmpty()) {
                sb.append("<h3>Attack surface</h3><ul>");
                for (AttackVector av : kb.attack_vectors) {
                    sb.append("<li><b>").append(esc(av.name)).append("</b>");
                    if (notBlank(av.check)) {
                        sb.append("<br><code>").append(esc(FindingText.interpolate(av.check, f))).append("</code>");
                    }
                    if (notBlank(av.wordlist)) {
                        sb.append("<br><i>wordlist:</i> ").append(esc(av.wordlist));
                    }
                    sb.append("</li>");
                }
                sb.append("</ul>");
            }
            if (kb.verification_steps != null && !kb.verification_steps.isEmpty()) {
                sb.append("<h3>Manual verification steps</h3><ol>");
                for (String s : kb.verification_steps) {
                    sb.append("<li>").append(esc(FindingText.interpolate(s, f))).append("</li>");
                }
                sb.append("</ol>");
            }
            if (kb.wordlists != null && !kb.wordlists.isEmpty()) {
                sb.append("<h3>Useful wordlists</h3><ul>");
                for (String w : kb.wordlists) {
                    sb.append("<li>").append(esc(w)).append("</li>");
                }
                sb.append("</ul>");
            }
            if (kb.references != null && !kb.references.isEmpty()) {
                sb.append("<h3>References</h3><ul>");
                for (String r : kb.references) {
                    sb.append("<li>").append(esc(r)).append("</li>");
                }
                sb.append("</ul>");
            }
        }

        if (!f.relatedUrls().isEmpty()) {
            sb.append("<h3>Related URLs seen</h3><ul>");
            for (String u : f.relatedUrls()) {
                sb.append("<li>").append(esc(u)).append("</li>");
            }
            sb.append("</ul>");
        }

        sb.append("<h3>Evidence</h3><ul>");
        for (Hit h : f.evidence()) {
            sb.append("<li>").append(esc(h.indicatorId())).append(" (+").append(h.weight())
                    .append("): <code>").append(esc(h.matchedText())).append("</code></li>");
        }
        sb.append("</ul>");

        sb.append("</body></html>");
        editor.setText(sb.toString());
        editor.setCaretPosition(0);
    }

    private static void row(StringBuilder sb, String k, String v) {
        sb.append("<tr><td style='color:#666;'><b>").append(k).append("</b></td><td>")
                .append(v).append("</td></tr>");
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
