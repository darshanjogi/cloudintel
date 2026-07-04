package com.cloudintel.cad.report;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.registry.model.AttackVector;
import com.cloudintel.cad.registry.model.KnowledgeBase;

import java.util.List;

/**
 * Emits a native Burp {@link AuditIssue} for a reported finding and adds it to the site map,
 * so cloud findings appear in Burp's Target &gt; Issues view alongside CloudIntel's dashboard.
 * The issue's base URL is taken from the actual triggering request/response so the issue is
 * anchored to the real host in the target sitemap tree.
 */
public final class IssueReporter {

    private final MontoyaApi api;

    public IssueReporter(MontoyaApi api) {
        this.api = api;
    }

    /** Build and register an audit issue for the finding. */
    public void report(Finding f) {
        List<HttpRequestResponse> sources = f.sources();
        String baseUrl = pickBaseUrl(f, sources);

        String name = "Cloud service exposed: " + f.service().name;
        AuditIssue issue = AuditIssue.auditIssue(
                name,
                buildDetail(f),
                buildRemediation(f),
                baseUrl,
                mapSeverity(f.service().severity),
                mapConfidence(f.band()),
                shortBackground(f),
                null,
                mapSeverity(f.service().severity),
                sources);
        api.siteMap().add(issue);
    }

    /** Prefer the URL of the first retained source RR so Target > Issues shows the right host. */
    private static String pickBaseUrl(Finding f, List<HttpRequestResponse> sources) {
        if (!sources.isEmpty()) {
            try {
                String u = sources.get(0).url();
                if (u != null && !u.isBlank()) return u;
            } catch (RuntimeException ignored) {
                // Fall through.
            }
        }
        List<String> urls = f.relatedUrls();
        if (!urls.isEmpty()) return urls.get(0);
        return "https://" + f.key().assetId() + "/";
    }

    private String buildDetail(Finding f) {
        KnowledgeBase kb = f.service().knowledge_base;
        StringBuilder sb = new StringBuilder();
        sb.append("<p><b>Cloud service:</b> ").append(esc(f.service().name))
                .append(" (").append(esc(f.service().provider)).append(")</p>");
        sb.append("<p><b>Asset:</b> ").append(esc(f.key().assetId())).append("</p>");
        sb.append("<p><b>Confidence band:</b> ").append(esc(f.band()))
                .append(" (score ").append(f.score())
                .append(", threshold ").append(f.service().report_threshold).append(")</p>");
        sb.append("<p><b>Why detected:</b> ").append(esc(FindingText.whyDetected(f))).append("</p>");

        if (kb != null && kb.description != null && !kb.description.isBlank()) {
            sb.append("<p>").append(esc(kb.description)).append("</p>");
        }
        if (kb != null && kb.attack_vectors != null && !kb.attack_vectors.isEmpty()) {
            sb.append("<p><b>Possible attack vectors:</b></p><ul>");
            for (AttackVector av : kb.attack_vectors) {
                sb.append("<li>").append(esc(av.name));
                if (av.check != null && !av.check.isBlank()) {
                    sb.append(" &mdash; ").append(esc(FindingText.interpolate(av.check, f)));
                }
                if (av.wordlist != null && !av.wordlist.isBlank()) {
                    sb.append(" [wordlist: ").append(esc(av.wordlist)).append("]");
                }
                sb.append("</li>");
            }
            sb.append("</ul>");
        }
        List<String> urls = f.relatedUrls();
        if (!urls.isEmpty()) {
            sb.append("<p><b>Related URLs:</b></p><ul>");
            for (String u : urls) sb.append("<li>").append(esc(u)).append("</li>");
            sb.append("</ul>");
        }
        return sb.toString();
    }

    private String buildRemediation(Finding f) {
        KnowledgeBase kb = f.service().knowledge_base;
        if (kb == null || kb.verification_steps == null || kb.verification_steps.isEmpty()) {
            return "Manually verify the exposure and apply least-privilege access controls.";
        }
        StringBuilder sb = new StringBuilder("<p><b>Manual verification steps:</b></p><ol>");
        for (String step : kb.verification_steps) {
            sb.append("<li>").append(esc(FindingText.interpolate(step, f))).append("</li>");
        }
        sb.append("</ol>");
        if (kb.references != null && !kb.references.isEmpty()) {
            sb.append("<p><b>References:</b></p><ul>");
            for (String ref : kb.references) sb.append("<li>").append(esc(ref)).append("</li>");
            sb.append("</ul>");
        }
        return sb.toString();
    }

    private String shortBackground(Finding f) {
        KnowledgeBase kb = f.service().knowledge_base;
        if (kb != null && kb.description != null && !kb.description.isBlank()) {
            return esc(kb.description);
        }
        return "Cloud infrastructure artifact detected passively from HTTP traffic.";
    }

    private static AuditIssueSeverity mapSeverity(String severity) {
        if (severity == null) return AuditIssueSeverity.INFORMATION;
        switch (severity.toLowerCase()) {
            case "high": return AuditIssueSeverity.HIGH;
            case "medium": return AuditIssueSeverity.MEDIUM;
            case "low": return AuditIssueSeverity.LOW;
            default: return AuditIssueSeverity.INFORMATION;
        }
    }

    private static AuditIssueConfidence mapConfidence(String band) {
        if (band == null) return AuditIssueConfidence.TENTATIVE;
        switch (band) {
            case "Very High": return AuditIssueConfidence.CERTAIN;
            case "High": return AuditIssueConfidence.FIRM;
            default: return AuditIssueConfidence.TENTATIVE;
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
