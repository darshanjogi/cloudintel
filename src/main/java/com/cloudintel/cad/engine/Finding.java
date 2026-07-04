package com.cloudintel.cad.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.cloudintel.cad.registry.model.ServiceFingerprint;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The live, accumulating record for one asset. Evidence is deduplicated by
 * (indicatorId + matchedText); the score is the sum of the weights of the distinct
 * indicator ids that have fired. The first HttpRequestResponse that evidenced each
 * indicator is retained so users can inspect and forward the exact triggering traffic.
 * Not thread-safe on its own — {@link EvidenceCorrelator} guards all mutation.
 */
public final class Finding {

    /** Cap on retained source request/response pairs to bound memory. */
    private static final int MAX_SOURCES = 8;

    private final AssetKey key;
    private final ServiceFingerprint service;
    private final String assetLabel;

    // Distinct evidence lines keyed by indicatorId + " " + matchedText.
    private final Map<String, Hit> evidence = new LinkedHashMap<>();
    // For each retained hit-key, the source request/response that evidenced it.
    private final Map<String, HttpRequestResponse> sourceByHit = new LinkedHashMap<>();
    // Ordered list of retained sources (deduped, capped).
    private final List<HttpRequestResponse> sources = new ArrayList<>();
    private final Set<String> relatedUrls = new java.util.LinkedHashSet<>();

    private int score;
    private String band = "";
    private boolean reported;

    public Finding(AssetKey key, ServiceFingerprint service, String assetLabel) {
        this.key = key;
        this.service = service;
        this.assetLabel = assetLabel;
    }

    public AssetKey key() { return key; }
    public ServiceFingerprint service() { return service; }
    public String assetLabel() { return assetLabel; }
    public int score() { return score; }
    public String band() { return band; }
    public boolean reported() { return reported; }
    public void markReported() { this.reported = true; }
    public List<Hit> evidence() { return new ArrayList<>(evidence.values()); }
    public List<String> relatedUrls() { return new ArrayList<>(relatedUrls); }

    /** Retained source request/responses that evidenced this finding (in insertion order). */
    public List<HttpRequestResponse> sources() { return new ArrayList<>(sources); }

    /** The source that evidenced a given hit, or null. */
    public HttpRequestResponse sourceFor(Hit hit) {
        return sourceByHit.get(hit.indicatorId() + " " + hit.matchedText());
    }

    public int distinctIndicatorCount() {
        Set<String> ids = new TreeSet<>();
        for (Hit h : evidence.values()) ids.add(h.indicatorId());
        return ids.size();
    }

    /**
     * Merge new hits (deduped) and a related URL; recompute the score. For each newly-added
     * hit, remember the source request/response (bounded).
     */
    public void merge(List<Hit> hits, String url, HttpRequestResponse source) {
        for (Hit h : hits) {
            String k = h.indicatorId() + " " + h.matchedText();
            if (evidence.putIfAbsent(k, h) == null && source != null) {
                sourceByHit.put(k, source);
                if (!sources.contains(source) && sources.size() < MAX_SOURCES) {
                    sources.add(source);
                }
            }
        }
        if (url != null && !url.isBlank()) relatedUrls.add(url);
        recomputeScore();
    }

    private void recomputeScore() {
        Map<String, Integer> weightById = new LinkedHashMap<>();
        for (Hit h : evidence.values()) weightById.putIfAbsent(h.indicatorId(), h.weight());
        int s = 0;
        for (int w : weightById.values()) s += w;
        this.score = s;
    }

    void setBand(String band) { this.band = band; }
}
