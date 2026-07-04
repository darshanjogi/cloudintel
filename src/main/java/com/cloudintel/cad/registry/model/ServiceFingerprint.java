package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * One cloud service's complete fingerprint: identity, weighted indicators, guards, and
 * knowledge base. Populated by SnakeYAML from a {@code services:} list item.
 */
public class ServiceFingerprint {
    public String id;
    public String name;
    public String category;
    public String severity = "information";
    public int report_threshold;
    public Bands bands;
    public int require_distinct_indicators = 2;
    public AssetSpec asset;
    public List<Indicator> indicators = new ArrayList<>();
    public Deny deny;
    public KnowledgeBase knowledge_base;

    /** Set by RegistryLoader after load so findings can show their provider. */
    public transient String provider;

    public ServiceFingerprint() {
    }

    /** Map a raw score to a named band. Assumes score has already cleared report_threshold. */
    public String bandFor(int score) {
        if (bands == null) {
            return "Medium";
        }
        if (score >= bands.very_high) {
            return "Very High";
        }
        if (score >= bands.high) {
            return "High";
        }
        return "Medium";
    }
}
