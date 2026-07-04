package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * How to identify the concrete asset for a service. Populated by SnakeYAML from the
 * {@code asset:} block of a service fingerprint.
 */
public class AssetSpec {
    public List<Extractor> extractors = new ArrayList<>();
    /** When no extractor matches, attach header-only evidence to the observed host. */
    public boolean host_level_fallback = false;

    public AssetSpec() {
    }
}
