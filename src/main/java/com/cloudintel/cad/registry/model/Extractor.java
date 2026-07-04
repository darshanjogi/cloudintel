package com.cloudintel.cad.registry.model;

import java.util.regex.Pattern;

/**
 * Resolves the concrete asset identity (bucket / distribution / function / host) from an
 * observation. Extractors are tried in order; the first match wins.
 * Populated by SnakeYAML from an {@code asset.extractors:} list item.
 */
public class Extractor {
    /** host | url | body | header:&lt;name&gt; */
    public String from;
    public String regex;
    /** Capture-group reference for the asset id, e.g. {@code $1}. */
    public String asset_id = "$1";
    /** Human label with {@code $1}-style interpolation. */
    public String label;

    public transient Pattern compiled;

    public Extractor() {
    }

    /** @return the header name if {@code from} is {@code header:<name>}, else null. */
    public String headerName() {
        if (from != null && from.regionMatches(true, 0, "header:", 0, 7)) {
            return from.substring(7).trim();
        }
        return null;
    }
}
