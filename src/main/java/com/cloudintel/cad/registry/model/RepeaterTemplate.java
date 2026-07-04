package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * A prefilled request the tester fires manually. {assetId} is interpolated at send time.
 * Populated by SnakeYAML from {@code knowledge_base.repeater_template}.
 */
public class RepeaterTemplate {
    public String method = "GET";
    public String url;
    /** Header lines as {@code "Name: value"} strings. */
    public List<String> headers = new ArrayList<>();

    public RepeaterTemplate() {
    }
}
