package com.cloudintel.cad.registry.model;

import java.util.regex.Pattern;

/**
 * A single weighted detection signal. Multiple indicators sum toward a service's score.
 * Populated by SnakeYAML from a {@code indicators:} list item.
 */
public class Indicator {
    /** Unique within a service; identifies this signal in dedup and "why detected". */
    public String id;
    /** host | url | header | header-name | body | xml | mime | cookie | redirect */
    public String source;
    /** regex | contains | equals | iequals (default regex). */
    public String match = "regex";
    public String pattern;
    public int weight;

    /** Compiled form of {@link #pattern} when {@link #match} is regex; null otherwise. */
    public transient Pattern compiled;

    public Indicator() {
    }
}
