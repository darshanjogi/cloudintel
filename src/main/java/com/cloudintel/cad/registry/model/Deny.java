package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-service false-positive guard. Populated by SnakeYAML from the {@code deny:} block.
 */
public class Deny {
    /** Host globs that must never be fingerprinted, e.g. {@code *.internal}. */
    public List<String> hosts = new ArrayList<>();

    public Deny() {
    }
}
