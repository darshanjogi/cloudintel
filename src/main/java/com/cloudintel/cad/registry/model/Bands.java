package com.cloudintel.cad.registry.model;

/**
 * Score cutoffs that map a raw evidence score to a named confidence band.
 * Populated by SnakeYAML from the {@code bands:} map in a fingerprint file.
 */
public class Bands {
    public int medium;
    public int high;
    public int very_high;

    public Bands() {
    }

    /** @return true if the cutoffs are strictly ascending (medium <= high <= very_high). */
    public boolean ascending() {
        return medium <= high && high <= very_high;
    }
}
