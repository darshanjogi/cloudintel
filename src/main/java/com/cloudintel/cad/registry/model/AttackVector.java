package com.cloudintel.cad.registry.model;

/**
 * One realistic, human-driven attack vector for a detected service.
 * Populated by SnakeYAML from a {@code knowledge_base.attack_vectors:} list item.
 * Either {@link #check} or {@link #wordlist} (or both) may be present.
 */
public class AttackVector {
    public String name;
    /** Concrete request/observation, may use {assetId} interpolation. */
    public String check;
    /** Suggested wordlist file for this vector. */
    public String wordlist;

    public AttackVector() {
    }
}
