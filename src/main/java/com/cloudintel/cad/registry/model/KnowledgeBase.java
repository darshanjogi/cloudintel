package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * The attack knowledge shown verbatim in the finding detail pane.
 * Populated by SnakeYAML from the {@code knowledge_base:} block of a service fingerprint.
 */
public class KnowledgeBase {
    public String description = "";
    public String why_detected = "";
    public List<AttackVector> attack_vectors = new ArrayList<>();
    public List<String> verification_steps = new ArrayList<>();
    public RepeaterTemplate repeater_template;
    public List<String> wordlists = new ArrayList<>();
    public List<String> references = new ArrayList<>();

    public KnowledgeBase() {
    }
}
