package com.cloudintel.cad.registry.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Top-level object for one provider fingerprint file: a provider name and its services.
 * Populated by SnakeYAML from a whole {@code *.yaml} file.
 */
public class Fingerprint {
    public String provider;
    public List<ServiceFingerprint> services = new ArrayList<>();

    public Fingerprint() {
    }
}
