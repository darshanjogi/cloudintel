package com.cloudintel.cad.engine;

import java.util.Objects;

/**
 * Stable identity a finding accumulates on: provider + service + concrete asset.
 * Two observations that resolve to the same key merge their evidence.
 */
public final class AssetKey {
    private final String provider;
    private final String serviceId;
    private final String assetId;

    public AssetKey(String provider, String serviceId, String assetId) {
        this.provider = provider;
        this.serviceId = serviceId;
        this.assetId = assetId;
    }

    public String provider() {
        return provider;
    }

    public String serviceId() {
        return serviceId;
    }

    public String assetId() {
        return assetId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AssetKey other)) {
            return false;
        }
        return Objects.equals(provider, other.provider)
                && Objects.equals(serviceId, other.serviceId)
                && Objects.equals(assetId, other.assetId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(provider, serviceId, assetId);
    }

    @Override
    public String toString() {
        return provider + "/" + serviceId + "/" + assetId;
    }
}
