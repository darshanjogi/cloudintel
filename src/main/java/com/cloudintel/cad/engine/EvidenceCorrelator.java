package com.cloudintel.cad.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.cloudintel.cad.registry.model.ServiceFingerprint;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stateful, thread-safe hub. For each observation it runs every fingerprint, resolves the
 * asset, merges evidence into the per-asset {@link Finding}, and fires a callback when a
 * finding first crosses its reporting threshold or upgrades to a higher band. The source
 * HttpRequestResponse for each firing indicator is stored on the finding so users can view
 * exactly which traffic evidenced the detection and send it to Repeater.
 */
public final class EvidenceCorrelator {

    /** Notified when a finding becomes reportable or upgrades band. */
    public interface Listener {
        void onFindingChanged(Finding finding, boolean firstReport, String previousBand);
    }

    private final List<ServiceFingerprint> services;
    private final FingerprintMatcher matcher;
    private final ConfidenceScorer scorer;
    private final Listener listener;

    private final Map<AssetKey, Finding> findings = new ConcurrentHashMap<>();

    public EvidenceCorrelator(List<ServiceFingerprint> services,
                              FingerprintMatcher matcher,
                              ConfidenceScorer scorer,
                              Listener listener) {
        this.services = services;
        this.matcher = matcher;
        this.scorer = scorer;
        this.listener = listener;
    }

    /** Process one observation with no source request/response (synthetic / test path). */
    public void observe(HttpObservation obs) {
        observe(obs, null);
    }

    /** Process one observation and remember the source RR for any new hits it produces. */
    public void observe(HttpObservation obs, HttpRequestResponse source) {
        for (ServiceFingerprint svc : services) {
            FingerprintMatcher.Match m = matcher.match(svc, obs);
            if (m == null) continue;

            AssetKey key = new AssetKey(svc.provider, svc.id, m.assetId());
            Finding f = findings.computeIfAbsent(key, k -> new Finding(k, svc, m.assetLabel()));
            boolean firstReport;
            String previousBand;
            synchronized (f) {
                previousBand = f.band();
                boolean wasReported = f.reported();
                f.merge(m.hits(), obs.url(), source);
                boolean reportable = scorer.isReportable(f);
                if (!reportable) continue;
                String newBand = scorer.assignBand(f);
                firstReport = !wasReported;
                boolean bandChanged = !newBand.equals(previousBand);
                if (firstReport) f.markReported();
                if (!firstReport && !bandChanged) continue;
            }
            if (listener != null) listener.onFindingChanged(f, firstReport, previousBand);
        }
    }

    public List<Finding> reportedFindings() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings.values()) if (f.reported()) out.add(f);
        return out;
    }

    public Collection<Finding> allFindings() { return findings.values(); }
}
