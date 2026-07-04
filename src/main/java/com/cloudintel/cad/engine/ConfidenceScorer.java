package com.cloudintel.cad.engine;

import com.cloudintel.cad.registry.model.ServiceFingerprint;

/**
 * Decides whether a finding is reportable and assigns its band. A finding reports only when
 * it has at least {@code require_distinct_indicators} distinct signals AND its score strictly
 * exceeds the service {@code report_threshold}.
 */
public final class ConfidenceScorer {

    /** @return true if the finding now clears the reporting gate. */
    public boolean isReportable(Finding f) {
        ServiceFingerprint svc = f.service();
        if (f.distinctIndicatorCount() < svc.require_distinct_indicators) {
            return false;
        }
        return f.score() > svc.report_threshold;
    }

    /** Assign the band based on the current score; returns the band string. */
    public String assignBand(Finding f) {
        String band = f.service().bandFor(f.score());
        f.setBand(band);
        return band;
    }
}
