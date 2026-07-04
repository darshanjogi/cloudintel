package com.cloudintel.cad;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.cloudintel.cad.engine.ConfidenceScorer;
import com.cloudintel.cad.engine.EvidenceCorrelator;
import com.cloudintel.cad.engine.FingerprintMatcher;
import com.cloudintel.cad.engine.HttpObservation;
import com.cloudintel.cad.engine.ObservationFactory;
import com.cloudintel.cad.registry.CadLogger;
import com.cloudintel.cad.registry.RegistryLoader;
import com.cloudintel.cad.registry.model.ServiceFingerprint;
import com.cloudintel.cad.report.IssueReporter;
import com.cloudintel.cad.ui.CadContextMenu;
import com.cloudintel.cad.ui.DashboardPanel;

import javax.swing.SwingUtilities;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Entry point for the CloudIntel Burp extension. Strictly passive: observes response traffic
 * and always continues it unchanged. Detection runs on a bounded background worker so Burp's
 * response threads and the UI are never blocked (BApp store threading requirement).
 */
public final class CadExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "CloudIntel";
    public static final String TAB_NAME = "CloudIntel";

    /** Cap on queued observations to bound memory when traffic bursts. */
    private static final int MAX_QUEUE_SIZE = 4096;

    private final List<Registration> registrations = new ArrayList<>();
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private Thread worker;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        CadLogger log = new CadLogger() {
            @Override public void info(String message) { api.logging().logToOutput(message); }
            @Override public void error(String message) { api.logging().logToError(message); }
        };

        // Load and validate the fingerprint registry.
        Path userDir = Path.of(System.getProperty("user.home"), ".cloudintel", "fingerprints");
        List<ServiceFingerprint> services = new RegistryLoader(log).load(userDir);
        if (services.isEmpty()) {
            api.logging().logToError("CloudIntel: no valid fingerprints loaded — detection disabled.");
        }

        // UI + reporter.
        DashboardPanel dashboard = new DashboardPanel(api);
        IssueReporter reporter = new IssueReporter(api);

        // Engine — the listener updates the dashboard and (on first report) raises an audit issue.
        EvidenceCorrelator correlator = new EvidenceCorrelator(
                services, new FingerprintMatcher(), new ConfidenceScorer(),
                (finding, firstReport, previousBand) -> {
                    try {
                        dashboard.onFindingChanged(finding);
                        if (firstReport) {
                            reporter.report(finding);
                        }
                    } catch (RuntimeException ex) {
                        api.logging().logToError("CloudIntel: listener error for "
                                + finding.key() + ": " + ex.getMessage());
                    }
                });
        dashboard.setCorrelator(correlator);

        // Bounded queue + single worker: keeps detection off Burp's response thread.
        LinkedBlockingQueue<PendingObservation> queue = new LinkedBlockingQueue<>(MAX_QUEUE_SIZE);
        worker = new Thread(() -> workerLoop(queue, correlator, api), "CloudIntel-worker");
        worker.setDaemon(true);
        worker.start();

        // Passive HTTP handler — always continueWith unchanged.
        Registration httpReg = api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(request);
            }
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                try {
                    HttpObservation obs = ObservationFactory.from(response);
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                            response.initiatingRequest(), response);
                    // Drop rather than block if the queue is full — never delay Burp's traffic.
                    queue.offer(new PendingObservation(obs, rr));
                } catch (RuntimeException ex) {
                    api.logging().logToError("CloudIntel: enqueue failed: " + ex.getMessage());
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
        registrations.add(httpReg);

        // UI tab + context menu — register on the EDT.
        SwingUtilities.invokeLater(() -> {
            try {
                api.userInterface().applyThemeToComponent(dashboard);
                registrations.add(api.userInterface().registerSuiteTab(TAB_NAME, dashboard));
            } catch (RuntimeException ex) {
                api.logging().logToError("CloudIntel: UI registration failed: " + ex.getMessage());
            }
        });
        registrations.add(api.userInterface().registerContextMenuItemsProvider(new CadContextMenu(api, dashboard)));

        // Clean unload: deregister everything and stop the worker (BApp criterion #6).
        api.extension().registerUnloadingHandler(() -> {
            stopping.set(true);
            for (Registration r : registrations) {
                try {
                    if (r != null && r.isRegistered()) r.deregister();
                } catch (RuntimeException ex) {
                    api.logging().logToError("CloudIntel: deregister failed: " + ex.getMessage());
                }
            }
            registrations.clear();
            if (worker != null) {
                worker.interrupt();
                try { worker.join(TimeUnit.SECONDS.toMillis(2)); } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            api.logging().logToOutput("CloudIntel: unloaded cleanly.");
        });

        api.logging().logToOutput("CloudIntel: loaded with " + services.size()
                + " service fingerprints. Passive detection active.");
    }

    /** Drains the queue, wrapping detection work so no uncaught exceptions kill the thread. */
    private void workerLoop(LinkedBlockingQueue<PendingObservation> queue,
                            EvidenceCorrelator correlator, MontoyaApi api) {
        while (!stopping.get()) {
            PendingObservation p;
            try {
                p = queue.poll(500, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (p == null) continue;
            try {
                correlator.observe(p.obs, p.rr);
            } catch (RuntimeException ex) {
                api.logging().logToError("CloudIntel: detection error: " + ex.getMessage());
            }
        }
    }

    /** Small holder so the queue can pass both the observation and the source RR. */
    private static final class PendingObservation {
        final HttpObservation obs;
        final HttpRequestResponse rr;
        PendingObservation(HttpObservation obs, HttpRequestResponse rr) {
            this.obs = obs; this.rr = rr;
        }
    }
}
