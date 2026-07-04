package com.cloudintel.cad.registry;

/**
 * Minimal logging seam so the engine and registry never depend on Montoya types.
 * The extension entry point adapts Burp's Logging to this interface.
 */
public interface CadLogger {
    void info(String message);

    void error(String message);

    /** A no-op logger for contexts without Burp (e.g. local experimentation). */
    CadLogger NOOP = new CadLogger() {
        @Override
        public void info(String message) {
        }

        @Override
        public void error(String message) {
        }
    };
}
