package com.cloudintel.cad.engine;

/**
 * One fired indicator: which signal matched, its weight, and the matched text (for the
 * auto-composed "why detected" explanation).
 */
public record Hit(String indicatorId, int weight, String matchedText) {
}
