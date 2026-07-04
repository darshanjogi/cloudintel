package com.cloudintel.cad.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.engine.Hit;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;

/**
 * The evidence viewer under a selected finding. Shows the list of firing indicators; picking
 * one loads its source request &amp; response into Burp's own read-only editors, with the
 * matched text set as the search expression so it is highlighted. "Send to Repeater" forwards
 * the exact triggering request into Burp Repeater.
 */
public final class EvidencePanel extends JPanel {

    private final MontoyaApi api;
    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;
    private final DefaultListModel<HitRow> hitsModel = new DefaultListModel<>();
    private final JList<HitRow> hitsList = new JList<>(hitsModel);
    private final JLabel status = new JLabel(" ");
    private final JButton sendBtn = new JButton("Send to Repeater");

    private Finding finding;
    private HitRow currentRow;

    public EvidencePanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.reqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        hitsList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedHit();
        });
        JScrollPane hitsScroll = new JScrollPane(hitsList);
        hitsScroll.setPreferredSize(new Dimension(320, 120));

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                reqEditor.uiComponent(), respEditor.uiComponent());
        editors.setResizeWeight(0.5);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sendBtn.setEnabled(false);
        sendBtn.addActionListener(e -> sendCurrentToRepeater());
        toolbar.add(sendBtn);
        toolbar.add(status);

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("  Firing indicators (click one to highlight in request/response):"),
                BorderLayout.NORTH);
        top.add(hitsScroll, BorderLayout.CENTER);
        top.add(toolbar, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, editors);
        split.setResizeWeight(0.25);
        add(split, BorderLayout.CENTER);
        showEmpty();
    }

    /** Load a finding's hits into the list; auto-select the first. */
    public void show(Finding f) {
        this.finding = f;
        hitsModel.clear();
        for (Hit h : f.evidence()) {
            HttpRequestResponse rr = f.sourceFor(h);
            hitsModel.addElement(new HitRow(h, rr));
        }
        if (!hitsModel.isEmpty()) {
            hitsList.setSelectedIndex(0);
        } else {
            clearEditors();
            status.setText("No captured request/response for this finding yet.");
            sendBtn.setEnabled(false);
        }
    }

    public void showEmpty() {
        this.finding = null;
        this.currentRow = null;
        hitsModel.clear();
        clearEditors();
        status.setText(" ");
        sendBtn.setEnabled(false);
    }

    private void showSelectedHit() {
        HitRow row = hitsList.getSelectedValue();
        this.currentRow = row;
        if (row == null || row.rr == null) {
            clearEditors();
            status.setText(row == null ? " " : "No captured request/response for this indicator.");
            sendBtn.setEnabled(false);
            return;
        }
        try {
            if (row.rr.request() != null) reqEditor.setRequest(row.rr.request());
            if (row.rr.response() != null) respEditor.setResponse(row.rr.response());
            // Highlight the matched text in both panes.
            String needle = row.hit.matchedText();
            if (needle != null && !needle.isBlank()) {
                String shortNeedle = shortenForSearch(needle);
                reqEditor.setSearchExpression(shortNeedle);
                respEditor.setSearchExpression(shortNeedle);
            }
            status.setText("Indicator: " + row.hit.indicatorId() + "   Matched: " + shortenForDisplay(row.hit.matchedText()));
            sendBtn.setEnabled(true);
        } catch (RuntimeException ex) {
            status.setText("Could not render evidence: " + ex.getMessage());
            sendBtn.setEnabled(false);
        }
    }

    private void sendCurrentToRepeater() {
        if (finding == null || currentRow == null || currentRow.rr == null || currentRow.rr.request() == null) {
            return;
        }
        try {
            api.repeater().sendToRepeater(currentRow.rr.request(),
                    "CloudIntel: " + finding.service().name);
            status.setText("Sent to Repeater: " + currentRow.rr.request().url());
        } catch (RuntimeException ex) {
            api.logging().logToError("CloudIntel: send-to-repeater failed: " + ex.getMessage());
            status.setText("Send to Repeater failed: " + ex.getMessage());
        }
    }

    private void clearEditors() {
        try {
            reqEditor.setRequest(null);
            respEditor.setResponse(null);
        } catch (RuntimeException ignored) {
            // Some Montoya builds reject null; ignore.
        }
    }

    /** Burp's search box handles short literal strings best. Trim regexy garbage. */
    private static String shortenForSearch(String s) {
        String t = s.replace("\n", " ").replace("\r", " ").trim();
        if (t.length() > 60) t = t.substring(0, 60);
        return t;
    }

    private static String shortenForDisplay(String s) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= 80 ? t : t.substring(0, 80) + "…";
    }

    /** One row in the hits list: the hit and its retained source RR (may be null). */
    private static final class HitRow {
        final Hit hit;
        final HttpRequestResponse rr;
        HitRow(Hit hit, HttpRequestResponse rr) { this.hit = hit; this.rr = rr; }
        @Override public String toString() {
            return hit.indicatorId() + " (+" + hit.weight() + ")"
                    + (rr == null ? "   [no source captured]" : "");
        }
    }
}
