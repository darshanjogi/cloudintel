package com.cloudintel.cad.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.registry.model.RepeaterTemplate;
import com.cloudintel.cad.report.FindingText;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

/**
 * Context-menu actions for the currently selected CAD finding: send the fingerprint's
 * prefilled Repeater template (the tester fires it), copy the endpoint, or open the checklist.
 */
public final class CadContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final DashboardPanel dashboard;

    public CadContextMenu(MontoyaApi api, DashboardPanel dashboard) {
        this.api = api;
        this.dashboard = dashboard;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Finding f = dashboard.selectedFinding();
        if (f == null) {
            return null;
        }
        List<Component> items = new ArrayList<>();

        JMenuItem toRepeater = new JMenuItem("CloudIntel: Send verification request to Repeater");
        toRepeater.addActionListener(e -> sendToRepeater(f));
        items.add(toRepeater);

        JMenuItem copy = new JMenuItem("CloudIntel: Copy endpoint");
        copy.addActionListener(e -> copyEndpoint(f));
        items.add(copy);

        return items;
    }

    private void sendToRepeater(Finding f) {
        RepeaterTemplate tpl = f.service().knowledge_base != null
                ? f.service().knowledge_base.repeater_template : null;
        String url = tpl != null && tpl.url != null && !tpl.url.isBlank()
                ? FindingText.interpolate(tpl.url, f)
                : "https://" + f.key().assetId() + "/";
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            if (tpl != null) {
                if (tpl.method != null && !tpl.method.isBlank()) {
                    request = request.withMethod(tpl.method);
                }
                if (tpl.headers != null) {
                    for (String line : tpl.headers) {
                        int colon = line.indexOf(':');
                        if (colon > 0) {
                            String name = line.substring(0, colon).trim();
                            String value = FindingText.interpolate(line.substring(colon + 1).trim(), f);
                            request = request.withHeader(name, value);
                        }
                    }
                }
            }
            api.repeater().sendToRepeater(request, "CloudIntel: " + f.service().name);
            api.logging().logToOutput("CloudIntel: sent verification request to Repeater for " + url);
        } catch (RuntimeException ex) {
            api.logging().logToError("CloudIntel: could not build Repeater request for " + url + ": " + ex.getMessage());
        }
    }

    private void copyEndpoint(Finding f) {
        List<String> urls = f.relatedUrls();
        String endpoint = !urls.isEmpty() ? urls.get(0) : "https://" + f.key().assetId() + "/";
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(endpoint), null);
        api.logging().logToOutput("CloudIntel: copied endpoint " + endpoint);
    }
}
