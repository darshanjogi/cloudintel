package com.cloudintel.cad.ui;

import burp.api.montoya.MontoyaApi;
import com.cloudintel.cad.engine.AssetKey;
import com.cloudintel.cad.engine.EvidenceCorrelator;
import com.cloudintel.cad.engine.Finding;
import com.cloudintel.cad.report.AssetExporter;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The CloudIntel tab: a provider &rarr; service &rarr; asset tree on the left, and on the
 * right a vertical split of the knowledge-base detail pane over an evidence viewer that
 * shows the exact request/response that triggered each hit (with highlights) and can forward
 * it to Repeater. Thread-safe entry point is {@link #onFindingChanged}; all Swing mutation is
 * marshalled onto the EDT.
 */
public final class DashboardPanel extends JPanel {

    private final MontoyaApi api;
    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("CloudIntel");
    private final DefaultTreeModel treeModel = new DefaultTreeModel(root);
    private final JTree tree = new JTree(treeModel);
    private final FindingDetailPanel detail = new FindingDetailPanel();
    private final EvidencePanel evidence;

    private final Map<String, DefaultMutableTreeNode> providerNodes = new HashMap<>();
    private final Map<String, DefaultMutableTreeNode> serviceNodes = new HashMap<>();
    private final Map<AssetKey, DefaultMutableTreeNode> assetNodes = new HashMap<>();
    private final Map<DefaultMutableTreeNode, Finding> nodeFindings = new HashMap<>();

    private EvidenceCorrelator correlator;

    public DashboardPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.evidence = new EvidencePanel(api);

        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setRootVisible(true);
        tree.addTreeSelectionListener(e -> updateRightPane());

        JButton exportBtn = new JButton("Export assets…");
        exportBtn.addActionListener(e -> exportAssets());
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.add(exportBtn);

        JPanel left = new JPanel(new BorderLayout());
        left.add(toolbar, BorderLayout.NORTH);
        left.add(new JScrollPane(tree), BorderLayout.CENTER);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detail, evidence);
        rightSplit.setResizeWeight(0.45);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, rightSplit);
        split.setDividerLocation(340);
        add(split, BorderLayout.CENTER);
    }

    public void setCorrelator(EvidenceCorrelator correlator) {
        this.correlator = correlator;
    }

    /** Currently selected finding, or null (used by the Burp context menu). */
    public Finding selectedFinding() {
        Object last = tree.getLastSelectedPathComponent();
        if (last instanceof DefaultMutableTreeNode node) {
            return nodeFindings.get(node);
        }
        return null;
    }

    /** Called by the correlator (any thread) when a finding is reported or upgrades band. */
    public void onFindingChanged(Finding f) {
        SwingUtilities.invokeLater(() -> upsert(f));
    }

    private void updateRightPane() {
        Finding f = selectedFinding();
        if (f == null) {
            detail.showEmpty();
            evidence.showEmpty();
        } else {
            detail.show(f);
            evidence.show(f);
        }
    }

    private void upsert(Finding f) {
        String provider = f.key().provider();
        String serviceKey = provider + "||" + f.service().id;

        DefaultMutableTreeNode providerNode = providerNodes.computeIfAbsent(provider, p -> {
            DefaultMutableTreeNode n = new DefaultMutableTreeNode(p);
            treeModel.insertNodeInto(n, root, root.getChildCount());
            return n;
        });
        DefaultMutableTreeNode serviceNode = serviceNodes.computeIfAbsent(serviceKey, k -> {
            DefaultMutableTreeNode n = new DefaultMutableTreeNode(new ServiceLabel(f.service().name, 0));
            treeModel.insertNodeInto(n, providerNode, providerNode.getChildCount());
            return n;
        });

        DefaultMutableTreeNode assetNode = assetNodes.get(f.key());
        if (assetNode == null) {
            assetNode = new DefaultMutableTreeNode(assetLabel(f));
            assetNodes.put(f.key(), assetNode);
            nodeFindings.put(assetNode, f);
            treeModel.insertNodeInto(assetNode, serviceNode, serviceNode.getChildCount());
            ServiceLabel sl = (ServiceLabel) serviceNode.getUserObject();
            serviceNode.setUserObject(new ServiceLabel(sl.name, sl.count + 1));
            treeModel.nodeChanged(serviceNode);
        } else {
            assetNode.setUserObject(assetLabel(f));
            treeModel.nodeChanged(assetNode);
            if (assetNode.equals(tree.getLastSelectedPathComponent())) {
                // Refresh right pane if the currently-selected finding upgraded.
                updateRightPane();
            }
        }
        tree.expandPath(new TreePath(providerNode.getPath()));
    }

    private static String assetLabel(Finding f) {
        return f.key().assetId() + "  [" + f.band() + " · " + f.score() + "]";
    }

    /** Parent modal dialogs to Burp's suite frame so multi-monitor placement works. */
    private Component parentFrame() {
        try {
            Frame f = api.userInterface().swingUtils().suiteFrame();
            if (f != null) return f;
        } catch (RuntimeException ignored) {
            // Fall through — use this panel's window.
        }
        return this;
    }

    private void exportAssets() {
        if (correlator == null) return;
        List<Finding> reported = correlator.reportedFindings();
        if (reported.isEmpty()) {
            JOptionPane.showMessageDialog(parentFrame(), "No reported findings to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export assets (choose base name; .json and .csv are written)");
        if (chooser.showSaveDialog(parentFrame()) != JFileChooser.APPROVE_OPTION) return;
        String base = chooser.getSelectedFile().getAbsolutePath();
        String jsonPath = base.endsWith(".json") ? base : base + ".json";
        String csvPath = base.endsWith(".json") ? base.substring(0, base.length() - 5) + ".csv" : base + ".csv";
        try {
            Files.writeString(java.nio.file.Path.of(jsonPath), AssetExporter.toJson(reported), StandardCharsets.UTF_8);
            Files.writeString(java.nio.file.Path.of(csvPath), AssetExporter.toCsv(reported), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(parentFrame(), "Exported " + reported.size()
                    + " assets to:\n" + jsonPath + "\n" + csvPath);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static final class ServiceLabel {
        final String name;
        final int count;
        ServiceLabel(String name, int count) { this.name = name; this.count = count; }
        @Override public String toString() { return name + " (" + count + ")"; }
    }
}
