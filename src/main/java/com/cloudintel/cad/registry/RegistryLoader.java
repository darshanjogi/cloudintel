package com.cloudintel.cad.registry;

import com.cloudintel.cad.registry.model.Bands;
import com.cloudintel.cad.registry.model.Extractor;
import com.cloudintel.cad.registry.model.Fingerprint;
import com.cloudintel.cad.registry.model.Indicator;
import com.cloudintel.cad.registry.model.ServiceFingerprint;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Stream;

/**
 * Loads provider fingerprint files (bundled resources + an optional user directory),
 * validates each service against the schema, compiles its regexes, and drops any
 * fingerprint that fails validation — logging exactly which file/service and why, so a
 * single bad (e.g. community-contributed) signature can never crash the load of the rest.
 */
public final class RegistryLoader {

    /** Classpath location of the bundled fingerprints and their index. */
    private static final String RESOURCE_DIR = "/fingerprints/";
    private static final String INDEX_RESOURCE = RESOURCE_DIR + "index.txt";

    private static final Set<String> ALLOWED_CATEGORIES = Set.of(
            "object-storage", "cdn", "compute", "serverless", "api", "auth",
            "database", "messaging", "dns", "platform", "secrets", "analytics");
    private static final Set<String> ALLOWED_SOURCES = Set.of(
            "host", "url", "header", "header-name", "body", "xml", "mime", "cookie", "redirect");
    private static final Set<String> ALLOWED_MATCHES = Set.of(
            "regex", "contains", "equals", "iequals");

    private final CadLogger log;

    public RegistryLoader(CadLogger log) {
        this.log = log == null ? CadLogger.NOOP : log;
    }

    /**
     * Load and validate every fingerprint. Bundled resources are read first, then any
     * {@code *.yaml} in {@code userDir} (may be null). Invalid services are skipped.
     *
     * @return all valid service fingerprints, each tagged with its provider.
     */
    public List<ServiceFingerprint> load(Path userDir) {
        List<ServiceFingerprint> out = new ArrayList<>();
        Set<String> seenIds = new LinkedHashSet<>();

        for (String resource : bundledResourceNames()) {
            String text = readResource(RESOURCE_DIR + resource);
            if (text != null) {
                loadOne("resource:" + resource, text, out, seenIds);
            }
        }

        if (userDir != null && Files.isDirectory(userDir)) {
            try (Stream<Path> files = Files.list(userDir)) {
                List<Path> yamls = files
                        .filter(p -> p.getFileName().toString().endsWith(".yaml"))
                        .sorted()
                        .toList();
                for (Path p : yamls) {
                    try {
                        String text = Files.readString(p, StandardCharsets.UTF_8);
                        loadOne(p.toString(), text, out, seenIds);
                    } catch (IOException e) {
                        log.error("CloudIntel: could not read user fingerprint " + p + ": " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                log.error("CloudIntel: could not list user fingerprint dir " + userDir + ": " + e.getMessage());
            }
        }

        log.info("CloudIntel: loaded " + out.size() + " service fingerprints from "
                + bundledResourceNames().size() + " bundled file(s)"
                + (userDir != null ? " + user dir " + userDir : ""));
        return out;
    }

    /** Parse one file's YAML and append its valid services. */
    private void loadOne(String origin, String text, List<ServiceFingerprint> out, Set<String> seenIds) {
        Fingerprint fp;
        try {
            fp = newYaml().load(text);
        } catch (RuntimeException e) {
            log.error("CloudIntel: skipping " + origin + " — YAML parse failed: " + e.getMessage());
            return;
        }
        if (fp == null || fp.provider == null || fp.provider.isBlank()) {
            log.error("CloudIntel: skipping " + origin + " — missing 'provider'");
            return;
        }
        if (fp.services == null || fp.services.isEmpty()) {
            log.error("CloudIntel: skipping " + origin + " — no services");
            return;
        }
        int kept = 0;
        for (ServiceFingerprint svc : fp.services) {
            List<String> problems = validate(svc);
            if (!problems.isEmpty()) {
                log.error("CloudIntel: skipping service '" + (svc.id == null ? "?" : svc.id)
                        + "' in " + origin + " — " + String.join("; ", problems));
                continue;
            }
            if (!seenIds.add(svc.id)) {
                log.error("CloudIntel: skipping duplicate service id '" + svc.id + "' in " + origin);
                continue;
            }
            svc.provider = fp.provider;
            out.add(svc);
            kept++;
        }
        log.info("CloudIntel: " + origin + " (" + fp.provider + ") — kept " + kept + "/" + fp.services.size() + " services");
    }

    /**
     * Validate one service and compile its regexes in place.
     *
     * @return a list of problems; empty means valid.
     */
    private List<String> validate(ServiceFingerprint svc) {
        List<String> problems = new ArrayList<>();
        if (svc == null) {
            return List.of("null service");
        }
        if (isBlank(svc.id)) {
            problems.add("missing id");
        }
        if (isBlank(svc.name)) {
            problems.add("missing name");
        }
        if (svc.category == null || !ALLOWED_CATEGORIES.contains(svc.category)) {
            problems.add("bad category: " + svc.category);
        }
        if (svc.require_distinct_indicators < 2) {
            problems.add("require_distinct_indicators must be >= 2 (was " + svc.require_distinct_indicators + ")");
        }
        Bands b = svc.bands;
        if (b == null) {
            problems.add("missing bands");
        } else if (!b.ascending()) {
            problems.add("bands not ascending: " + b.medium + "/" + b.high + "/" + b.very_high);
        } else if (b.medium < svc.report_threshold) {
            problems.add("medium band " + b.medium + " < report_threshold " + svc.report_threshold);
        }
        if (svc.indicators == null || svc.indicators.size() < 2) {
            problems.add("needs >= 2 indicators");
        } else {
            int maxWeight = 0;
            for (Indicator ind : svc.indicators) {
                if (isBlank(ind.id)) {
                    problems.add("indicator missing id");
                }
                if (ind.source == null || !ALLOWED_SOURCES.contains(ind.source)) {
                    problems.add("indicator '" + ind.id + "' bad source: " + ind.source);
                }
                if (ind.match == null || !ALLOWED_MATCHES.contains(ind.match)) {
                    problems.add("indicator '" + ind.id + "' bad match: " + ind.match);
                }
                if (isBlank(ind.pattern)) {
                    problems.add("indicator '" + ind.id + "' missing pattern");
                } else if ("regex".equals(ind.match)) {
                    try {
                        ind.compiled = Pattern.compile(ind.pattern);
                    } catch (PatternSyntaxException e) {
                        problems.add("indicator '" + ind.id + "' bad regex: " + e.getMessage());
                    }
                }
                maxWeight = Math.max(maxWeight, ind.weight);
            }
            // Single-signal guard: no lone indicator may clear the report threshold.
            if (maxWeight > svc.report_threshold) {
                problems.add("single-signal risk: max indicator weight " + maxWeight
                        + " > report_threshold " + svc.report_threshold);
            }
        }
        if (svc.asset != null && svc.asset.extractors != null) {
            for (Extractor ex : svc.asset.extractors) {
                if (isBlank(ex.regex)) {
                    problems.add("extractor missing regex");
                } else {
                    try {
                        ex.compiled = Pattern.compile(ex.regex);
                    } catch (PatternSyntaxException e) {
                        problems.add("extractor bad regex: " + e.getMessage());
                    }
                }
            }
        }
        return problems;
    }

    /** Names of bundled fingerprint files, read from the shipped index. */
    private List<String> bundledResourceNames() {
        String index = readResource(INDEX_RESOURCE);
        List<String> names = new ArrayList<>();
        if (index == null) {
            log.error("CloudIntel: bundled fingerprint index missing at " + INDEX_RESOURCE);
            return names;
        }
        for (String line : index.split("\\R")) {
            String name = line.trim();
            if (!name.isEmpty() && !name.startsWith("#") && name.endsWith(".yaml")) {
                names.add(name);
            }
        }
        return names;
    }

    private String readResource(String path) {
        try (InputStream in = RegistryLoader.class.getResourceAsStream(path)) {
            if (in == null) {
                return null;
            }
            try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                char[] buf = new char[8192];
                int n;
                while ((n = r.read(buf)) != -1) {
                    sb.append(buf, 0, n);
                }
                return sb.toString();
            }
        } catch (IOException e) {
            log.error("CloudIntel: could not read resource " + path + ": " + e.getMessage());
            return null;
        }
    }

    /** A SnakeYAML instance restricted to our own model classes (no arbitrary type construction). */
    private static Yaml newYaml() {
        LoaderOptions opts = new LoaderOptions();
        opts.setAllowDuplicateKeys(false);
        return new Yaml(new Constructor(Fingerprint.class, opts));
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
