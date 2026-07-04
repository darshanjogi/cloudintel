package com.cloudintel.cad.engine;

import com.cloudintel.cad.registry.model.Extractor;
import com.cloudintel.cad.registry.model.Indicator;
import com.cloudintel.cad.registry.model.ServiceFingerprint;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs one service fingerprint's indicators against a single observation and, if any fire,
 * resolves the concrete asset id. Pure and stateless — accumulation happens downstream in
 * {@link EvidenceCorrelator}.
 */
public final class FingerprintMatcher {

    /** Result of matching one fingerprint against one observation. */
    public record Match(String assetId, String assetLabel, List<Hit> hits) {
    }

    /**
     * @return a Match if the service fired at least one indicator and the observation is not
     *         denied; otherwise null.
     */
    public Match match(ServiceFingerprint svc, HttpObservation obs) {
        if (isDenied(svc, obs.host())) {
            return null;
        }
        List<Hit> hits = new ArrayList<>();
        for (Indicator ind : svc.indicators) {
            String matched = fire(ind, obs);
            if (matched != null) {
                hits.add(new Hit(ind.id, ind.weight, matched));
            }
        }
        if (hits.isEmpty()) {
            return null;
        }
        String[] asset = resolveAsset(svc, obs);
        if (asset == null) {
            return null; // no extractable asset and no host fallback
        }
        return new Match(asset[0], asset[1], hits);
    }

    /** @return the matched text if this indicator fires against the observation, else null. */
    private String fire(Indicator ind, HttpObservation obs) {
        switch (ind.source) {
            case "host":
                return matchOne(ind, single(obs.host()));
            case "url":
                return matchOne(ind, single(obs.url()));
            case "mime":
                return matchOne(ind, single(obs.mimeType()));
            case "body":
            case "xml":
                return matchOne(ind, single(obs.bodyText()));
            case "header":
                return matchOne(ind, obs.headerLines());
            case "header-name":
                return matchOne(ind, obs.headerNamesLower());
            case "cookie":
                return matchOne(ind, obs.cookieNames());
            case "redirect":
                return matchOne(ind, obs.redirectTargets());
            default:
                return null;
        }
    }

    private static List<String> single(String s) {
        return s == null ? List.of() : List.of(s);
    }

    /** Try the indicator against each candidate; return the first matching candidate text. */
    private String matchOne(Indicator ind, List<String> candidates) {
        for (String c : candidates) {
            if (c == null) {
                continue;
            }
            switch (ind.match) {
                case "contains":
                    if (c.contains(ind.pattern)) {
                        return c;
                    }
                    break;
                case "equals":
                    if (c.equals(ind.pattern)) {
                        return c;
                    }
                    break;
                case "iequals":
                    if (c.equalsIgnoreCase(ind.pattern)) {
                        return c;
                    }
                    break;
                case "regex":
                default:
                    Pattern p = ind.compiled != null ? ind.compiled : Pattern.compile(ind.pattern);
                    if (p.matcher(c).find()) {
                        return c;
                    }
                    break;
            }
        }
        return null;
    }

    /**
     * Resolve [assetId, label]. Tries each extractor in order; on no match, falls back to the
     * host if {@code host_level_fallback} is set. Returns null if neither yields an asset.
     */
    private String[] resolveAsset(ServiceFingerprint svc, HttpObservation obs) {
        if (svc.asset != null && svc.asset.extractors != null) {
            for (Extractor ex : svc.asset.extractors) {
                String input = extractorInput(ex, obs);
                if (input == null || input.isEmpty() || ex.compiled == null) {
                    continue;
                }
                Matcher m = ex.compiled.matcher(input);
                if (m.find()) {
                    String id = interpolate(ex.asset_id, m);
                    if (id != null && !id.isBlank()) {
                        String label = ex.label != null ? interpolate(ex.label, m) : id;
                        return new String[]{id, label};
                    }
                }
            }
        }
        boolean fallback = svc.asset != null && svc.asset.host_level_fallback;
        if (fallback && !obs.host().isEmpty()) {
            return new String[]{obs.host(), svc.name + " on " + obs.host()};
        }
        return null;
    }

    private String extractorInput(Extractor ex, HttpObservation obs) {
        if (ex.from == null) {
            return null;
        }
        String from = ex.from.toLowerCase(Locale.ROOT);
        if (from.equals("host")) {
            return obs.host();
        }
        if (from.equals("url")) {
            return obs.url();
        }
        if (from.equals("body")) {
            return obs.bodyText();
        }
        String headerName = ex.headerName();
        if (headerName != null) {
            return obs.headerValue(headerName);
        }
        return null;
    }

    /** Replace {@code $1}, {@code $2}, ... with capture groups from the matcher. */
    private String interpolate(String template, Matcher m) {
        if (template == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < template.length(); i++) {
            char ch = template.charAt(i);
            if (ch == '$' && i + 1 < template.length() && Character.isDigit(template.charAt(i + 1))) {
                int g = template.charAt(i + 1) - '0';
                i++;
                if (g >= 1 && g <= m.groupCount()) {
                    String grp = m.group(g);
                    sb.append(grp == null ? "" : grp);
                }
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private boolean isDenied(ServiceFingerprint svc, String host) {
        if (svc.deny == null || svc.deny.hosts == null || host == null || host.isEmpty()) {
            return false;
        }
        for (String glob : svc.deny.hosts) {
            if (globMatches(glob, host)) {
                return true;
            }
        }
        return false;
    }

    /** Simple glob: {@code *} matches any run of characters; matched case-insensitively. */
    private static boolean globMatches(String glob, String host) {
        if (glob == null) {
            return false;
        }
        StringBuilder re = new StringBuilder("(?i)");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                re.append(".*");
            } else {
                re.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return host.matches(re.toString());
    }
}
