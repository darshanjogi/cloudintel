package com.cloudintel.cad.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A Burp-independent, normalized view of a single request/response exchange. The engine
 * consumes only this — never Montoya types — so the whole detection pipeline can run on
 * synthetic traffic.
 */
public final class HttpObservation {

    private final String url;
    private final String method;
    private final String host;
    private final int statusCode;
    private final String mimeType;
    private final String bodyText;
    // Response header names (lower-cased) -> original "Name: value" line list.
    private final Map<String, List<String>> headerLines;
    private final List<String> headerNamesLower;
    private final List<String> cookieNames;
    private final List<String> redirectTargets;

    private HttpObservation(Builder b) {
        this.url = b.url == null ? "" : b.url;
        this.method = b.method == null ? "GET" : b.method;
        this.host = b.host == null ? "" : b.host.toLowerCase(Locale.ROOT);
        this.statusCode = b.statusCode;
        this.mimeType = b.mimeType == null ? "" : b.mimeType;
        this.bodyText = b.bodyText == null ? "" : b.bodyText;
        this.headerLines = b.headerLines;
        this.headerNamesLower = b.headerNamesLower;
        this.cookieNames = b.cookieNames;
        this.redirectTargets = b.redirectTargets;
    }

    public String url() {
        return url;
    }

    public String method() {
        return method;
    }

    public String host() {
        return host;
    }

    public int statusCode() {
        return statusCode;
    }

    public String mimeType() {
        return mimeType;
    }

    public String bodyText() {
        return bodyText;
    }

    /** Full header lines as {@code "Name: value"}, for {@code source: header} matching. */
    public List<String> headerLines() {
        List<String> all = new ArrayList<>();
        for (List<String> v : headerLines.values()) {
            all.addAll(v);
        }
        return all;
    }

    /** Lower-cased header names present, for {@code source: header-name} matching. */
    public List<String> headerNamesLower() {
        return headerNamesLower;
    }

    public List<String> cookieNames() {
        return cookieNames;
    }

    public List<String> redirectTargets() {
        return redirectTargets;
    }

    /** First value for a header name (case-insensitive), or null. */
    public String headerValue(String name) {
        List<String> lines = headerLines.get(name.toLowerCase(Locale.ROOT));
        if (lines == null || lines.isEmpty()) {
            return null;
        }
        String line = lines.get(0);
        int colon = line.indexOf(':');
        return colon >= 0 ? line.substring(colon + 1).trim() : line;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Incremental builder used by the Burp adapter and by synthetic tests. */
    public static final class Builder {
        private String url;
        private String method;
        private String host;
        private int statusCode;
        private String mimeType;
        private String bodyText;
        private final Map<String, List<String>> headerLines = new LinkedHashMap<>();
        private final List<String> headerNamesLower = new ArrayList<>();
        private final List<String> cookieNames = new ArrayList<>();
        private final List<String> redirectTargets = new ArrayList<>();

        public Builder url(String v) {
            this.url = v;
            return this;
        }

        public Builder method(String v) {
            this.method = v;
            return this;
        }

        public Builder host(String v) {
            this.host = v;
            return this;
        }

        public Builder statusCode(int v) {
            this.statusCode = v;
            return this;
        }

        public Builder mimeType(String v) {
            this.mimeType = v;
            return this;
        }

        public Builder bodyText(String v) {
            this.bodyText = v;
            return this;
        }

        /** Add one response header. Location headers are also captured as redirect targets. */
        public Builder header(String name, String value) {
            if (name == null) {
                return this;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            headerLines.computeIfAbsent(lower, k -> new ArrayList<>()).add(name + ": " + value);
            headerNamesLower.add(lower);
            if (lower.equals("location") && value != null && !value.isBlank()) {
                redirectTargets.add(value.trim());
            }
            return this;
        }

        public Builder cookieName(String name) {
            if (name != null && !name.isBlank()) {
                cookieNames.add(name);
            }
            return this;
        }

        public HttpObservation build() {
            return new HttpObservation(this);
        }
    }
}
