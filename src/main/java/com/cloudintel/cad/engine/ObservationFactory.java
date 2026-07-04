package com.cloudintel.cad.engine;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;

/**
 * Adapts Montoya's response type into a Burp-independent {@link HttpObservation}. This is the
 * only engine-side class that touches Montoya, keeping the pipeline testable on synthetic data.
 */
public final class ObservationFactory {

    /** Max response body characters to scan (bounds cost on large assets like JS bundles). */
    private static final int MAX_BODY_CHARS = 512 * 1024;

    private ObservationFactory() {
    }

    public static HttpObservation from(HttpResponseReceived response) {
        HttpRequest request = response.initiatingRequest();
        String url = request != null ? safe(request.url()) : "";
        String method = request != null ? safe(request.method()) : "GET";
        String host = request != null && request.httpService() != null
                ? request.httpService().host() : hostFromUrl(url);

        String mime = response.mimeType() != null
                ? response.mimeType().name().toLowerCase(Locale.ROOT) : "";
        String body = safe(response.bodyToString());
        if (body.length() > MAX_BODY_CHARS) {
            body = body.substring(0, MAX_BODY_CHARS);
        }

        HttpObservation.Builder b = HttpObservation.builder()
                .url(url)
                .method(method)
                .host(host)
                .statusCode(response.statusCode())
                .mimeType(mime)
                .bodyText(body);

        for (HttpHeader h : response.headers()) {
            b.header(h.name(), h.value());
        }
        for (Cookie c : response.cookies()) {
            b.cookieName(c.name());
        }
        return b.build();
    }

    private static String hostFromUrl(String url) {
        if (url == null) {
            return "";
        }
        int scheme = url.indexOf("://");
        if (scheme < 0) {
            return "";
        }
        int start = scheme + 3;
        int end = start;
        while (end < url.length()) {
            char c = url.charAt(end);
            if (c == '/' || c == ':' || c == '?' || c == '#') {
                break;
            }
            end++;
        }
        return url.substring(start, end).toLowerCase(Locale.ROOT);
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
