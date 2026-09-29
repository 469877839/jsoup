package org.jsoup.safety;

import org.jsoup.internal.Normalizer;
import org.jsoup.internal.StringUtil;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 Validates URL attribute values for {@link Cleaner#cleanStrict(org.jsoup.nodes.Document)}. Multi-candidate
 attributes (e.g. {@code srcset}) are split into their individual URLs, and each candidate's scheme is checked
 against the safelist's protocols. Parse results are cached by attribute value, so a repeated value is only parsed
 once per clean; this trades a little memory for avoiding repeated parse cost on large documents.
 <p>Instances are not thread-safe; create one per clean operation.</p>
 */
class UrlAttributeChecker {
    private final Safelist safelist;
    private final Map<String, String> schemeCache = new HashMap<>(); // raw URL -> normalized scheme ("" if none)
    private final Map<String, List<Candidate>> candidatesCache = new HashMap<>(); // raw srcset value -> parsed candidates
    private final Map<String, Resolved> resolveCache = new HashMap<>(); // raw URL -> absolute form

    UrlAttributeChecker(Safelist safelist) {
        this.safelist = safelist;
    }

    /**
     Checks the attribute's URL value(s) against the allowed protocols.
     @return the value to write into the cleaned document, or {@code null} if the attribute must be dropped
     */
    String check(String tagName, Element el, String key, String value, Set<Safelist.Protocol> protocols) {
        Set<String> allowed = new HashSet<>();
        for (Safelist.Protocol protocol : protocols)
            allowed.add(Normalizer.lowerCase(protocol.toString()));

        boolean writeAbs = safelist.shouldAbsUrl(tagName, key);
        if (isMultiCandidate(key))
            return checkCandidates(el.baseUri(), value, allowed, writeAbs);
        return checkSingle(el.baseUri(), value, allowed, writeAbs);
    }

    /** Attributes that hold a comma-separated list of URL candidates. */
    private static boolean isMultiCandidate(String key) {
        String lower = Normalizer.lowerCase(key);
        return lower.equals("srcset") || lower.equals("imagesrcset");
    }

    private String checkSingle(String baseUri, String value, Set<String> protocols, boolean writeAbs) {
        String abs = resolve(baseUri, value);
        // mirrors Safelist.getProtocolValue: an unresolvable value carrying an http(s) scheme is rejected outright
        String check = !abs.isEmpty() ? abs : StringUtil.hasHttpScheme(value) ? "" : value;
        if (check.isEmpty()) return null;

        String scheme = schemeOf(check);
        if (!scheme.isEmpty())
            return protocols.contains(scheme) ? writeback(writeAbs, abs, value) : null;
        if (check.startsWith("#")) // anchor links require the # protocol
            return protocols.contains("#") && Safelist.isValidAnchor(check) ? writeback(writeAbs, abs, value) : null;
        // a relative URL that could not be made absolute: only safe when relative links are preserved as-is
        return writeAbs ? null : value;
    }

    private static String writeback(boolean writeAbs, String abs, String value) {
        return writeAbs && !abs.isEmpty() ? abs : value;
    }

    private String checkCandidates(String baseUri, String value, Set<String> protocols, boolean writeAbs) {
        List<Candidate> candidates = candidatesOf(value);
        if (!writeAbs) { // preserving relative links: validate each candidate, keep the source text as-is
            for (Candidate candidate : candidates)
                if (checkSingle(baseUri, candidate.url, protocols, false) == null)
                    return null;
            return value;
        }
        // rejoin so that reparsing the written value yields the same candidates (stable under repeated cleans)
        StringBuilder sb = new StringBuilder(value.length());
        for (Candidate candidate : candidates) {
            String url = checkSingle(baseUri, candidate.url, protocols, true);
            if (url == null) return null; // any unsafe candidate drops the whole attribute
            if (sb.length() > 0) sb.append(", ");
            sb.append(url.indexOf(',') >= 0 ? url.replace(",", "%2C") : url); // a comma would split into different candidates on reparse
            if (!candidate.descriptors.isEmpty())
                sb.append(' ').append(candidate.descriptors);
        }
        return sb.toString();
    }

    private String schemeOf(String value) {
        String cached = schemeCache.get(value);
        if (cached != null) return cached;
        String scheme = extractScheme(value);
        schemeCache.put(value, scheme);
        return scheme;
    }

    private List<Candidate> candidatesOf(String value) {
        List<Candidate> cached = candidatesCache.get(value);
        if (cached != null) return cached;
        List<Candidate> candidates = parseCandidates(value);
        candidatesCache.put(value, candidates);
        return candidates;
    }

    private String resolve(String baseUri, String url) {
        Resolved resolved = resolveCache.get(url);
        if (resolved != null && resolved.baseUri.equals(baseUri)) return resolved.url;
        String abs = StringUtil.resolve(baseUri, url);
        resolveCache.put(url, new Resolved(baseUri, abs));
        return abs;
    }

    private static final Pattern SchemePattern = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+\\-.]*):");

    /**
     Extracts the URL scheme, after decoding percent-encoded bytes and removing ASCII whitespace and control
     characters (all of which browsers ignore or which may smuggle a scheme past a prefix match). E.g.
     {@code "JaVa\tScript:"} and {@code "%6Aavascript:"} are both seen as {@code javascript}. Returns "" if none.
     */
    static String extractScheme(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        int length = value.length();
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < length) {
                int hi = hex(value.charAt(i + 1)), lo = hex(value.charAt(i + 2));
                if (hi >= 0 && lo >= 0) {
                    int decoded = hi << 4 | lo;
                    if (decoded > 0x20 && decoded < 0x7f)
                        sb.append((char) decoded);
                    // else: decoded whitespace, control, or non-ASCII; dropped
                    i += 2;
                    continue;
                }
            }
            if (c > 0x20 && c != 0x7f)
                sb.append(c);
            // else: ASCII whitespace and control characters are ignored
        }
        Matcher matcher = SchemePattern.matcher(sb);
        return matcher.find() ? Normalizer.lowerCase(matcher.group(1)) : "";
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** Splits a srcset-style value: comma-separated candidates, each a URL followed by whitespace-separated descriptors. */
    private static List<Candidate> parseCandidates(String value) {
        List<Candidate> candidates = new ArrayList<>();
        int pos = 0, length = value.length();
        while (pos <= length) {
            int comma = value.indexOf(',', pos);
            int end = comma < 0 ? length : comma;
            int start = pos;
            while (start < end && value.charAt(start) <= ' ') start++;
            while (end > start && value.charAt(end - 1) <= ' ') end--;
            if (start < end) {
                int split = start;
                while (split < end && value.charAt(split) > ' ') split++;
                int descStart = split;
                while (descStart < end && value.charAt(descStart) <= ' ') descStart++;
                candidates.add(new Candidate(
                    value.substring(start, split),
                    descStart < end ? value.substring(descStart, end) : ""));
            }
            if (comma < 0) break;
            pos = comma + 1;
        }
        return candidates;
    }

    private static class Candidate {
        final String url;
        final String descriptors;

        Candidate(String url, String descriptors) {
            this.url = url;
            this.descriptors = descriptors;
        }
    }

    private static class Resolved {
        final String baseUri;
        final String url;

        Resolved(String baseUri, String url) {
            this.baseUri = baseUri;
            this.url = url;
        }
    }
}
