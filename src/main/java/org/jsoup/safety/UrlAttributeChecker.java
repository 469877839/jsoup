package org.jsoup.safety;

import org.jsoup.internal.StringUtil;
import org.jsoup.nodes.Attribute;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 Validates and rewrites URL attribute values for {@link Cleaner.Mode#Stable} cleaning. Multi-candidate attributes
 (such as {@code srcset}) are split into individual URL candidates; each candidate's scheme is parsed and checked
 against the safelist's allowed protocols. Parse results are cached by attribute value, so each distinct value is
 parsed only once per clean.
 */
final class UrlAttributeChecker {
    private final String baseUri;
    private final Map<String, List<Candidate>> valueCache = new HashMap<>(); // single-URL attribute values
    private final Map<String, List<Candidate>> srcsetCache = new HashMap<>(); // multi-candidate (srcset) values

    UrlAttributeChecker(String baseUri) {
        this.baseUri = baseUri;
    }

    /** A single URL candidate parsed from an attribute value, with its optional srcset-style descriptor. */
    private static final class Candidate {
        final String url; // control-stripped, trimmed URL token
        final String descriptor; // srcset descriptor (e.g. "2x"), or "" if none
        final @Nullable String scheme; // parsed lowercase scheme, or null if relative or an anchor
        @Nullable String resolved; // lazily resolved absolute URL, for relative candidates

        Candidate(String url, String descriptor) {
            this.url = url;
            this.descriptor = descriptor;
            this.scheme = schemeOf(url);
        }
    }

    /** Tests if every URL candidate in the attribute's value uses an allowed protocol. */
    boolean isSafeValue(Attribute attr, Set<String> protocols) {
        List<Candidate> candidates = candidatesFor(attr);
        if (candidates.isEmpty()) return false; // an empty URL attribute is not safe
        for (Candidate candidate : candidates) {
            if (!isSafeCandidate(candidate, protocols))
                return false;
        }
        return true;
    }

    /**
     Rewrites the attribute value, making relative URL candidates absolute against the base URI. Candidates that
     already carry a scheme (and anchors) keep their source spelling. Re-parsing the returned value yields the same
     candidates, so cleaning a cleaned document again gives the same output.
     */
    String absolutize(Attribute attr) {
        List<Candidate> candidates = candidatesFor(attr);
        if (!isSrcset(attr)) {
            Candidate candidate = candidates.get(0); // non-empty; only called on safe values
            return rewritten(candidate);
        }
        StringBuilder sb = StringUtil.borrowBuilder();
        for (Candidate candidate : candidates) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(rewritten(candidate));
            if (!candidate.descriptor.isEmpty())
                sb.append(' ').append(candidate.descriptor);
        }
        return StringUtil.releaseBuilder(sb);
    }

    private boolean isSafeCandidate(Candidate candidate, Set<String> protocols) {
        String url = candidate.url;
        if (url.isEmpty()) return false;
        if (isAnchor(url)) return protocols.contains("#") && Safelist.isValidAnchor(url);
        if (candidate.scheme != null) return protocols.contains(candidate.scheme);
        String resolved = resolve(candidate); // relative URL: test the scheme it resolves to against the base
        if (resolved.isEmpty()) return false;
        String scheme = schemeOf(resolved);
        return scheme != null && protocols.contains(scheme);
    }

    /** The absolute form of a relative candidate; scheme'd candidates and anchors keep their source spelling. */
    private String rewritten(Candidate candidate) {
        if (candidate.scheme != null || isAnchor(candidate.url)) return candidate.url;
        String resolved = resolve(candidate);
        return resolved.isEmpty() ? candidate.url : resolved;
    }

    private String resolve(Candidate candidate) {
        if (candidate.resolved == null)
            candidate.resolved = StringUtil.resolve(baseUri, candidate.url);
        return candidate.resolved;
    }

    private List<Candidate> candidatesFor(Attribute attr) {
        boolean srcset = isSrcset(attr);
        Map<String, List<Candidate>> cache = srcset ? srcsetCache : valueCache;
        return cache.computeIfAbsent(attr.getValue(), value -> srcset ? parseSrcset(value) : parseSingle(value));
    }

    private static boolean isSrcset(Attribute attr) {
        String localName = attr.localName();
        return localName.equalsIgnoreCase("srcset") || localName.equalsIgnoreCase("imagesrcset");
    }

    private static boolean isAnchor(String url) {
        return !url.isEmpty() && url.charAt(0) == '#';
    }

    private static List<Candidate> parseSingle(String value) {
        List<Candidate> candidates = new ArrayList<>(1);
        String url = stripAndTrim(value);
        if (!url.isEmpty())
            candidates.add(new Candidate(url, ""));
        return candidates;
    }

    /**
     Splits a srcset-style value into candidates. Candidates are separated by commas; within a candidate, the URL
     runs to the first whitespace, and the rest (up to the next comma) is the descriptor. A URL token ending in a
     comma ends the candidate with no descriptor. Re-joining the parsed candidates with ", " and " " separators
     re-parses to the same candidates.
     */
    private static List<Candidate> parseSrcset(String value) {
        List<Candidate> candidates = new ArrayList<>();
        int pos = 0, length = value.length();
        while (pos < length) {
            while (pos < length && isSeparator(value.charAt(pos))) pos++; // skip whitespace and commas
            if (pos >= length) break;

            int start = pos; // collect the URL token, up to whitespace
            while (pos < length && !StringUtil.isWhitespace(value.charAt(pos))) pos++;
            String token = value.substring(start, pos);

            int end = token.length(); // a trailing comma ends the candidate, and is not part of the URL
            while (end > 0 && token.charAt(end - 1) == ',') end--;
            boolean endedByComma = end < token.length();
            String url = stripControlChars(token.substring(0, end));
            if (url.isEmpty()) continue;

            String descriptor = "";
            if (!endedByComma) { // collect the descriptor, up to the next comma
                while (pos < length && StringUtil.isWhitespace(value.charAt(pos))) pos++;
                start = pos;
                while (pos < length && value.charAt(pos) != ',') pos++;
                descriptor = trim(stripControlChars(value.substring(start, pos)));
            }
            candidates.add(new Candidate(url, descriptor));
        }
        return candidates;
    }

    /** Parses the scheme of a URL: an ASCII alpha, then alphanumerics / {@code + - .}, up to a {@code :}. */
    static @Nullable String schemeOf(String url) {
        int length = url.length();
        if (length == 0 || !isAlpha(url.charAt(0))) return null;
        for (int i = 1; i < length; i++) {
            char c = url.charAt(i);
            if (c == ':') return url.substring(0, i).toLowerCase(Locale.ROOT);
            if (!isSchemeChar(c)) return null;
        }
        return null;
    }

    private static boolean isAlpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isSchemeChar(char c) {
        return isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
    }

    private static boolean isSeparator(char c) {
        return StringUtil.isWhitespace(c) || c == ',';
    }

    private static String stripAndTrim(String value) {
        return trim(stripControlChars(value));
    }

    /** Strips ASCII control characters, as browsers do when parsing URLs. */
    private static String stripControlChars(String value) {
        StringBuilder sb = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x1f) {
                if (sb == null) {
                    sb = new StringBuilder(value.length());
                    sb.append(value, 0, i);
                }
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb != null ? sb.toString() : value;
    }

    private static String trim(String value) {
        int start = 0, end = value.length();
        while (start < end && StringUtil.isWhitespace(value.charAt(start))) start++;
        while (end > start && StringUtil.isWhitespace(value.charAt(end - 1))) end--;
        return value.substring(start, end);
    }
}
