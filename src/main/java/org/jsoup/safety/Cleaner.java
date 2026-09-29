package org.jsoup.safety;

import org.jsoup.helper.Validate;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.DataNode;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.NodeInternals;
import org.jsoup.nodes.Range;
import org.jsoup.nodes.TextNode;
import org.jsoup.parser.ParseErrorList;
import org.jsoup.parser.Parser;
import org.jsoup.select.NodeVisitor;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Set;

import static org.jsoup.internal.SharedConstants.DummyUri;

/**
 The {@link Safelist}-based HTML cleaner. Use to ensure that end-user provided HTML contains only the elements and attributes
 that you are expecting; no junk, and no cross-site scripting attacks!
 <p>
 The HTML cleaner parses the input as HTML and then runs it through a safelist, so the output HTML can only contain
 HTML that is allowed by the safelist.
 </p>
 <p>
 It is assumed that the input HTML is a body fragment; the clean methods only pull from the source's body, and the
 canned safelists only allow body-contained tags.
 </p>
 <p>
 Rather than interacting directly with a Cleaner object, generally see the {@code clean} methods in {@link org.jsoup.Jsoup}.
 </p>
 <p>
 A Cleaner may be reused across multiple documents and shared across concurrent threads once its {@link Safelist} has
 been configured. The cleaner uses the supplied safelist directly, so later safelist changes affect later cleaning
 calls. If you need a variant of an existing configuration, use {@link Safelist#Safelist(Safelist)} to make a copy.
 </p>
 */
public class Cleaner {
    private final Safelist safelist;

    /**
     Create a new cleaner, that sanitizes documents using the supplied safelist.
     @param safelist safe-list to clean with
     */
    public Cleaner(Safelist safelist) {
        Validate.notNull(safelist);
        this.safelist = safelist;
    }

    /**
     Creates a new, clean document, from the original dirty document, containing only elements allowed by the safelist.
     The original document is not modified. Only elements from the dirty document's <code>body</code> are used. The
     OutputSettings of the original document are cloned into the clean document.
     @param dirtyDocument Untrusted base document to clean.
     @return cleaned document.
     */
    public Document clean(Document dirtyDocument) {
        Validate.notNull(dirtyDocument);

        Document clean = Document.createShell(dirtyDocument.baseUri());
        copySafeNodes(dirtyDocument.body(), clean.body());
        clean.outputSettings(dirtyDocument.outputSettings().clone());

        return clean;
    }

    /**
     Creates a new, clean document from the dirty document, like {@link #clean(Document)}, but with strict URL
     validation. URL attributes (those with configured protocols) are checked per URL candidate: multi-candidate
     attributes such as {@code srcset} are split into their individual URLs, and each candidate's scheme is parsed
     and compared against the safelist's protocols. If any candidate is not allowed, the whole attribute is removed
     (the element itself is kept). Scheme parsing normalizes case, and ignores leading and trailing whitespace,
     ASCII control characters, and percent-encoding, so that e.g. {@code "JaVaScript:..."} and
     {@code "%6Aavascript:..."} are both seen as the {@code javascript} scheme. A namespaced attribute (e.g.
     {@code xlink:href}) is checked against the protocols of its local name ({@code href}) when it has no protocols
     of its own.
     <p>
     As in {@link #clean(Document)}, relative URLs are made absolute unless
     {@link Safelist#preserveRelativeLinks(boolean)} is set, in which case the source text is kept as-is. The
     written attribute values are stable: cleaning the output of this method produces byte-identical output.
     </p>
     <p>
     The input document is not modified. Only elements from the dirty document's <code>body</code> are used. The
     OutputSettings of the original document are cloned into the clean document.
     </p>
     @param dirtyDocument Untrusted base document to clean.
     @return cleaned document.
     */
    public Document cleanStrict(Document dirtyDocument) {
        Validate.notNull(dirtyDocument);

        Document clean = Document.createShell(dirtyDocument.baseUri());
        CleaningVisitor cleaningVisitor = new CleaningVisitor(dirtyDocument.body(), clean.body(), new UrlAttributeChecker(safelist));
        cleaningVisitor.traverse(dirtyDocument.body());
        clean.outputSettings(dirtyDocument.outputSettings().clone());

        return clean;
    }

    /**
     Determines if the input document's <b>body</b> is valid, against the safelist. It is considered valid if all the
     tags and attributes in the input HTML are allowed by the safelist, and that there is no content in the
     <code>head</code>.
     <p>
     This method is intended to be used in a user interface as a validator for user input. Note that regardless of the
     output of this method, the input document <b>must always</b> be normalized using a method such as
     {@link #clean(Document)}, and the result of that method used to store or serialize the document before later reuse
     such as presentation to end users. This ensures that enforced attributes are set correctly, and that any
     differences between how a given browser and how jsoup parses the input HTML are normalized.
     </p>
     <p>Example:
     <pre>{@code
     Document inputDoc = Jsoup.parse(inputHtml);
     Cleaner cleaner = new Cleaner(Safelist.relaxed());
     boolean isValid = cleaner.isValid(inputDoc);
     Document normalizedDoc = cleaner.clean(inputDoc);
     }</pre>
     </p>
     @param dirtyDocument document to test
     @return true if no tags or attributes need to be removed; false if they do
     */
    public boolean isValid(Document dirtyDocument) {
        Validate.notNull(dirtyDocument);

        Document clean = Document.createShell(dirtyDocument.baseUri());
        int numDiscarded = copySafeNodes(dirtyDocument.body(), clean.body());
        return numDiscarded == 0
            && dirtyDocument.head().childNodes().isEmpty(); // because we only look at the body, but we start from a shell, make sure there's nothing in the head
    }

    /**
     Determines if the input document's <b>body HTML</b> is valid, against the safelist. It is considered valid if all
     the tags and attributes in the input HTML are allowed by the safelist.
     <p>
     This method is intended to be used in a user interface as a validator for user input. Note that regardless of the
     output of this method, the input document <b>must always</b> be normalized using a method such as
     {@link #clean(Document)}, and the result of that method used to store or serialize the document before later reuse
     such as presentation to end users. This ensures that enforced attributes are set correctly, and that any
     differences between how a given browser and how jsoup parses the input HTML are normalized.
     </p>
     <p>Example:
     <pre>{@code
     Document inputDoc = Jsoup.parse(inputHtml);
     Cleaner cleaner = new Cleaner(Safelist.relaxed());
     boolean isValid = cleaner.isValidBodyHtml(inputHtml);
     Document normalizedDoc = cleaner.clean(inputDoc);
     }</pre>
     </p>
     @param bodyHtml HTML fragment to test
     @return true if no tags or attributes need to be removed; false if they do
     */
    public boolean isValidBodyHtml(String bodyHtml) {
        String baseUri = (safelist.preserveRelativeLinks()) ? DummyUri : ""; // fake base URI to allow relative URLs to remain valid
        Document clean = Document.createShell(baseUri);
        Document dirty = Document.createShell(baseUri);
        ParseErrorList errorList = ParseErrorList.tracking(1);
        List<Node> nodes = Parser.parseFragment(bodyHtml, dirty.body(), baseUri, errorList);
        dirty.body().insertChildren(0, nodes);
        int numDiscarded = copySafeNodes(dirty.body(), clean.body());
        return numDiscarded == 0 && errorList.isEmpty();
    }

    /**
     Iterates the input and copies trusted nodes (tags, attributes, text) into the destination.
     */
    private final class CleaningVisitor implements NodeVisitor {
        private int numDiscarded = 0;
        private final Element root;
        private Element destination; // current element to append nodes to
        private final UrlAttributeChecker urlChecker; // set in strict mode; null for the default clean

        private CleaningVisitor(Element root, Element destination) {
            this(root, destination, null);
        }

        private CleaningVisitor(Element root, Element destination, UrlAttributeChecker urlChecker) {
            this.root = root;
            this.destination = destination;
            this.urlChecker = urlChecker;
        }

        @Override public void head(Node source, int depth) {
            if (source instanceof Element) {
                Element sourceEl = (Element) source;

                if (safelist.isSafeTag(sourceEl.normalName())) { // safe, clone and copy safe attrs
                    ElementMeta meta = urlChecker == null ? createSafeElement(sourceEl) : createSafeElementStrict(sourceEl, urlChecker);
                    Element destChild = meta.el;
                    destination.appendChild(destChild);

                    numDiscarded += meta.numAttribsDiscarded;
                    destination = destChild;
                } else if (source != root) { // not a safe tag, so don't add. don't count root against discarded.
                    numDiscarded++;
                }
            } else if (source instanceof TextNode) {
                TextNode sourceText = (TextNode) source;
                TextNode destText = new TextNode(sourceText.getWholeText());
                destination.appendChild(destText);
            } else if (source instanceof DataNode && safelist.isSafeTag(source.parent().normalName())) {
                DataNode sourceData = (DataNode) source;
                DataNode destData = new DataNode(sourceData.getWholeData());
                destination.appendChild(destData);
            } else { // else, we don't care about comments, xml proc instructions, etc
                numDiscarded++;
            }
        }

        @Override public void tail(Node source, int depth) {
            if (source instanceof Element && safelist.isSafeTag(source.normalName())) {
                destination = destination.parent(); // would have descended, so pop destination stack
            }
        }
    }

    private int copySafeNodes(Element source, Element dest) {
        CleaningVisitor cleaningVisitor = new CleaningVisitor(source, dest);
        cleaningVisitor.traverse(source);
        return cleaningVisitor.numDiscarded;
    }

    private ElementMeta createSafeElement(Element sourceEl) {
        Element dest = sourceEl.shallowClone(); // reuses tag, clones attributes and preserves any user data
        String sourceTag = sourceEl.tagName();
        Attributes destAttrs = dest.attributes();
        dest.clearAttributes(); // clear all non-internal attributes, ready for safe copy

        int numDiscarded = 0;
        Attributes sourceAttrs = sourceEl.attributes();
        for (Attribute sourceAttr : sourceAttrs) {
            if (safelist.isSafeAttribute(sourceTag, sourceEl, sourceAttr)) { // will keep this attr
                String key = sourceAttr.getKey();
                String value = sourceAttr.getValue();

                if (safelist.shouldAbsUrl(sourceTag, key)) { // configured to make absolute urls for this key (href)
                    value = sourceEl.absUrl(key);
                    if (value.isEmpty()) // could not be made abs; leave as-is to allow custom unknown protocols
                        value = sourceAttr.getValue();
                }
                Range.AttributeRange range = sourceAttrs.sourceRange(key);
                destAttrs.put(key, value);
                NodeInternals.attributeRange(destAttrs, key, range);
            } else
                numDiscarded++;
        }

        applyEnforcedAttributes(sourceEl, sourceTag, destAttrs);
        dest.attributes().addAll(destAttrs); // re-attach, if removed in clear
        return new ElementMeta(dest, numDiscarded);
    }

    /**
     Like {@link #createSafeElement(Element)}, but validates URL attributes per candidate via the
     {@link UrlAttributeChecker}, and never writes back into the source element.
     */
    private ElementMeta createSafeElementStrict(Element sourceEl, UrlAttributeChecker urlChecker) {
        Element dest = sourceEl.shallowClone(); // reuses tag, clones attributes and preserves any user data
        String sourceTag = sourceEl.tagName();
        Attributes destAttrs = dest.attributes();
        dest.clearAttributes(); // clear all non-internal attributes, ready for safe copy

        int numDiscarded = 0;
        Attributes sourceAttrs = sourceEl.attributes();
        for (Attribute sourceAttr : sourceAttrs) {
            Set<Safelist.Protocol> protocols = safelist.strictAttributeProtocols(sourceTag, sourceAttr);
            if (protocols == null) { // attribute not allowed
                numDiscarded++;
                continue;
            }
            String key = sourceAttr.getKey();
            String value = sourceAttr.getValue();
            if (!protocols.isEmpty()) { // URL attribute; check each candidate's scheme
                value = urlChecker.check(sourceTag, sourceEl, key, value, protocols);
                if (value == null) { // a candidate was not safe; drop the whole attribute
                    numDiscarded++;
                    continue;
                }
            }
            Range.AttributeRange range = sourceAttrs.sourceRange(key);
            destAttrs.put(key, value);
            NodeInternals.attributeRange(destAttrs, key, range);
        }

        applyEnforcedAttributes(sourceEl, sourceTag, destAttrs);
        dest.attributes().addAll(destAttrs); // re-attach, if removed in clear
        return new ElementMeta(dest, numDiscarded);
    }

    private void applyEnforcedAttributes(Element sourceEl, String sourceTag, Attributes destAttrs) {
        Attributes enforcedAttrs = safelist.getEnforcedAttributes(sourceTag);
        // special case for <a href rel=nofollow>, only apply to external links:
        if (sourceEl.nameIs("a") && enforcedAttrs.get("rel").equals("nofollow")) {
            String href = sourceEl.absUrl("href");
            if (!href.isEmpty()) {
                try {
                    URL baseUrl = new URL(sourceEl.baseUri());
                    URL linkUrl = new URL(href);
                    String baseHost = baseUrl.getHost();
                    if (!baseHost.isEmpty() && baseHost.equalsIgnoreCase(linkUrl.getHost())) // same site, so don't set the nofollow
                        enforcedAttrs.remove("rel");
                } catch (MalformedURLException ignored) {}
            }
        }

        // apply enforced attributes case-insensitively, so a preserved-case source attr is canonicalized to the enforced key
        for (Attribute enforcedAttr : enforcedAttrs) {
            destAttrs.removeIgnoreCase(enforcedAttr.getKey());
            destAttrs.put(enforcedAttr.getKey(), enforcedAttr.getValue());
        }
    }

    private static class ElementMeta {
        Element el;
        int numAttribsDiscarded;

        ElementMeta(Element el, int numAttribsDiscarded) {
            this.el = el;
            this.numAttribsDiscarded = numAttribsDiscarded;
        }
    }

}
