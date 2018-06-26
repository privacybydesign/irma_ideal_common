package foundation.privacybydesign.ideal.common;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;

public class IDealResponse extends IDealMessage {
    public IDealResponse(Document doc) {
        super(doc);
    }

    public static IDealResponse get(InputStream stream)
            throws IOException, SAXException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Document doc = factory.newDocumentBuilder().parse(stream);
            String name = doc.getDocumentElement().getLocalName();
            if (name.equals("AcquirerErrorRes")) {
                return new IDealErrorResponses(doc);
            } else {
                // TODO: more response types
                return new IDealResponse(doc);
            }
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("unexpected XML exception");
        }
    }
}
