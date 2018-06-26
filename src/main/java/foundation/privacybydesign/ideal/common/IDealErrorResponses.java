package foundation.privacybydesign.ideal.common;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class IDealErrorResponses extends IDealResponse {
    public IDealErrorResponses(Document doc) {
        super(doc);
    }

    // Get a specific error from the "Error" element.
    private String getError(String tagName) {
        NodeList errorList = doc.getElementsByTagNameNS("*", "Error");
        if (errorList.getLength() == 0) return null;
        Element error = (Element)errorList.item(0);

        NodeList errorPartList = error.getElementsByTagNameNS("*", tagName);
        if (errorPartList.getLength() == 0) return null;
        Element errorPart = (Element)errorPartList.item(0);
        return errorPart.getTextContent();
    }

    public String getErrorCode() {
        return getError("errorCode");
    }

    public String getErrorMessage() {
        return getError("errorMessage");
    }

    public String getErrorDetail() {
        return getError("errorDetail");
    }

    public String getSuggestedAction() {
        return getError("suggestedAction");
    }

    public String getConsumerMessage() {
        return getError("consumerMessage");
    }
}
