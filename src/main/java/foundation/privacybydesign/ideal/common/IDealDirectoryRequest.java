package foundation.privacybydesign.ideal.common;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class IDealDirectoryRequest extends IDealMessage {

    public IDealDirectoryRequest(Document doc) {
        super(doc);
    }

    // Create a new directory request message.
    public static IDealDirectoryRequest create(Configuration conf) {
        try {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();

            Element root = doc.createElement("DirectoryReq");
            root.setAttribute("xmlns", "http://www.idealdesk.com/ideal/messages/mer-acq/3.3.1");
            root.setAttribute("version", "3.3.1");
            doc.appendChild(root);

            Date date = new Date();
            SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
            dateFormatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            String timestamp = dateFormatter.format(date);
            Element timestampElement = doc.createElement("createDateTimestamp");
            timestampElement.setTextContent(timestamp);
            root.appendChild(timestampElement);

            Element merchant = doc.createElement("Merchant");
            root.appendChild(merchant);

            String merchantId = conf.getMerchantId();
            // "If the MerchantID has less than 9 digits, leading zeros must be
            // used to fill out the field."
            while (merchantId.length() < 9) {
                merchantId = "0" + merchantId;
            }

            Element merchantIdElement = doc.createElement("merchantID");
            merchantIdElement.setTextContent(merchantId);
            merchant.appendChild(merchantIdElement);

            Element subIdElement = doc.createElement("subID");
            subIdElement.setTextContent(conf.getMerchantSubId());
            merchant.appendChild(subIdElement);

            return new IDealDirectoryRequest(doc);

        } catch (ParserConfigurationException e) {
            throw new RuntimeException("unexpected XML exception");
        }
    }
}
