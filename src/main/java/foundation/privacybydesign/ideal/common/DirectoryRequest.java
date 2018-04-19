package foundation.privacybydesign.ideal.common;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import sun.security.krb5.Config;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

public class DirectoryRequest {
    private Document doc;

    public DirectoryRequest(Configuration conf) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            doc = builder.newDocument();
            doc.setXmlStandalone(true);

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

            Element merchantIdElement = doc.createElement("merchantId");
            merchantIdElement.setTextContent(merchantId);
            merchant.appendChild(merchantIdElement);

            Element subIdElement = doc.createElement("subId");
            subIdElement.setTextContent(conf.getMerchantSubId());
            merchant.appendChild(subIdElement);

        } catch (ParserConfigurationException e) {
            throw new RuntimeException("unexpected XML builder exception");
        }
    }

    public void sign(PrivateKey sk, X509Certificate cert) {
        // Source:
        // http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
        try {
            // Configure how to sign: use SHA256, sign the entire document, and
            // some other options.
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference ref = factory.newReference("",
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    Collections.singletonList(
                            factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null)
                    ),
                    null,
                    null);
            SignedInfo si = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null),
                    factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                    Collections.singletonList(ref)
            );

            // Configure "KeyInfo" and "KeyName" tags.
            KeyInfoFactory kif = factory.getKeyInfoFactory();
            KeyName kn = kif.newKeyName(getFingerprint(cert));
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kn));

            // And sign!
            DOMSignContext dsc = new DOMSignContext(sk, doc.getDocumentElement());
            XMLSignature signature = factory.newXMLSignature(si, ki);
            signature.sign(dsc);
        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException | MarshalException | XMLSignatureException | CertificateEncodingException e) {
            throw new RuntimeException("unexpected crypto error");
        }
    }

    private String getFingerprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] digest = md.digest(cert.getEncoded());
        return DatatypeConverter.printHexBinary(digest);
    }

    // Output the directory request XML as a string.
    public String toString() {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer t = tf.newTransformer();
            t.setOutputProperty(OutputKeys.INDENT, "yes");
            t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter writer = new StringWriter();
            t.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.getBuffer().toString();
        } catch (TransformerException e) {
            throw new RuntimeException("unexpected XML transformer exception");
        }
    }
}
