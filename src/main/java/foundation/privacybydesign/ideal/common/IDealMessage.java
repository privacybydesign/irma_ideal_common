package foundation.privacybydesign.ideal.common;

import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class IDealMessage {
    protected Document doc;

    public IDealMessage(Document doc) {
        this.doc = doc;
    }

    // Put a signature on this iDeal message. Should be called only once.
    // The private key is the key to sign with, and the certificate is used to
    // generate a fingerprint (must be part of the message).
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

    // Verify a signature. Will silently return on success and throw an error on
    // a validation error (e.g. invalid signature).
    public void validate(X509Certificate cert) throws IDealValidationException {
        // Source:
        // http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
        try {
            // Find Signature element.
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new IDealValidationException("cannot find Signature element");
            }
            if (nl.getLength() > 1) {
                throw new IDealValidationException("multiple signatures provided");
            }

            // Find KeyName element to check whether the signing fingerprint
            // matches (as a quick error detection check, this is not a security
            // check).
            Element signature = (Element) nl.item(0);
            NodeList keyInfoList = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
            if (keyInfoList.getLength() != 1) {
                throw new IDealValidationException("expected exactly 1 KeyInfo element");
            }
            Element keyInfo = (Element)keyInfoList.item(0);
            NodeList keyNameList = keyInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyName");
            if (keyNameList.getLength() != 1) {
                throw new IDealValidationException("expected exactly 1 KeyName element");
            }
            Element keyName = (Element)keyNameList.item(0);

            // Check whether the certificate fingerprint matches the signing
            // fingerprint.
            if (!keyName.getTextContent().equals(getFingerprint(cert))) {
                throw new IDealValidationException("invalid fingerprint in KeyName");
            }

            // Verify the signature!
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            PublicKey pk = cert.getPublicKey();
            DOMValidateContext validateContext = new DOMValidateContext(pk, signature);
            XMLSignature xmlSignature = factory.unmarshalXMLSignature(validateContext);
            if (!xmlSignature.validate(validateContext)) {
                throw new IDealValidationException("signature verification failed");
            }

            // Signature is valid. Don't do anything.
        } catch (CertificateEncodingException | NoSuchAlgorithmException | XMLSignatureException e) {
            throw new RuntimeException("unexpected crypto error");
        } catch (MarshalException e) {
            throw new IDealValidationException("failed to unmarshal signature");
        }
    }

    // Returns the fingerprint for this certificate, as expected by the iDeal
    // protocol.
    private String getFingerprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] digest = md.digest(cert.getEncoded());
        return DatatypeConverter.printHexBinary(digest);
    }

    // Output the request XML as a string.
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
