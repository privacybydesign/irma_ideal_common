package foundation.privacybydesign.ideal.common;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Configuration {
    private String merchantId;
    private String merchantSubId;

    public Configuration(String merchantId, String merchantSubId) {
        // TODO: load configuration from a config file.
        this.merchantId = merchantId;
        this.merchantSubId = merchantSubId;
    }

    private byte[] getResource(String filename) throws IOException {
        return convertSteamToByteArray(getResourceStream(filename), 2048);
    }

    private InputStream getResourceStream(String filename) throws IOException {
        // TODO: load resources the proper way
        URL url = new File(filename).toURI().toURL();

        URLConnection urlConn = url.openConnection();
        urlConn.setUseCaches(false);
        return urlConn.getInputStream();
    }

    private byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
        byte[] buffer = new byte[size];
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        int line;
        while ((line = stream.read(buffer)) != -1) {
            os.write(buffer, 0, line);
        }
        stream.close();

        os.flush();
        os.close();
        return os.toByteArray();
    }

    public PrivateKey loadPrivateKey(String filename) throws KeyManagementException {
        try {
            return decodePrivateKey(getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    public X509Certificate loadCertificate(String filename) throws KeyManagementException {
        try {
            return decodeCertificate(getResourceStream(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    private PrivateKey decodePrivateKey(byte[] rawKey) throws KeyManagementException {
        try {
            if (rawKey == null || rawKey.length == 0)
                throw new KeyManagementException("Could not read private key");

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rawKey);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyManagementException(e);
        }
    }

    private X509Certificate decodeCertificate(InputStream rawKey) throws KeyManagementException {
        try {
            if (rawKey == null)
                throw new KeyManagementException("Could not read certificate");

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate)factory.generateCertificate(rawKey);
        } catch (CertificateException e) {
            throw new KeyManagementException(e);
        }
    }

    public String getMerchantId() { return merchantId; }

    public String getMerchantSubId() { return merchantSubId; }
}
