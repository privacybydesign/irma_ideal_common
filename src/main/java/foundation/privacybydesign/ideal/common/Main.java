package foundation.privacybydesign.ideal.common;

import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Main {

    public static void main(String []args) throws KeyManagementException {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Configuration conf = new Configuration("1", "0");

        DirectoryRequest dr = new DirectoryRequest(conf);
        PrivateKey sk = conf.loadPrivateKey("build/resources/main/sk.der");
        X509Certificate cert = conf.loadCertificate("build/resources/main/cert.der");
        dr.sign(sk, cert);
        System.out.println(dr.toString());
    }
}
