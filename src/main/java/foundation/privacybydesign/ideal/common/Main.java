package foundation.privacybydesign.ideal.common;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Main {

    public static void main(String []args)
            throws KeyManagementException, IOException {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String merchantId = "1";
        String baseURL = "https://idealtest.secure-ing.com/ideal/iDeal";

        Configuration conf = new Configuration(merchantId, "0");
        PrivateKey sk = conf.loadPrivateKey("src/main/resources/ideal-sk.der");
        X509Certificate cert = conf.loadCertificate("src/main/resources/ideal-cert.der");
        X509Certificate bankCert = conf.loadCertificate("src/main/resources/cert.ing.der");

        IDealDirectoryRequest dr = IDealDirectoryRequest.create(conf);
        dr.sign(sk, cert);
        try {
            // sanity checking
            dr.validate(cert);
        } catch (IDealValidationException e){
            throw new RuntimeException("failed to validate outgoing message");
        }
        System.out.println("Created directory request:");
        System.out.println(dr.toString());

        IDealClient client = new IDealClient(baseURL);
        IDealResponse response = client.doRequest(dr);
        System.out.println("Got response:");
        System.out.println(response.toString());

        // TODO: validate (needs certificate)
        try {
            response.validate(bankCert);
            System.out.println("validated response!");
        } catch (IDealValidationException e) {
            System.out.println("could not validate response: " + e.getMessage());
        }

        if (response instanceof IDealErrorResponses) {
            IDealErrorResponses errorResponses = (IDealErrorResponses)response;
            System.out.println("Error code:       " + errorResponses.getErrorCode());
            System.out.println("Error message:    " + errorResponses.getErrorMessage());
            System.out.println("Error detail:     " + errorResponses.getErrorDetail());
            System.out.println("Suggested action: " + errorResponses.getSuggestedAction());
            System.out.println("Consumer message: " + errorResponses.getConsumerMessage());
        }
    }
}
