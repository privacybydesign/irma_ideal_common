package foundation.privacybydesign.ideal.common;

import java.io.IOException;
import java.io.InputStream;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.xml.sax.SAXException;

public class IDealClient {
    private String baseURL;
    private HttpClient httpClient;

    public IDealClient(String baseURL) {
        this.baseURL = baseURL;
    }

    private HttpClient getHttpClient() {
        if (httpClient == null) {
            httpClient = HttpClients.createDefault();
        }
        return httpClient;
    }

    public IDealResponse doRequest(IDealMessage message) throws IOException {
        HttpPost httpPost = new HttpPost(baseURL);
        httpPost.setHeader("Content-Type", "text/xml; charset=\"utf-8\"");
        httpPost.setHeader("Version", "1.0");
        httpPost.setHeader("Encoding", "UTF-8");
        httpPost.setEntity(new StringEntity(message.toString(), "utf-8"));

        HttpResponse response = getHttpClient().execute(httpPost);
        if (response.getStatusLine().getStatusCode() != 200) {
            throw new IOException("unexpected HTTP status: " + response.getStatusLine().toString());
        }
        String responseType = ContentType.getOrDefault(response.getEntity()).getMimeType();
        if (!responseType.equals("text/xml")) {
            throw new IOException("unexpected HTTP media type, expected text/xml, got: " + responseType);
        }

        InputStream responseStream = response.getEntity().getContent();
        try {
            return IDealResponse.get(responseStream);
        } catch (SAXException e) {
            // This is stretching the definition of IO a bit... But I'll use
            // IOException as an XML error is on a layer below the iDeal
            // protocol.
            throw new IOException("failed to parse XML in iDeal response");
        }
    }
}
