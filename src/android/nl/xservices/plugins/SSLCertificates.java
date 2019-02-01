package nl.xservices.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import javax.net.ssl.HttpsURLConnection;
import javax.security.cert.CertificateException;
import java.io.IOException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.ArrayList;
import java.lang.String;
import java.lang.Long;
import java.math.BigInteger;


public class SSLCertificates extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  private static final String LOG_TAG = "SSLCertificates";

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            final String serverURL = args.getString(0);
            final JSONArray allowedFingerprints = args.getJSONArray(2);
            List<String> fingerprints = getFingerprints(serverURL);
            JSONArray data = getFingerprintsJsonData(serverURL);
            callbackContext.success(data);
            return;
          } catch (Exception e) {
            callbackContext.error("CONNECTION_FAILED. Details: " + e.getMessage());
          }
        }
      });
      return true;
    } else {
      callbackContext.error("sslCertificates." + action + " is not a supported function. Did you mean '" + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }

  private static JSONArray getFingerprintsJsonData(String httpsURL) throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
    final HttpsURLConnection con = (HttpsURLConnection) new URL(httpsURL).openConnection();
    con.setConnectTimeout(5000);
    con.connect();
    JSONArray jsonArray = new JSONArray();
    for (int i = 0; i < con.getServerCertificates().length; i++) {
      final Certificate cert = con.getServerCertificates()[i];

      // LOG.e(LOG_TAG, cert.toString());
      final MessageDigest md = MessageDigest.getInstance("SHA256");
      md.update(cert.getEncoded());
      String fingerprint = dumpHex(md.digest());

      JSONObject jsonObject = new JSONObject();
      try {
        jsonObject.put("index", i);
        jsonObject.put("fingerprint", fingerprint);

        if (cert instanceof X509Certificate) {
          X509Certificate x = (X509Certificate ) cert;
          // LOG.e(LOG_TAG, "Serial number: "+ x.getSerialNumber());
          String serialNumber = (new BigInteger(x.getSerialNumber().toString(), 10)).toString(16);
          // LOG.e(LOG_TAG, "Serial number (hex): "+ serialNumber);
          jsonObject.put("serialNumber", serialNumber);
        }
      } catch (JSONException e) {
      }

      jsonArray.put(jsonObject);
    }

    return jsonArray;
  }

  private static String dumpHex(byte[] data) {
    final int n = data.length;
    final StringBuilder sb = new StringBuilder(n * 3 - 1);
    for (int i = 0; i < n; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
      sb.append(HEX_CHARS[data[i] & 0x0F]);
    }
    return sb.toString();
  }
}
