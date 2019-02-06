package digital.gartner.common;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;

public class Authentication {
    public String generatePasswordToken(String url, String username, String password, String nonce) {
        String passwordHash = generatePasswordHash(username, password);
        String payload = url + passwordHash + username + nonce;
        return HmacUtils.hmacSha256Hex(passwordHash, payload);
    }

    public String generatePasswordHash(String username, String password ) {
        String toReturn = username + ":" + password;
        return DigestUtils.sha256Hex(toReturn);
    }

    public String generateAccessToken(String publicId, String secretKey, String timestamp) {
        if (timestamp == null) {
            throw new RuntimeException("No timestamp was provided for generating the AccessToken");
        }
        if (publicId == null) {
            throw new RuntimeException("No publicId was provided for generating the AccessToken");
        }
        if (secretKey == null) {
            throw new RuntimeException("No secretKey was provided for generating the AccessToken");
        }

        StringBuilder buf = new StringBuilder();

        buf.append(publicId)
                .append(secretKey)
                .append(timestamp);

        return HmacUtils.hmacSha256Hex(secretKey, buf.toString());
    }

    public String generateSignature(String payload, String publicKey, String nonce, String timestamp, String accessToken) {
        if (payload == null) {
            throw new RuntimeException("No payload was provided for generating signature.");
        }
        if (publicKey == null) {
            throw new RuntimeException("No publicKey was provided for generating signature.");
        }
        if (nonce == null) {
            throw new RuntimeException("No nonce was provided for generating signature.");
        }
        if (timestamp == null) {
            throw new RuntimeException("No timestamp was provided for generating signature.");
        }
        if (accessToken == null) {
            throw new RuntimeException("No accessToken was provided for generating signature.");
        }

        StringBuilder buf = new StringBuilder();
        buf.append(payload)
                .append(timestamp)
                .append(publicKey)
                .append(nonce);
        return HmacUtils.hmacSha256Hex(accessToken, buf.toString());
    }
}
