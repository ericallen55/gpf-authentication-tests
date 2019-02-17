package digital.gartner.common;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AuthenticationTest {

    private Authentication authentication = new Authentication();

    //Things that also could be tested if I knew the business requirements.
    //format of the variables, at least timestamp should have some standard format we should test the string for and handle the error.
    //The parameters should be first caught in the controller, these test still should be run in case somehow bad data gets through.

    @Test
    public void test() throws Exception {
        assertTrue(true);
    }

    @Test void generatePasswordToken(){
        String response = authentication.generatePasswordToken("url", "username", "password", "nonce");
        assertEquals(response, "413360fd7e8a9b122b8524e6c6d04fcc5673bdbb3b6778183f1d756a8bd10fbe");
    }

    //Should throw exception
    @Test void generatePasswordTokenNullUrl(){
        String response = authentication.generatePasswordToken(null, "username", "password", "nonce");
        assertEquals(response, "e16fa6da31f99dc1f2ccc25fc250bd370a2d31d3e30bf4c5d93fcee4d6eea8a0");
    }

    //Should throw exception
    @Test void generatePasswordTokenNullUsername(){
        String response = authentication.generatePasswordToken("url", null, "password", "nonce");
        assertEquals(response, "6df3f979d584a19f08d43856d767a13fa7856176bdde4044ad7cbc2dabc765cb");
    }

    //Should throw exception
    @Test void generatePasswordTokenNullPassword(){
        String response = authentication.generatePasswordToken("url", "username", null, "nonce");
        assertEquals(response, "f6d7d5c67e819fe545e116707955fbd610ea5825bff7efc433b72582789d7442");
    }

    //Should throw exception
    @Test void generatePasswordTokenNullNonce(){
        String response = authentication.generatePasswordToken("url", "username", "password", null);
        assertEquals(response, "d07942d042018b2074175e33aa95dbdf32cdb480f591dfb14c5882748dbd9282");
    }

    //Should throw exception
    @Test void generatePasswordTokenEmptyUrl(){
        String response = authentication.generatePasswordToken("", "username", "password", "nonce");
        assertEquals(response, "29fb51dea4d7f06db15f89bc6e4ded49451de59c9b28adefe09712fb8beb5d6d");
    }

    //Should throw exception
    @Test void generatePasswordTokenEmptyUsername(){
        String response = authentication.generatePasswordToken("url", "", "password", "nonce");
        assertEquals(response, "1a571fe70a88a99dd224b0fe78135b3dc44c83dee043261efd9592803d19b5d9");
    }

    //Should throw exception
    @Test void generatePasswordTokenEmptyPassword(){
        String response = authentication.generatePasswordToken("url", "username", "", "nonce");
        assertEquals(response, "c2e7ba524df6ec823bd42dd6eedc6967805e58d7236f0170edab48d9f7bdb10f");
    }

    //Should throw exception
    @Test void generatePasswordTokenEmptyNonce(){
        String response = authentication.generatePasswordToken("url", "username", "password", "");
        assertEquals(response, "85a1aa712ab4e3d10ca6af97507649ee38dea91ce03823df979ff4f038ac9948");
    }

    @Test
    public void generatePasswordHash(){
        String response = authentication.generatePasswordHash("username", "password");
        assertEquals(response, "bc842c31a9e54efe320d30d948be61291f3ceee4766e36ab25fa65243cd76e0e");
    }

    @Test
    //Should throw exception
    public void generatePasswordHashNullUsername(){
        String response = authentication.generatePasswordHash(null, "password");
        assertEquals(response, "96fa040c5fc56684d750ab63fe0100c3d602acac68b98a53afaf445aa880fa4e");
    }

    @Test
    //Should throw exception
    public void generatePasswordHashEmptyUsername(){
        String response = authentication.generatePasswordHash("", "password");
        assertEquals(response, "cae8f9d6c842c419d7bf279a4a73a9077632ffb85bdde51ef6b0bf183345739a");
    }

    @Test
    //Should throw exception
    public void generatePasswordHashNullPassword(){
        String response = authentication.generatePasswordHash("username", null);
        assertEquals(response, "18ed6688b063edb300b3d69f99021ef37f82b9f1ba936efae02a0d9e21923acc");
    }

    @Test
    //Should throw exception
    public void generatePasswordHashEmptyPassword(){
        String response = authentication.generatePasswordHash("username", "");
        assertEquals(response, "d35f07f0e217ae4a78817f18569b1bad47f380e57bd241ee09ad4392fd401a6a");
    }

    @Test
    public void generateAccessToken(){
        String response = authentication.generateAccessToken("publicId", "secretKey", "timestamp");
        assertEquals(response, "ad0572ccca247f5702eef6466b81a0bc62de1eb80ad50b1412ccad479fc89fd8");
    }

    @Test
    public void generateAccessTokenNullPublicId(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateAccessToken(null, "secretKey", "timestamp");
        });
        assertEquals(throwable.getMessage(), "No publicId was provided for generating the AccessToken");
    }

    @Test
    //Should throw exception
    public void generateAccessTokenEmptyPublicId(){
        String response = authentication.generateAccessToken("", "secretKey", "timestamp");
        assertEquals(response, "1821994364d80ec8f50b191845684a21212205d1df59c714d8c22d6325f32b7f");
    }

    @Test
    public void generateAccessTokenNullSecretKey(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateAccessToken("publicId", null, "timestamp");
        });
        assertEquals(throwable.getMessage(), "No secretKey was provided for generating the AccessToken");
    }

    @Test
    //not testing the message returned since we aren't generating it.  We should throw our own error not relay on an underlying base method hmacSha256Hex.
    public void generateAccessTokenEmptySecretKey(){
        assertThrows(IllegalArgumentException.class, () -> {
            authentication.generateAccessToken("publicId", "", "timestamp");
        });
    }

    @Test
    public void generateAccessTokenNullTimestamp(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateAccessToken("publicId", "secretKey", null);
        });
        assertEquals(throwable.getMessage(), "No timestamp was provided for generating the AccessToken");
    }

    @Test
    //Should throw exception
    public void generateAccessTokenEmptyTimestamp() {
        String response = authentication.generateAccessToken("publicId", "secretKey", "");
        assertEquals(response, "9127fe256c4b153f35c665b8ed06665f83eaa5c0649b0de8d86702e1233b92e5");
    }

    @Test
    public void generateSignature(){
        String response = authentication.generateSignature("payload", "publicKey", "nonce", "timestamp", "accessToken");
        assertEquals(response, "c5d670f149399cfb13dba4a3f288b1edd55841b0db04c1642870e4c2c292acdf");
    }

    @Test
    public void generateSignatureNullPayload(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateSignature(null, "publicKey", "nonce", "timestamp", "accessToken");
        });
        assertEquals(throwable.getMessage(), "No payload was provided for generating signature.");
    }

    @Test
    public void generateSignatureNullPublicKey(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateSignature("payload", null, "nonce", "timestamp", "accessToken");
        });
        assertEquals(throwable.getMessage(), "No publicKey was provided for generating signature.");
    }

    @Test
    public void generateSignatureNullNonce(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateSignature("payload", "publicKey", null, "timestamp", "accessToken");
        });
        assertEquals(throwable.getMessage(), "No nonce was provided for generating signature.");
    }

    @Test
    public void generateSignatureNullTimeStamp(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateSignature("payload", "publicKey", "nonce", null, "accessToken");
        });
        assertEquals(throwable.getMessage(), "No timestamp was provided for generating signature.");
    }

    @Test
    public void generateSignatureNullAccessToken(){
        Throwable throwable = expectThrows(RuntimeException.class, () -> {
            authentication.generateSignature("payload", "publicKey", "nonce", "timestamp", null);
        });
        assertEquals(throwable.getMessage(), "No accessToken was provided for generating signature.");
    }

    @Test
    public void generateSignatureEmptyPayload(){
        String response = authentication.generateSignature("", "publicKey", "nonce", "timestamp", "accessToken");
        assertEquals(response, "172f3ae208c38871ce4944c78287c4c984447ec2a54b3574b03e1faf73c9b0f2");
    }

    @Test
    //Should throw exception
    public void generateSignatureEmptyPublicKey(){
        String response = authentication.generateSignature("payload", "", "nonce", "timestamp", "accessToken");
        assertEquals(response, "8618f653be18b46a792adb0ca638f0c4561822745c30e8dc9b3a905dcdb02ff6");
    }

    @Test
    //Should throw exception
    public void generateSignatureEmptyNonce(){
        String response = authentication.generateSignature("payload", "publicKey", "", "timestamp", "accessToken");
        assertEquals(response, "2d2dc7d06e8b8f1cf0a74a627457345104ef9ffea3512cf74667c80865d440bb");
    }

    @Test
    //Should throw exception or generate a timestamp
    public void generateSignatureEmptyTimestamp(){
        String response = authentication.generateSignature("payload", "publicKey", "nonce", "", "accessToken");
        assertEquals(response, "da77a337ff77766d6057c5bb348bce4f933ed282c97872e0f5031e6595344b59");
    }

    @Test
    //not testing the message returned since we aren't generating it.  We should throw our own error not relay on an underlying base method hmacSha256Hex.
    public void generateSignatureEmptyAccessToken(){
        assertThrows(IllegalArgumentException.class, () -> {
            authentication.generateSignature("payload", "publicKey", "nonce", "timestamp", "");
        });
    }
}