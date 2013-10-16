import org.junit.Test;
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey;
import uk.org.lidalia.crypto.rsa.RsaPublicKey;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;

public class RsaKeyTests {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    @Test
    public void createSerialiseAndRestorePrivateKey() throws InvalidKeySpecException {
        RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        byte[] privateKeyEncoded = privateKey.getEncoded();

        RsaPrivateCrtKey restoredPrivateKey = RsaPrivateCrtKey.fromEncoded(privateKeyEncoded);

        assertThat(restoredPrivateKey, is(privateKey));
    }

    @Test
    public void createSerialiseAndRestorePublicKey() throws InvalidKeySpecException {
        RsaPublicKey publicKey = RsaPrivateCrtKey.generate().getPublicKey();
        byte[] publicKeyEncoded = publicKey.getEncoded();

        RsaPublicKey restoredPublicKey = RsaPublicKey.fromEncoded(publicKeyEncoded);

        assertThat(restoredPublicKey, is(publicKey));
    }

    @Test
    public void signAndVerifyData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final String dataToSign = "some random data";

        final byte[] signature = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertTrue(privateKey.getPublicKey().verifySignature(signature, SHA256, dataToSign.getBytes(UTF_8)));
    }

    @Test
    public void signAndVerifyTamperedData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final String dataToSign = "some random data";

        final byte[] signature = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertFalse(privateKey.getPublicKey().verifySignature(signature, SHA256, "tampered data".getBytes(UTF_8)));
    }

    @Test
    public void signAndVerifyDifferentKey() {
        final String dataToSign = "some random data";
        final RsaPrivateCrtKey signingKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey nonMatchingPublicKey = RsaPrivateCrtKey.generate().getPublicKey();

        final byte[] signature = signingKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertFalse(nonMatchingPublicKey.verifySignature(signature, SHA256, dataToSign.getBytes(UTF_8)));
    }

}
