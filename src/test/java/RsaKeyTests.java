import org.junit.Test;
import uk.org.lidalia.crypto.rsa.RsaKey;
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey;
import uk.org.lidalia.crypto.rsa.RsaPublicKey;
import uk.org.lidalia.lang.Task;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;
import static uk.org.lidalia.test.ShouldThrow.shouldThrow;

public class RsaKeyTests {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private final byte[] unencrypted = "hello world".getBytes(UTF_8);

    @Test
    public void createSerialiseAndRestorePrivateKey() throws InvalidKeySpecException {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final byte[] privateKeyEncoded = privateKey.getEncoded();

        final RsaPrivateCrtKey restoredPrivateKey = RsaPrivateCrtKey.fromEncoded(privateKeyEncoded);

        assertThat(restoredPrivateKey, is(privateKey));
    }

    @Test
    public void createSerialiseAndRestorePublicKey() throws InvalidKeySpecException {
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().getPublicKey();
        final byte[] publicKeyEncoded = publicKey.getEncoded();

        final RsaPublicKey restoredPublicKey = RsaPublicKey.fromEncoded(publicKeyEncoded);

        assertThat(restoredPublicKey, is(publicKey));
    }

    @Test
    public void signAndVerifyData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey publicKey = privateKey.getPublicKey();
        final String dataToSign = "some random data";

        final byte[] signature = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertTrue(publicKey.verifySignature(signature, SHA256, dataToSign.getBytes(UTF_8)));
    }

    @Test
    public void signAndVerifyTamperedData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey publicKey = privateKey.getPublicKey();
        final String dataToSign = "some random data";

        final byte[] signature = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertFalse(publicKey.verifySignature(signature, SHA256, "tampered data".getBytes(UTF_8)));
    }

    @Test
    public void signAndVerifyDifferentKey() {
        final String dataToSign = "some random data";
        final RsaPrivateCrtKey signingKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey nonMatchingPublicKey = RsaPrivateCrtKey.generate().getPublicKey();

        final byte[] signature = signingKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        assertFalse(nonMatchingPublicKey.verifySignature(signature, SHA256, dataToSign.getBytes(UTF_8)));
    }

    @Test
    public void encryptAndDecryptDataAsymmetrically() {
        RsaPrivateCrtKey keyA = RsaPrivateCrtKey.generate();
        RsaPublicKey keyB = keyA.getPublicKey();

        encryptAndDecryptDataAsymmetrically(keyA, keyB);
        encryptAndDecryptDataAsymmetrically(keyB, keyA);
    }

    private void encryptAndDecryptDataAsymmetrically(RsaKey keyA, RsaKey keyB) {

        byte[] encrypted = keyA.encrypt(unencrypted);
        byte[] decrypted = keyB.decrypt(encrypted);

        assertThat(decrypted, is(unencrypted));
        assertThat(encrypted, is(not(unencrypted)));
    }

    @Test
    public void failToDecryptDataSymmetrically() {
        RsaPrivateCrtKey keyA = RsaPrivateCrtKey.generate();
        RsaPublicKey keyB = keyA.getPublicKey();

        failToDecryptDataSymmetrically(keyA);
        failToDecryptDataSymmetrically(keyB);
    }

    private void failToDecryptDataSymmetrically(final RsaKey key) {
        final byte[] encrypted = key.encrypt(unencrypted);
        shouldThrow(IllegalStateException.class, new Task() {
            @Override
            public void perform() throws Exception {
                key.decrypt(encrypted);
            }
        });
    }
}
