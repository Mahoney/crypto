import org.junit.Test;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.rsa.RsaKey;
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey;
import uk.org.lidalia.crypto.rsa.RsaPublicKey;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.lang.Task;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;
import static uk.org.lidalia.test.ShouldThrow.shouldThrow;

public class RsaKeyTests {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private final Bytes unencrypted = Bytes.of("hello world");

    @Test
    public void createSerialiseAndRestorePrivateKey()
            throws InvalidKeySpecException {
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.generate();
        final byte[] privateKeyEncoded = privateKey.getEncoded();

        final RsaPrivateCrtKey restoredPrivateKey
                = RsaPrivateCrtKey.fromEncoded(privateKeyEncoded);

        assertThat(restoredPrivateKey, is(privateKey));
    }

    @Test
    public void createSerialiseAndRestorePublicKey()
            throws InvalidKeySpecException {
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().publicKey();
        final byte[] publicKeyEncoded = publicKey.getEncoded();

        final RsaPublicKey restoredPublicKey
                = RsaPublicKey.fromEncoded(publicKeyEncoded);

        assertThat(restoredPublicKey, is(publicKey));
    }

    @Test
    public void signAndVerifyData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey publicKey = privateKey.publicKey();
        final String dataToSign = "some random data";

        final Bytes signature
                = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        final boolean signatureValid = publicKey.verifySignature(
                signature,
                SHA256,
                dataToSign.getBytes(UTF_8)
        );
        assertTrue(signatureValid);
    }

    @Test
    public void signAndVerifyTamperedData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey publicKey = privateKey.publicKey();
        final String dataToSign = "some random data";

        final Bytes signature
                = privateKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        final boolean signatureValid = publicKey.verifySignature(
                signature,
                SHA256,
                "tampered data".getBytes(UTF_8)
        );
        assertFalse(signatureValid);
    }

    @Test
    public void signAndVerifyDifferentKey() {
        final String dataToSign = "some random data";
        final RsaPrivateCrtKey signingKey
                = RsaPrivateCrtKey.generate();
        final RsaPublicKey nonMatchingPublicKey
                = RsaPrivateCrtKey.generate().publicKey();

        final Bytes signature
                = signingKey.signatureFor(SHA256, dataToSign.getBytes(UTF_8));

        final boolean signatureValid = nonMatchingPublicKey.verifySignature(
                signature,
                SHA256,
                dataToSign.getBytes(UTF_8)
        );
        assertFalse(signatureValid);
    }

    @Test
    public void encryptAndDecryptDataAsymmetrically()
            throws DecryptionFailedException {
        final RsaPrivateCrtKey keyA = RsaPrivateCrtKey.generate();
        final RsaPublicKey keyB = keyA.publicKey();

        encryptAndDecryptDataAsymmetrically(keyA, keyB);
        encryptAndDecryptDataAsymmetrically(keyB, keyA);
    }

    private void encryptAndDecryptDataAsymmetrically(
            final RsaKey keyA,
            final RsaKey keyB) throws DecryptionFailedException {

        final Bytes encrypted = keyA.encrypt(unencrypted);
        assertThat(encrypted, is(not(unencrypted)));

        final Bytes decrypted = keyB.decrypt(encrypted);
        assertThat(decrypted, is(unencrypted));
    }

    @Test
    public void failToDecryptDataSymmetrically() {
        final RsaPrivateCrtKey keyA = RsaPrivateCrtKey.generate();
        final RsaPublicKey keyB = keyA.publicKey();

        failToDecryptDataSymmetrically(keyA);
        failToDecryptDataSymmetrically(keyB);
    }

    private void failToDecryptDataSymmetrically(final RsaKey key) {
        final Bytes encrypted = key.encrypt(unencrypted);
        final DecryptionFailedException exception
                = shouldThrow(DecryptionFailedException.class, new Task() {
            @Override
            public void perform() throws Exception {
                key.decrypt(encrypted);
            }
        });
        assertThat(exception.getMessage(), is("Unable to decrypt data"));
        assertThat(exception.getCause(), notNullValue());
    }
}
