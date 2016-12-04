import org.junit.Test;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey;
import uk.org.lidalia.crypto.rsa.RsaPublicKey;
import uk.org.lidalia.encoding.Bytes;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;

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

        final Bytes encrypted = keyB.encrypt(unencrypted);
        assertThat(encrypted, is(not(unencrypted)));

        final Bytes decrypted = keyA.decrypt(encrypted);
        assertThat(decrypted, is(unencrypted));
    }
}
