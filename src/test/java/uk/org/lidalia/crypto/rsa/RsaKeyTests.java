package uk.org.lidalia.crypto.rsa;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.EncryptedBytes;
import uk.org.lidalia.crypto.Signature;
import uk.org.lidalia.encoding.Bytes;

import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;

public class RsaKeyTests {

    private final String unencrypted = RandomStringUtils.random(60);

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

        final Signature signature = privateKey.sign(dataToSign);

        assertTrue(publicKey.verify(signature, dataToSign));
    }

    @Test
    public void signAndVerifyTamperedData() {
        final RsaPrivateCrtKey privateKey = RsaPrivateCrtKey.generate();
        final RsaPublicKey publicKey = privateKey.publicKey();
        final String dataToSign = "some random data";

        final Signature signature = privateKey.sign(dataToSign);

        assertFalse(publicKey.verify(signature, "tampered data"));
    }

    @Test
    public void signAndVerifyDifferentKey() {
        final String dataToSign = "some random data";
        final RsaPrivateCrtKey signingKey
                = RsaPrivateCrtKey.generate();
        final RsaPublicKey nonMatchingPublicKey
                = RsaPrivateCrtKey.generate().publicKey();

        final Signature signature = signingKey.sign(dataToSign);

        assertFalse(nonMatchingPublicKey.verify(signature, dataToSign));
    }

    @Test
    public void encryptAndDecryptDataAsymmetrically()
            throws DecryptionFailedException {
        final RsaPrivateCrtKey keyA = RsaPrivateCrtKey.generate();
        final RsaPublicKey keyB = keyA.publicKey();

        final EncryptedBytes encrypted = keyB.encrypt(unencrypted);
        assertThat(encrypted, is(not(unencrypted)));

        final Bytes decrypted = keyA.decrypt(encrypted);
        assertThat(decrypted.string(), is(unencrypted));
    }
}
