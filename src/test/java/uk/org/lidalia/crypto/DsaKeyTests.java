package uk.org.lidalia.crypto;

import org.junit.Test;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.dsa.DsaKeyPair;
import uk.org.lidalia.crypto.dsa.DsaPrivateKey;
import uk.org.lidalia.crypto.dsa.DsaPublicKey;
import uk.org.lidalia.encoding.Bytes;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;
import static uk.org.lidalia.crypto.dsa.Dsa.DSA;

public class DsaKeyTests {

    @Test
    public void createSerialiseAndRestorePrivateKey()
            throws InvalidKeySpecException {
        final DsaPrivateKey privateKey
                = DSA.generateKeyPair().privateKey();
        final byte[] privateKeyEncoded = privateKey.getEncoded();

        final DsaPrivateKey restoredPrivateKey
                = DsaPrivateKey.fromEncoded(privateKeyEncoded);

        assertThat(restoredPrivateKey, is(privateKey));
    }

    @Test
    public void createSerialiseAndRestorePublicKey()
            throws InvalidKeySpecException {
        final DsaPublicKey publicKey = DSA.generateKeyPair().publicKey();
        final byte[] publicKeyEncoded = publicKey.getEncoded();

        final DsaPublicKey restoredPublicKey
                = DsaPublicKey.fromEncoded(publicKeyEncoded);

        assertThat(restoredPublicKey, is(publicKey));
    }

    @Test
    public void signAndVerifyData() {
        final DsaKeyPair keyPair = DSA.generateKeyPair();
        final DsaPrivateKey privateKey = keyPair.privateKey();
        final DsaPublicKey publicKey = keyPair.publicKey();
        final String dataToSign = "some random data";

        final Signature signature = privateKey.sign(dataToSign);

        assertTrue(publicKey.verify(signature, dataToSign));
    }

    @Test
    public void signAndVerifyTamperedData() {
        final DsaKeyPair keyPair = DSA.generateKeyPair();
        final DsaPrivateKey privateKey = keyPair.privateKey();
        final DsaPublicKey publicKey = keyPair.publicKey();
        final String dataToSign = "some random data";

        final Signature signature = privateKey.sign(dataToSign);

        assertFalse(publicKey.verify(signature, "tampered data"));
    }

    @Test
    public void signAndVerifyDifferentKey() {
        final String dataToSign = "some random data";
        final DsaPrivateKey signingKey
                = DSA.generateKeyPair().privateKey();
        final DsaPublicKey nonMatchingPublicKey
                = DSA.generateKeyPair().publicKey();

        final Signature signature = signingKey.sign(dataToSign);

        final boolean signatureValid = nonMatchingPublicKey.verify(signature, dataToSign);
        assertFalse(signatureValid);
    }
}
