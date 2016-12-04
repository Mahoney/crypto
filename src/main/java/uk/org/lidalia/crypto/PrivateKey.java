package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface PrivateKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends
        java.security.PrivateKey,
        AsymmetricKey<Public, Private, Pair>,
        DecryptKey<Public, Private> {

    Bytes signatureFor(
        HashAlgorithm hashAlgorithm,
        Bytes contents
    );

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, byte[] contents) {
        return signatureFor(hashAlgorithm, Bytes.of(contents));
    }

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return signatureFor(hashAlgorithm, Bytes.of(contents, charset));
    }

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, String contents) {
        return signatureFor(hashAlgorithm, contents, UTF_8);
    }
}
