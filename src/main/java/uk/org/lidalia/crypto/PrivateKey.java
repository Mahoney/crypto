package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256;

public interface PrivateKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends
        java.security.PrivateKey,
        AsymmetricKey<Public, Private, Pair> {

    default Signature sign(Bytes contents, HashAlgorithm hashAlgorithm) {

        try {
            final java.security.Signature signer = signatureFor(hashAlgorithm);
            signer.initSign(this);
            signer.update(contents.array());
            return Signature.of(Bytes.of(signer.sign()), hashAlgorithm);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Key "+this+", algorithm "+hashAlgorithm+" could not sign "+contents.string(), e);
        }
    }

    default Signature sign(byte[] contents, HashAlgorithm hashAlgorithm) {
        return sign(Bytes.of(contents), hashAlgorithm);
    }

    default Signature sign(EncodedBytes contents, HashAlgorithm hashAlgorithm) {
        return sign(contents.decode(), hashAlgorithm);
    }

    default Signature sign(String contents, Charset charset, HashAlgorithm hashAlgorithm) {
        return sign(Bytes.of(contents, charset), hashAlgorithm);
    }
    default Signature sign(String contents, HashAlgorithm hashAlgorithm) {
        return sign(contents, UTF_8, hashAlgorithm);
    }

    default Signature sign(Bytes contents) {
        return sign(contents, SHA256);
    }

    default Signature sign(byte[] contents) {
        return sign(contents, SHA256);
    }

    default Signature sign(EncodedBytes contents) {
        return sign(contents, SHA256);
    }

    default Signature sign(String contents, Charset charset) {
        return sign(contents, charset, SHA256);
    }

    default Signature sign(String contents) {
        return sign(contents, SHA256);
    }
}
