package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.hash.HashAlgorithm;
import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.hash.HashAlgorithm.SHA256;

public interface PrivateKey<A extends AsymmetricCryptoAlgorithm<A>> extends
        java.security.PrivateKey,
        AsymmetricKey<A> {

    default Signature<A> sign(Bytes contents, HashAlgorithm hashAlgorithm) {

        try {
            final java.security.Signature signer = signatureFor(hashAlgorithm);
            signer.initSign(this);
            signer.update(contents.array());
            return Signature.of(Bytes.of(signer.sign()), hashAlgorithm, algorithm());
        } catch (final Exception e) {
            throw new IllegalArgumentException("Key "+this+", algorithm "+hashAlgorithm+" could not sign "+contents.string(), e);
        }
    }

    default Signature<A> sign(byte[] contents, HashAlgorithm hashAlgorithm) {
        return sign(Bytes.of(contents), hashAlgorithm);
    }

    default Signature<A> sign(EncodedBytes contents, HashAlgorithm hashAlgorithm) {
        return sign(contents.decode(), hashAlgorithm);
    }

    default Signature<A> sign(String contents, Charset charset, HashAlgorithm hashAlgorithm) {
        return sign(Bytes.of(contents, charset), hashAlgorithm);
    }
    default Signature<A> sign(String contents, HashAlgorithm hashAlgorithm) {
        return sign(contents, UTF_8, hashAlgorithm);
    }

    default Signature<A> sign(Bytes contents) {
        return sign(contents, SHA256);
    }

    default Signature<A> sign(byte[] contents) {
        return sign(contents, SHA256);
    }

    default Signature<A> sign(EncodedBytes contents) {
        return sign(contents, SHA256);
    }

    default Signature<A> sign(String contents, Charset charset) {
        return sign(contents, charset, SHA256);
    }

    default Signature<A> sign(String contents) {
        return sign(contents, SHA256);
    }
}
