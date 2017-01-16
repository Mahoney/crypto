package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface PublicKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends
        java.security.PublicKey,
        AsymmetricKey<Public, Private, Pair> {

    default boolean verify(Signature signature, Bytes signedContents) {
        try {
            final java.security.Signature verifier = Signature.signatureFor(signature.algorithm(), this);
            verifier.initVerify(this);
            verifier.update(signedContents.array());
            return verifier.verify(signature.bytes().array());
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Verifying a string with an RSA private key should always work. " +
                            "Using key="+ signature, e);
        }
    }

    default boolean verify(Signature signature, byte[] signedContents) {
        return verify(signature, Bytes.of(signedContents));
    }

    default boolean verify(Signature signature, Encoded<?> signedContents) {
        return verify(signature, signedContents.decode());
    }

    default boolean verify(Signature signature, String signedContents, Charset charset) {
        return verify(signature, Bytes.of(signedContents, charset));
    }

    default boolean verify(Signature signature, String signedContents) {
        return verify(signature, signedContents, UTF_8);
    }

    default boolean verify(
            Bytes signature,
            HashAlgorithm hashAlgorithm,
            Bytes signedContents
    ) {
        return verify(Signature.of(signature, hashAlgorithm), signedContents);
    };

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, String contents) {
        return verify(signature, hashAlgorithm, contents, UTF_8);
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, Bytes contents) {
        return verify(Bytes.of(signature), hashAlgorithm, contents);
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verify(Bytes.of(signature), hashAlgorithm, contents);
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verify(signature, hashAlgorithm, Bytes.of(contents));
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, String contents) {
        return verify(signature, hashAlgorithm, contents, UTF_8);
    }

    default boolean verify(Encoded<?> signature, HashAlgorithm hashAlgorithm, Bytes contents) {
        return verify(signature.decode(), hashAlgorithm, contents.array());
    }

    default boolean verify(Encoded<?> signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verify(signature.decode(), hashAlgorithm, contents);
    }

    default boolean verify(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verify(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents) {
        return verify(signature, hashAlgorithm, contents, UTF_8);
    }
}
