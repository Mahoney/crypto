package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.hash.HashAlgorithm;
import uk.org.lidalia.lang.Bytes;

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
            final java.security.Signature verifier = signatureFor(signature.algorithm());
            verifier.initVerify(this);
            verifier.update(signedContents.array());
            return verifier.verify(signature.bytes().array());
        } catch (final Exception e) {
            throw new IllegalStateException(
                "Failed to verify "+signature+" using key "+this+" against contents "+signedContents,
                e
            );
        }
    }

    default boolean verify(Signature signature, byte[] signedContents) {
        return verify(signature, Bytes.of(signedContents));
    }

    default boolean verify(Signature signature, EncodedBytes signedContents) {
        return verify(signature, signedContents.decode());
    }

    default boolean verify(Signature signature, String signedContents, Charset charset) {
        return verify(signature, Bytes.of(signedContents, charset));
    }

    default boolean verify(Signature signature, String signedContents) {
        return verify(signature, signedContents, UTF_8);
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, Bytes signedContents) {
        return verify(Signature.of(signature, hashAlgorithm), signedContents);
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, byte[] signedContents) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents));
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, EncodedBytes signedContents) {
        return verify(signature, hashAlgorithm, signedContents.decode());
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, String signedContents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents, charset));
    }

    default boolean verify(Bytes signature, HashAlgorithm hashAlgorithm, String signedContents) {
        return verify(signature, hashAlgorithm, signedContents, UTF_8);
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, Bytes signedContents) {
        return verify(Bytes.of(signature), hashAlgorithm, signedContents);
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, byte[] signedContents) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents));
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, EncodedBytes signedContents) {
        return verify(signature, hashAlgorithm, signedContents.decode());
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, String signedContents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents, charset));
    }

    default boolean verify(byte[] signature, HashAlgorithm hashAlgorithm, String signedContents) {
        return verify(signature, hashAlgorithm, signedContents, UTF_8);
    }

    default boolean verify(EncodedBytes signature, HashAlgorithm hashAlgorithm, Bytes signedContents) {
        return verify(signature.decode(), hashAlgorithm, signedContents);
    }

    default boolean verify(EncodedBytes signature, HashAlgorithm hashAlgorithm, byte[] signedContents) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents));
    }

    default boolean verify(EncodedBytes signature, HashAlgorithm hashAlgorithm, EncodedBytes signedContents) {
        return verify(signature, hashAlgorithm, signedContents.decode());
    }

    default boolean verify(EncodedBytes signature, HashAlgorithm hashAlgorithm, String signedContents, Charset charset) {
        return verify(signature, hashAlgorithm, Bytes.of(signedContents, charset));
    }

    default boolean verify(EncodedBytes signature, HashAlgorithm hashAlgorithm, String signedContents) {
        return verify(signature, hashAlgorithm, signedContents, UTF_8);
    }
}
