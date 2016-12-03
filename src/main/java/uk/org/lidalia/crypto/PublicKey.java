package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface PublicKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends java.security.PublicKey, Key<Public, Private, Pair> {

    boolean verifySignature(
            Bytes signature,
            HashAlgorithm hashAlgorithm,
            Bytes signedContents
    );

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verifySignature(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, String contents) {
        return verifySignature(signature, hashAlgorithm, contents, UTF_8);
    }

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, Bytes contents) {
        return verifySignature(Bytes.of(signature), hashAlgorithm, contents);
    }

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verifySignature(Bytes.of(signature), hashAlgorithm, contents);
    }

    default boolean verifySignature(Bytes signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verifySignature(signature, hashAlgorithm, Bytes.of(contents));
    }

    default boolean verifySignature(Bytes signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verifySignature(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verifySignature(Bytes signature, HashAlgorithm hashAlgorithm, String contents) {
        return verifySignature(signature, hashAlgorithm, contents, UTF_8);
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, Bytes contents) {
        return verifySignature(signature.decode(), hashAlgorithm, contents.array());
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, byte[] contents) {
        return verifySignature(signature.decode(), hashAlgorithm, contents);
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verifySignature(signature, hashAlgorithm, Bytes.of(contents, charset));
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents) {
        return verifySignature(signature, hashAlgorithm, contents, UTF_8);
    }

    Bytes encrypt(Bytes input);

    default Bytes encrypt(byte[] input) {
        return encrypt(Bytes.of(input));
    }

    default Bytes encrypt(String input, Charset charset) {
        return encrypt(Bytes.of(input, charset));
    }

    default Bytes encrypt(String input) {
        return encrypt(input, UTF_8);
    }
}
