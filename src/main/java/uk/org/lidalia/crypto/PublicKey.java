package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.base64.Base64;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.Encoder;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public interface PublicKey<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.PublicKey, Key<Public, Private> {

    boolean verifySignature(
            byte[] signature,
            HashAlgorithm hashAlgorithm,
            byte[]... signedContents);

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verifySignature(signature, hashAlgorithm, contents.getBytes(charset));
    }

    default boolean verifySignature(byte[] signature, HashAlgorithm hashAlgorithm, String contents) {
        return verifySignature(signature, hashAlgorithm, contents, UTF_8);
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, byte[]... contents) {
        return verifySignature(signature.getDecoded(), hashAlgorithm, contents);
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return verifySignature(signature, hashAlgorithm, contents.getBytes(charset));
    }

    default boolean verifySignature(Encoded<?> signature, HashAlgorithm hashAlgorithm, String contents) {
        return verifySignature(signature, hashAlgorithm, contents, UTF_8);
    }

    byte[] encrypt(byte[] input);

    default byte[] encrypt(String input, Charset charset) {
        return encrypt(input.getBytes(charset));
    }

    default byte[] encrypt(String input) {
        return encrypt(input, UTF_8);
    }

    default <T extends Encoded<T>> T encryptAndEncode(byte[] input, Encoder<T> encoder) {
        return encoder.encode(encrypt(input));
    }

    default <T extends Encoded<T>> T encryptAndEncode(String input, Charset charset, Encoder<T> encoder) {
        return encryptAndEncode(input.getBytes(charset), encoder);
    }

    default <T extends Encoded<T>> T encryptAndEncode(String input, Encoder<T> encoder) {
        return encryptAndEncode(input, UTF_8, encoder);
    }

    default Base64 encryptAndEncode(byte[] input) {
        return encryptAndEncode(input, base64);
    }

    default Base64 encryptAndEncode(String input, Charset charset) {
        return encryptAndEncode(input.getBytes(charset));
    }

    default Base64 encryptAndEncode(String input) {
        return encryptAndEncode(input, UTF_8);
    }
}
