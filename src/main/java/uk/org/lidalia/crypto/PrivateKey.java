package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.base64.Base64;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.Encoder;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public interface PrivateKey<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.PrivateKey, Key<Public, Private> {

    byte[] signatureFor(
        HashAlgorithm hashAlgorithm,
        byte[]... contents);

    default byte[] signatureFor(HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return signatureFor(hashAlgorithm, contents.getBytes(charset));
    }

    default byte[] signatureFor(HashAlgorithm hashAlgorithm, String contents) {
        return signatureFor(hashAlgorithm, contents, UTF_8);
    }

    default <T extends Encoded<T>> T encodeSignatureFor(HashAlgorithm hashAlgorithm, Encoder<T> encoder, byte[]... contents) {
        return encoder.encode(signatureFor(hashAlgorithm, contents));
    }

    default Base64 encodeSignatureFor(HashAlgorithm hashAlgorithm, byte[]... contents) {
        return encodeSignatureFor(hashAlgorithm, base64, contents);
    }

    default <T extends Encoded<T>> T encodeSignatureFor(HashAlgorithm hashAlgorithm, Encoder<T> encoder, String contents, Charset charset) {
        return encodeSignatureFor(hashAlgorithm, encoder, contents.getBytes(charset));
    }

    default Base64 encodeSignatureFor(HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return encodeSignatureFor(hashAlgorithm, base64, contents, charset);
    }

    default Base64 encodeSignatureFor(HashAlgorithm hashAlgorithm, String contents) {
        return encodeSignatureFor(hashAlgorithm, contents, UTF_8);
    }

    default <T extends Encoded<T>> T encodeSignatureFor(HashAlgorithm hashAlgorithm, Encoder<T> encoder, String contents) {
        return encodeSignatureFor(hashAlgorithm, encoder, contents, UTF_8);
    }

    byte[] decrypt(byte[] input) throws DecryptionFailedException;

    default byte[] decrypt(Encoded<?> input) throws DecryptionFailedException {
        return decrypt(input.getDecoded());
    }

    default String decryptAsString(byte[] input, Charset charset) throws DecryptionFailedException {
        return new String(decrypt(input), charset);
    }

    default String decryptAsString(byte[] input) throws DecryptionFailedException {
        return decryptAsString(input, UTF_8);
    }

    default String decryptAsString(Encoded<?>input, Charset charset) throws DecryptionFailedException {
        return decryptAsString(input.getDecoded(), charset);
    }

    default String decryptAsString(Encoded<?> input) throws DecryptionFailedException {
        return decryptAsString(input, UTF_8);
    }

}
