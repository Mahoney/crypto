package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.nio.charset.StandardCharsets.UTF_8;

public enum HashAlgorithm {

    NONE(""),
    MD2("MD2"),
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512");

    private final String algName;

    HashAlgorithm(String algName) {
        this.algName = algName;
    }

    public Hash hash(Bytes input) {
        if (this == NONE) {
            return Hash.of(input, this);
        } else {
            try {
                MessageDigest messageDigest = MessageDigest.getInstance(algName);
                return Hash.of(Bytes.of(messageDigest.digest(input.array())), this);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e); // TODO BETTER exception here!
            }
        }
    }

    public Hash hash(byte[] input) {
        return hash(Bytes.of(input));
    }

    public Hash hash(String input, Charset charset) {
        return hash(Bytes.of(input, charset));
    }

    public Hash hash(String input) {
        return hash(input, UTF_8);
    }

    public Hash hash(Encoded<?> input) {
        return hash(input.decode());
    }
}
