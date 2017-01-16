package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

public class HashAlgorithm {

    public static final HashAlgorithm NONE   = new HashAlgorithm("NONE");
    public static final HashAlgorithm MD2    = new HashAlgorithm("MD2");
    public static final HashAlgorithm MD5    = new HashAlgorithm("MD5");
    public static final HashAlgorithm SHA1   = new HashAlgorithm("SHA-1");
    public static final HashAlgorithm SHA224 = new HashAlgorithm("SHA-224");
    public static final HashAlgorithm SHA256 = new HashAlgorithm("SHA-256");
    public static final HashAlgorithm SHA384 = new HashAlgorithm("SHA-384");
    public static final HashAlgorithm SHA512 = new HashAlgorithm("SHA-512");

    private static final List<HashAlgorithm> values = unmodifiableList(asList(
            NONE,
            MD2,
            MD5,
            SHA1,
            SHA224,
            SHA256,
            SHA384,
            SHA512
    ));

    private final String algName;

    HashAlgorithm(String algName) {
        this.algName = requireNonNull(algName);
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

    @Override
    public String toString() {
        return algName;
    }

    public String toStringInAlgorithm() {
        return algName.replaceAll("-", "");
    }

    public static List<HashAlgorithm> values() {
        return values;
    }
}
