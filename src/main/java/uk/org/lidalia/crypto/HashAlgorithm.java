package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.bytes.EncodedBytes;

import java.nio.charset.Charset;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.crypto.JreHashAlgorithm.register;

public interface HashAlgorithm {

    Hash hash(Bytes input);

    default Hash hash(byte[] input) {
        return hash(Bytes.of(input));
    }

    default Hash hash(String input, Charset charset) {
        return hash(Bytes.of(input, charset));
    }

    default Hash hash(String input) {
        return hash(input, UTF_8);
    }

    default Hash hash(EncodedBytes input) {
        return hash(input.decode());
    }

    default String toStringInAlgorithm() {
        return toString().replaceAll("-", "");
    }

    HashAlgorithm NONE   = register("NONE");
    HashAlgorithm MD2    = register("MD2");
    HashAlgorithm MD5    = register("MD5");
    HashAlgorithm SHA1   = register("SHA-1");
    HashAlgorithm SHA224 = register("SHA-224");
    HashAlgorithm SHA256 = register("SHA-256");
    HashAlgorithm SHA384 = register("SHA-384");
    HashAlgorithm SHA512 = register("SHA-512");

    static Set<HashAlgorithm> values() {
        return HashAlgorithmRegistry.values();
    }

    static HashAlgorithm valueOf(String algName) {
        return HashAlgorithmRegistry.valueOf(algName);
    }
}
