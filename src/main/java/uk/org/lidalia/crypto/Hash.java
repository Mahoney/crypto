package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

public class Hash {

    public static Hash of(Bytes hash, HashAlgorithm hashAlgorithm) {
        return new Hash(hash, hashAlgorithm);
    }

    public static Hash of(byte[] hash, HashAlgorithm hashAlgorithm) {
        return new Hash(Bytes.of(hash), hashAlgorithm);
    }

    public static Hash of(Encoded<?> hash, HashAlgorithm hashAlgorithm) {
        return new Hash(hash.decode(), hashAlgorithm);
    }

    public static Hash of(String hash, Charset charset, HashAlgorithm hashAlgorithm) {
        return of(Bytes.of(hash, charset), hashAlgorithm);
    }

    public static Hash of(String hash, HashAlgorithm hashAlgorithm) {
        return of(hash, UTF_8, hashAlgorithm);
    }

    private final Bytes hash;
    private final HashAlgorithm algorithm;

    private Hash(Bytes hash, HashAlgorithm algorithm) {
        this.hash = requireNonNull(hash);
        this.algorithm = requireNonNull(algorithm);
    }

    public boolean matches(Bytes input) {
        return algorithm.hash(input).equals(this);
    }

    public boolean matches(byte[] input) {
        return matches(Bytes.of(input));
    }

    public boolean matches(Encoded<?> input) {
        return matches(input.decode());
    }

    public boolean matches(String input, Charset charset) {
        return matches(Bytes.of(input, charset));
    }

    public boolean matches(String input) {
        return matches(input, UTF_8);
    }

    public Bytes bytes() {
        return hash;
    }

    public HashAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Hash hash1 = (Hash) o;
        return Objects.equals(hash, hash1.hash) &&
                algorithm == hash1.algorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, algorithm);
    }

    @Override
    public String toString() {
        return bytes().encode().toString();
    }
}
