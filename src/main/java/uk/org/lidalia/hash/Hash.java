package uk.org.lidalia.hash;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.encoding.hex.NotAHexEncodedString;
import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.hex.HexEncoder.hex;

public class Hash {

    public static Hash of(Bytes hash, HashAlgorithm hashAlgorithm) {
        return new Hash(hash, hashAlgorithm);
    }

    public static Hash of(byte[] hash, HashAlgorithm hashAlgorithm) {
        return new Hash(Bytes.of(hash), hashAlgorithm);
    }

    public static Hash of(EncodedBytes hash, HashAlgorithm hashAlgorithm) {
        return new Hash(hash.decode(), hashAlgorithm);
    }

    public static Hash of(String hash, HashAlgorithm hashAlgorithm) throws NotAHexEncodedString {
        return of(hex.of(hash), hashAlgorithm);
    }

    private final Bytes hash;
    private final HashAlgorithm algorithm;

    private Hash(Bytes hash, HashAlgorithm algorithm) {
        this.hash = requireNonNull(hash);
        this.algorithm = requireNonNull(algorithm);
    }

    public boolean matches(Bytes content) {
        return algorithm.hash(content).equals(this);
    }

    public boolean matches(byte[] content) {
        return matches(Bytes.of(content));
    }

    public boolean matches(EncodedBytes content) {
        return matches(content.decode());
    }

    public boolean matches(String content, Charset charset) {
        return matches(Bytes.of(content, charset));
    }

    public boolean matches(String content) {
        return matches(content, UTF_8);
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
        return hex.encode(hash).toString();
    }
}
