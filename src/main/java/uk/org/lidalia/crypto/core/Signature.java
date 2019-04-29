package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.bytes.EncodedBytes;

import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Signature {

    public static Signature of(Bytes hash, HashAlgorithm hashAlgorithm) {
        return new Signature(hash, hashAlgorithm);
    }

    public static Signature of(byte[] hash, HashAlgorithm hashAlgorithm) {
        return new Signature(Bytes.of(hash), hashAlgorithm);
    }

    public static Signature of(EncodedBytes hash, HashAlgorithm hashAlgorithm) {
        return new Signature(hash.decode(), hashAlgorithm);
    }

    private final Bytes hash;
    private final HashAlgorithm algorithm;

    private Signature(Bytes hash, HashAlgorithm algorithm) {
        this.hash = requireNonNull(hash);
        this.algorithm = requireNonNull(algorithm);
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
        Signature hash1 = (Signature) o;
        return Objects.equals(hash, hash1.hash) &&
                algorithm == hash1.algorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, algorithm);
    }

    @Override
    public String toString() {
        return base64.encode(hash).toString();
    }
}
