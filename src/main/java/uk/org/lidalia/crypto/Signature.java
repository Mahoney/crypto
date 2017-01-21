package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

public class Signature {

    public static Signature of(Bytes hash, HashAlgorithm hashAlgorithm) {
        return new Signature(hash, hashAlgorithm);
    }

    public static Signature of(byte[] hash, HashAlgorithm hashAlgorithm) {
        return new Signature(Bytes.of(hash), hashAlgorithm);
    }

    public static Signature of(Encoded<?> hash, HashAlgorithm hashAlgorithm) {
        return new Signature(hash.decode(), hashAlgorithm);
    }

    public static Signature of(String hash, Charset charset, HashAlgorithm hashAlgorithm) {
        return of(Bytes.of(hash, charset), hashAlgorithm);
    }

    public static Signature of(String hash, HashAlgorithm hashAlgorithm) {
        return of(hash, UTF_8, hashAlgorithm);
    }

    private final Bytes hash;
    private final HashAlgorithm hashAlgorithm;

    private Signature(Bytes hash, HashAlgorithm hashAlgorithm) {
        this.hash = requireNonNull(hash);
        this.hashAlgorithm = requireNonNull(hashAlgorithm);
    }

    public Bytes bytes() {
        return hash;
    }

    public HashAlgorithm algorithm() {
        return hashAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Signature hash1 = (Signature) o;
        return Objects.equals(hash, hash1.hash) &&
                hashAlgorithm == hash1.hashAlgorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, hashAlgorithm);
    }

    @Override
    public String toString() {
        return bytes().encode().toString();
    }
}
