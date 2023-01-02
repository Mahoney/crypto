package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.hash.HashAlgorithm;
import uk.org.lidalia.lang.Bytes;

import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Signature<A extends AsymmetricCryptoAlgorithm<A>> {

    public static <A extends AsymmetricCryptoAlgorithm<A>> Signature<A> of(Bytes hash, HashAlgorithm hashAlgorithm, AsymmetricCryptoAlgorithm<A> cryptoAlgorithm) {
        return new Signature<>(hash, hashAlgorithm, cryptoAlgorithm);
    }

    public static <A extends AsymmetricCryptoAlgorithm<A>> Signature<A> of(byte[] hash, HashAlgorithm hashAlgorithm, AsymmetricCryptoAlgorithm<A> cryptoAlgorithm) {
        return new Signature<>(Bytes.of(hash), hashAlgorithm, cryptoAlgorithm);
    }

    public static <A extends AsymmetricCryptoAlgorithm<A>> Signature<A> of(EncodedBytes hash, HashAlgorithm hashAlgorithm, AsymmetricCryptoAlgorithm<A> cryptoAlgorithm) {
        return new Signature<>(hash.decode(), hashAlgorithm, cryptoAlgorithm);
    }

    private final Bytes hash;
    private final HashAlgorithm hashAlgorithm;
    private final AsymmetricCryptoAlgorithm<A> cryptoAlgorithm;

    private Signature(
        Bytes hash,
        HashAlgorithm hashAlgorithm,
        AsymmetricCryptoAlgorithm<A> cryptoAlgorithm
    ) {
        this.hash = requireNonNull(hash);
        this.hashAlgorithm = requireNonNull(hashAlgorithm);
        this.cryptoAlgorithm = requireNonNull(cryptoAlgorithm);
    }

    public Bytes bytes() {
        return hash;
    }

    public HashAlgorithm hashAlgorithm() {
        return hashAlgorithm;
    }

    public AsymmetricCryptoAlgorithm<A> cryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        @SuppressWarnings("rawtypes") Signature hash1 = (Signature) o;
        return Objects.equals(hash, hash1.hash) &&
                Objects.equals(hashAlgorithm, hash1.hashAlgorithm) &&
                Objects.equals(cryptoAlgorithm, hash1.cryptoAlgorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash, hashAlgorithm, cryptoAlgorithm);
    }

    @Override
    public String toString() {
        return base64.encode(hash).toString();
    }
}
