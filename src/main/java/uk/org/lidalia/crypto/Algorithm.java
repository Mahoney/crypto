package uk.org.lidalia.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Objects;

public class Algorithm {

    public static Algorithm RSA = new Algorithm("RSA", "/ECB/PKCS1Padding");

    private final String name;
    private final String cipherPadding;

    private Algorithm(String name, String cipherPadding) {
        this.name = name;
        this.cipherPadding = cipherPadding;
    }

    public String getName() {
        return name;
    }

    public Cipher getCipher() {
        String algorithmWithPadding = this + cipherPadding;
        try {
            return Cipher.getInstance(algorithmWithPadding);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RequiredAlgorithmNotPresent(algorithmWithPadding, e);
        }
    }

    public KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(name);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(name, e);
        }
    }

    public Signature signatureFor(HashAlgorithm hashAlgorithm) {
        final String algorithm = hashAlgorithm + "with" + this;
        try {
            return Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(algorithm, e);
        }
    }

    @Override
    public String toString() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Algorithm algorithm = (Algorithm) o;
        return Objects.equals(name, algorithm.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
}
