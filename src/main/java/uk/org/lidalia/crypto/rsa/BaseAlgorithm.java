package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Algorithm;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.crypto.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Objects;

public abstract class BaseAlgorithm<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> implements Algorithm<Public,Private> {

    private final String name;
    private final String cipherPadding;
    private final KeyFactory keyFactory;

    BaseAlgorithm(String name, String cipherPadding) {
        this.name = name;
        this.cipherPadding = cipherPadding;
        this.keyFactory = buildKeyFactory();
    }

    private KeyFactory buildKeyFactory() {
        try {
            return KeyFactory.getInstance(name);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(name, e);
        }
    }

    @Override
    public String name() {
        return name;
    }

    KeyFactory keyFactory() {
        return keyFactory;
    }

    Cipher cipher() {
        String algorithmWithPadding = this + cipherPadding;
        try {
            return Cipher.getInstance(algorithmWithPadding);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RequiredAlgorithmNotPresent(algorithmWithPadding, e);
        }
    }

    Signature signatureFor(HashAlgorithm hashAlgorithm) {
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
        return Objects.equals(name, algorithm.name());
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

}