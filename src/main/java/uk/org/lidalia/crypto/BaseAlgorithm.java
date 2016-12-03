package uk.org.lidalia.crypto;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public abstract class BaseAlgorithm<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > implements Algorithm<Public,Private, Pair> {

    private final String name;
    private final String defaultCipherPadding;
    private final KeyFactory keyFactory;

    protected BaseAlgorithm(String name, String defaultCipherPadding) {
        this.name = name;
        this.defaultCipherPadding = defaultCipherPadding;
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

    @Override
    public String defaultCipherPadding() {
        return defaultCipherPadding;
    }

    protected KeyFactory keyFactory() {
        return keyFactory;
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
