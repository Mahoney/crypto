package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.util.Objects.requireNonNull;

class JreHashAlgorithm implements HashAlgorithm {

    private final String algName;

    private JreHashAlgorithm(String algName) {
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

    @Override
    public String toString() {
        return algName;
    }

    static HashAlgorithm register(String name) {
        HashAlgorithm alg = new JreHashAlgorithm(name);
        return HashAlgorithmRegistry.register(alg);
    }

}
