package uk.org.lidalia.crypto;

import uk.org.lidalia.hash.HashAlgorithm;

import java.security.NoSuchAlgorithmException;

public interface AsymmetricKey<A extends AsymmetricCryptoAlgorithm<A>> extends java.security.Key, Key<A> {

    @Override
    A algorithm();

    default java.security.Signature signatureFor(HashAlgorithm hashAlgorithm) {
        final String algorithm = hashAlgorithm.toStringInAlgorithm() + "with" + algorithm();
        try {
            return java.security.Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(algorithm, e);
        }
    }
}
