package uk.org.lidalia.crypto;

import uk.org.lidalia.hash.HashAlgorithm;

import java.security.NoSuchAlgorithmException;

public interface AsymmetricKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends java.security.Key, Key {

    @Override
    AsymmetricCryptoAlgorithm<Public, Private, Pair> algorithm();

    default java.security.Signature signatureFor(HashAlgorithm hashAlgorithm) {
        final String algorithm = hashAlgorithm.toStringInAlgorithm() + "with" + algorithm();
        try {
            return java.security.Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(algorithm, e);
        }
    }
}
