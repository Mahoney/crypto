package uk.org.lidalia.crypto;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public interface AsymmetricKeyAlgorithm<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends KeyAlgorithm {

    String name();

    int defaultKeySize();

    default Pair generateKeyPair() {
        return generateKeyPair(defaultKeySize());
    }

    Pair generateKeyPair(int keySize);

    Public publicKey(KeySpec keySpec) throws InvalidKeySpecException;

    Private privateKey(KeySpec keySpec) throws InvalidKeySpecException;

}
