package uk.org.lidalia.crypto;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public interface Algorithm<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > {

    String name();

    default Pair generateKeyPair() {
        return generateKeyPair(2048);
    }

    Pair generateKeyPair(int keySize);

    Public publicKey(KeySpec keySpec) throws InvalidKeySpecException;

    Private privateKey(KeySpec keySpec) throws InvalidKeySpecException;

    String defaultCipherPadding();
}
