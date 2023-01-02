package uk.org.lidalia.crypto;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public interface AsymmetricCryptoAlgorithm<Self extends AsymmetricCryptoAlgorithm<Self>> extends CryptoAlgorithm {

    String name();

    int defaultKeySize();

    KeyPair<Self> generateKeyPair();

    KeyPair<Self> generateKeyPair(int keySize);

    PublicKey<Self> publicKey(KeySpec keySpec) throws InvalidKeySpecException;

    PrivateKey<Self> privateKey(KeySpec keySpec) throws InvalidKeySpecException;

}
