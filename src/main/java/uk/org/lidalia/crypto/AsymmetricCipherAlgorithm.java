package uk.org.lidalia.crypto;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public interface AsymmetricCipherAlgorithm<Self extends AsymmetricCipherAlgorithm<Self>> extends CipherAlgorithm<Self>, AsymmetricCryptoAlgorithm<Self> {

    @Override
    PublicEncryptKey<Self> publicKey(KeySpec keySpec) throws InvalidKeySpecException;

    @Override
    PrivateDecryptKey<Self> privateKey(KeySpec keySpec) throws InvalidKeySpecException;

    @Override
    CipherKeyPair<Self> generateKeyPair();

    @Override
    CipherKeyPair<Self> generateKeyPair(int keySize);
}
