package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptionFailedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.interfaces.RSAKey;

public abstract class RsaKey<T extends Key & RSAKey> implements Key, RSAKey {

    final T decorated;

    RsaKey(T decorated) {
        this.decorated = decorated;
    }

    public byte[] encrypt(byte[] input) {
        try {
            return doCrypto(input, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            throw new IllegalStateException("Encrypting with an RSA key should always work. Using key="+this, e);
        }
    }

    public byte[] decrypt(byte[] input) throws DecryptionFailedException {
        try {
            return doCrypto(input, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private byte[] doCrypto(byte[] input, int encryptMode) throws Exception {
        Cipher rsa = RsaKeyUtils.cipher();
        try {
            rsa.init(encryptMode, this);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("An RSA Key should never be invalid for doing crypto. Using key="+this, e);
        }
        return rsa.doFinal(input);
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public final String getAlgorithm() {
        return decorated.getAlgorithm();
    }

    @Override
    public final String getFormat() {
        return decorated.getFormat();
    }

    @Override
    public final byte[] getEncoded() {
        return decorated.getEncoded();
    }

    @Override
    public final BigInteger getModulus() {
        return decorated.getModulus();
    }

    @Override
    public final String toString() {
        return decorated.toString();
    }

    @Override
    public final boolean equals(Object other) {
        return this == other || decorated.equals(other);
    }

    @Override
    public final int hashCode() {
        return decorated.hashCode();
    }
}
